"""
RAG Retriever — ChromaDB 기반 멀티소스 지식 베이스 검색

로드된 데이터 (.chroma_db):
  - KISA 시큐어코딩 가이드  12개
  - 금융보안원 (FSI-2026)   47개
  - OWASP Top 10 (2021)    23개
  - NVD/CVE               100개
  합계: 182개 문서

ChromaDB 경로: VSH_Project_MVP/.chroma_db
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import chromadb
    from chromadb.utils import embedding_functions
    _CHROMA_OK = True
except ImportError:
    _CHROMA_OK = False

_DB_DIR = Path(__file__).parent.parent.parent / ".chroma_db"
_COLLECTION = "vsh_kisa_guide"


class KISARetriever:
    """
    CWE + 코드 문맥으로 ChromaDB에서 KISA/FSI/OWASP/NVD 문서를 검색합니다.
    ChromaDB(.chroma_db)가 없으면 빈 결과를 반환합니다.
    """

    def __init__(self, db_dir: Optional[Path] = None):
        self._db_dir = db_dir or _DB_DIR
        self._client = None
        self._col = None
        self._ready = _CHROMA_OK and self._db_dir.exists()

        if self._ready:
            self._init()

    # ------------------------------------------------------------------ #
    # 공개 API
    # ------------------------------------------------------------------ #

    def query(self, cwe: str, code_snippet: str = "", n_results: int = 5) -> list[dict]:
        """CWE + 코드 문맥으로 관련 문서를 검색합니다."""
        if not (self._ready and self._col):
            return []
        return self._chroma_query(cwe, code_snippet, n_results)

    def query_by_source(
        self, cwe: str, code_snippet: str = "",
        source: str = "KISA", n_results: int = 3
    ) -> list[dict]:
        """특정 소스(KISA / FSI / OWASP / NVD)에서만 검색합니다."""
        if not (self._ready and self._col):
            return []
        return self._chroma_query(cwe, code_snippet, n_results, source_filter=source)

    def get_all_by_source(self, source: str, limit: int = 50) -> list[dict]:
        """특정 소스의 전체 문서를 반환합니다 (knowledge_repo.find_all() 용)."""
        if not (self._ready and self._col):
            return []
        try:
            raw = self._col.get(
                where={"source": {"$eq": source}},
                include=["documents", "metadatas"],
            )
            docs = raw.get("documents", [])[:limit]
            metas = raw.get("metadatas", [])[:limit]
            return self._parse_raw(docs, metas)
        except Exception:
            return []

    def get_context_string(self, cwe: str, code_snippet: str = "") -> str:
        """
        LLM 프롬프트에 삽입할 컨텍스트 문자열을 반환합니다.

        구조:
          [KISA 가이드]         조항 + 설명 + 예방법 + 안전코드
          [금융보안원 평가기준]  FSI 체크리스트
          [OWASP]               공격 시나리오
          [실제 CVE 사례]       CVE ID + CVSS
        """
        if not (self._ready and self._col):
            return f"ChromaDB를 찾을 수 없습니다. .chroma_db 폴더를 확인하세요. ({cwe})"

        kisa_docs  = self._chroma_query(cwe, code_snippet, 2, "KISA")
        fsi_docs   = self._chroma_query(cwe, code_snippet, 1, "FSI")
        owasp_docs = self._chroma_query(cwe, code_snippet, 1, "OWASP")
        nvd_docs   = self._chroma_query(cwe, code_snippet, 2, "NVD")

        parts: list[str] = []

        # KISA: doc_text에 설명/예방법/안전코드 모두 포함돼 있음
        for doc in kisa_docs:
            parts.append(
                f"[KISA 가이드]\n"
                f"항목: {doc.get('kisa_article', '')}\n"
                f"{doc.get('text', '')}"
            )

        for doc in fsi_docs:
            parts.append(
                f"[금융보안원 평가기준 — {doc.get('title', '')}]\n"
                f"평가항목: {doc.get('source_id', '')} | 위험도: {doc.get('risk', '')}\n"
                f"{doc.get('text', '')[:400]}"
            )

        for doc in owasp_docs:
            parts.append(
                f"[OWASP {doc.get('owasp_id', '')} — {doc.get('title', '')}]\n"
                f"{doc.get('text', '')[:400]}"
            )

        if nvd_docs:
            lines = [f"[실제 CVE 사례 — {cwe}]"]
            for doc in nvd_docs:
                lines.append(
                    f"  {doc.get('cve_id', '')} (CVSS {doc.get('cvss_score', '?')}): "
                    f"{doc.get('text', '')[:200]}"
                )
            parts.append("\n".join(lines))

        if not parts:
            return f"관련 가이드라인을 찾을 수 없습니다. ({cwe})"

        return "\n\n".join(parts)

    # ------------------------------------------------------------------ #
    # ChromaDB 초기화
    # ------------------------------------------------------------------ #

    def _init(self) -> None:
        try:
            ef = embedding_functions.DefaultEmbeddingFunction()
            self._client = chromadb.PersistentClient(path=str(self._db_dir))
            self._col = self._client.get_collection(name=_COLLECTION, embedding_function=ef)
        except Exception:
            self._ready = False
            self._col = None

    # ------------------------------------------------------------------ #
    # ChromaDB 쿼리
    # ------------------------------------------------------------------ #

    def _chroma_query(
        self, cwe: str, code_snippet: str, n_results: int,
        source_filter: Optional[str] = None,
    ) -> list[dict]:
        query_text = f"{cwe} {code_snippet[:300]}" if code_snippet else cwe

        where: dict = {}
        if source_filter and cwe:
            where = {"$and": [{"cwe": {"$eq": cwe}}, {"source": {"$eq": source_filter}}]}
        elif source_filter:
            where = {"source": {"$eq": source_filter}}
        elif cwe:
            where = {"cwe": {"$eq": cwe}}

        n = min(n_results, max(1, self._col.count()))
        try:
            raw = self._col.query(
                query_texts=[query_text], n_results=n,
                where=where or None,
                include=["documents", "metadatas"],
            )
            docs = raw.get("documents", [[]])[0]
            metas = raw.get("metadatas", [[]])[0]
        except Exception:
            try:
                raw = self._col.query(
                    query_texts=[query_text], n_results=n,
                    include=["documents", "metadatas"],
                )
                docs = raw.get("documents", [[]])[0]
                metas = raw.get("metadatas", [[]])[0]
            except Exception:
                return []

        return self._parse_raw(docs, metas, default_cwe=cwe)

    def _parse_raw(
        self,
        docs: list[str],
        metas: list[dict],
        default_cwe: str = "",
    ) -> list[dict]:
        """ChromaDB 결과를 표준 dict 목록으로 변환합니다."""
        output: list[dict] = []
        for doc_text, meta in zip(docs, metas):
            source = meta.get("source", "")
            entry: dict = {
                "text": doc_text,
                "source": source,
                "cwe": meta.get("cwe", default_cwe),
            }
            if source == "KISA":
                entry.update({
                    "kisa_article": meta.get("kisa_article", ""),
                    "title": meta.get("title", ""),
                })
            elif source == "FSI":
                entry.update({
                    "source_id": meta.get("source_id", ""),
                    "title": meta.get("title", ""),
                    "risk": meta.get("risk", ""),
                    "sheet": meta.get("sheet", ""),
                })
            elif source == "OWASP":
                entry.update({
                    "owasp_id": meta.get("owasp_id", ""),
                    "title": meta.get("title", ""),
                })
            elif source == "NVD":
                entry.update({
                    "cve_id": meta.get("cve_id", ""),
                    "cvss_score": meta.get("cvss_score", ""),
                })
            output.append(entry)
        return output
