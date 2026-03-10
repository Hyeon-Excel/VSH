from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:
    import chromadb
    from chromadb.utils import embedding_functions

    _CHROMA_OK = True
except ImportError:
    _CHROMA_OK = False

try:
    from config import CHROMA_COLLECTION, CHROMA_DB_DIR, CHROMA_CACHE_DIR
except ImportError:
    CHROMA_DB_DIR = str(Path(__file__).parent.parent.parent / ".chroma_db")
    CHROMA_CACHE_DIR = str(Path(__file__).parent.parent.parent / ".cache" / "chroma")
    CHROMA_COLLECTION = "vsh_kisa_guide"


class ChromaRetriever:
    """
    ChromaDB에서 CWE와 코드 문맥 기준으로 KISA/FSI/OWASP/NVD 문서를 조회한다.
    chromadb 패키지나 DB가 없으면 비활성 상태로 동작한다.
    """

    def __init__(self, db_dir: Optional[Path] = None, collection_name: str = CHROMA_COLLECTION):
        self._db_dir = Path(db_dir or CHROMA_DB_DIR)
        self._cache_dir = Path(CHROMA_CACHE_DIR)
        self._collection_name = collection_name
        self._client = None
        self._collection = None
        self._last_error: str | None = None
        self._ready = _CHROMA_OK and self._db_dir.exists()

        if self._ready:
            self._init()

    @property
    def ready(self) -> bool:
        return bool(self._ready and self._collection is not None)

    @property
    def status(self) -> str:
        if self.ready:
            return "READY"
        if not _CHROMA_OK:
            return "MISSING_DEPENDENCY"
        if not self._db_dir.exists():
            return "DB_NOT_FOUND"
        if self._last_error:
            return "INIT_FAILED"
        return "DISABLED"

    @property
    def status_summary(self) -> str:
        if self.ready:
            return f"Chroma collection `{self._collection_name}` 연결이 활성화되었습니다."
        if not _CHROMA_OK:
            return "chromadb 패키지가 설치되지 않아 Chroma RAG가 비활성화되었습니다."
        if not self._db_dir.exists():
            return f"Chroma DB 경로를 찾지 못했습니다: {self._db_dir}"
        if self._last_error:
            return f"Chroma 초기화에 실패했습니다: {self._last_error}"
        return "Chroma RAG가 비활성 상태입니다."

    def query(self, cwe_id: str, code_snippet: str = "", n_results: int = 5) -> list[dict]:
        return self.query_related(cwe_id, code_snippet, n_results=n_results)

    def query_related(self, cwe_id: str, code_snippet: str = "", n_results: int = 5) -> list[dict]:
        if not self.ready:
            return []

        query_text = self._build_query_text(cwe_id, code_snippet)
        # hyeonexcel 수정: query embedding이 준비되지 않은 로컬 환경에서도
        # exact metadata 매칭은 collection.get()으로 먼저 처리해 Chroma RAG를 바로 활용할 수 있게 한다.
        exact_docs = self._get_collection(
            where={"cwe": {"$eq": cwe_id}} if cwe_id else None,
            limit=max(n_results * 2, n_results),
            default_cwe=cwe_id,
        )
        exact_docs = self._rank_static_results(exact_docs, query_text, cwe_id)
        if len(exact_docs) >= n_results:
            return exact_docs[:n_results]

        broad_docs = self._query_collection(
            query_text=query_text,
            n_results=max(n_results * 3, n_results + 2),
            where=None,
            default_cwe=cwe_id,
        )
        if not broad_docs:
            broad_docs = self._get_collection(
                where=None,
                limit=self._collection.count(),
                default_cwe=cwe_id,
            )
            broad_docs = self._rank_static_results(broad_docs, query_text, cwe_id)
        return self._merge_ranked_results(exact_docs, broad_docs, cwe_id, n_results)

    def query_by_source(
        self,
        cwe_id: str,
        code_snippet: str = "",
        source: str = "KISA",
        n_results: int = 3,
    ) -> list[dict]:
        if not self.ready:
            return []

        filters = [{"source": {"$eq": source}}]
        if cwe_id:
            filters.insert(0, {"cwe": {"$eq": cwe_id}})

        where = filters[0] if len(filters) == 1 else {"$and": filters}
        query_text = self._build_query_text(cwe_id, code_snippet)
        return self._query_collection(
            query_text=query_text,
            n_results=n_results,
            where=where,
            default_cwe=cwe_id,
        )

    def get_context_string(self, cwe_id: str, code_snippet: str = "") -> str:
        docs = self.query(cwe_id, code_snippet, n_results=4)
        if not docs:
            return ""

        parts: list[str] = []
        for doc in docs:
            source = doc.get("source", "RAG")
            title = (
                doc.get("kisa_article")
                or doc.get("title")
                or doc.get("source_id")
                or doc.get("cve_id")
                or cwe_id
            )
            text = (doc.get("text") or "").strip()
            if text:
                parts.append(f"[{source}] {title}: {text[:300]}")

        return "\n".join(parts)

    def _init(self) -> None:
        try:
            self._configure_embedding_cache()
            ef = embedding_functions.DefaultEmbeddingFunction()
            self._client = chromadb.PersistentClient(path=str(self._db_dir))
            self._collection = self._client.get_collection(
                name=self._collection_name,
                embedding_function=ef,
            )
        except Exception as exc:
            self._last_error = str(exc)
            self._ready = False
            self._collection = None

    def _configure_embedding_cache(self) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("CHROMA_CACHE_DIR", str(self._cache_dir))
        try:
            from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2
        except Exception:
            return

        ONNXMiniLM_L6_V2.DOWNLOAD_PATH = self._cache_dir / "onnx_models" / ONNXMiniLM_L6_V2.MODEL_NAME

    def _get_collection(
        self,
        where: dict | None,
        limit: int,
        default_cwe: str,
    ) -> list[dict]:
        try:
            raw = self._collection.get(
                where=where,
                limit=max(1, limit),
                include=["documents", "metadatas"],
            )
            docs = raw.get("documents", [])
            metas = raw.get("metadatas", [])
        except Exception:
            return []

        return self._parse_raw(docs, metas, default_cwe)

    def _query_collection(
        self,
        query_text: str,
        n_results: int,
        where: dict | None,
        default_cwe: str,
    ) -> list[dict]:
        try:
            raw = self._collection.query(
                query_texts=[query_text],
                n_results=min(n_results, max(1, self._collection.count())),
                where=where,
                include=["documents", "metadatas"],
            )
            docs = raw.get("documents", [[]])[0]
            metas = raw.get("metadatas", [[]])[0]
        except Exception:
            return []

        return self._parse_raw(docs, metas, default_cwe)

    @classmethod
    def _rank_static_results(
        cls,
        docs: list[dict],
        query_text: str,
        cwe_id: str,
    ) -> list[dict]:
        source_priority = cls._source_priority(cwe_id)
        return sorted(
            docs,
            key=lambda doc: (
                cls._static_match_rank(doc, query_text, cwe_id),
                cls._doc_rank(doc, cwe_id, source_priority),
            ),
        )

    @staticmethod
    def _build_query_text(cwe_id: str, code_snippet: str) -> str:
        search_hints = {
            "CWE-22": "path traversal file inclusion",
            "CWE-78": "command injection os command",
            "CWE-79": "cross site scripting xss",
            "CWE-89": "sql injection parameterized query",
            "CWE-94": "code injection eval exec",
            "CWE-327": "weak cryptography insecure algorithm",
            "CWE-330": "weak randomness predictable value",
            "CWE-434": "unrestricted file upload",
            "CWE-502": "deserialization unsafe object",
            "CWE-798": "hardcoded credential secret password",
            "CWE-829": "dependency package supply chain vulnerable library",
        }
        hint = search_hints.get(cwe_id, "")
        return " ".join(part for part in [cwe_id, hint, code_snippet[:300]] if part).strip()

    @classmethod
    def _merge_ranked_results(
        cls,
        exact_docs: list[dict],
        broad_docs: list[dict],
        cwe_id: str,
        n_results: int,
    ) -> list[dict]:
        source_priority = cls._source_priority(cwe_id)
        merged: list[dict] = []
        seen: set[tuple[str, str, str]] = set()

        for doc in exact_docs + broad_docs:
            key = (
                doc.get("source", ""),
                doc.get("source_id", "") or doc.get("kisa_article", "") or doc.get("title", "") or doc.get("cve_id", ""),
                doc.get("text", "")[:120],
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(doc)

        merged.sort(key=lambda doc: cls._doc_rank(doc, cwe_id, source_priority))
        return merged[:n_results]

    @staticmethod
    def _source_priority(cwe_id: str) -> dict[str, int]:
        if cwe_id == "CWE-829":
            return {
                "NVD": 0,
                "FSI": 1,
                "KISA": 2,
                "OWASP": 3,
            }
        return {
            "KISA": 0,
            "FSI": 1,
            "OWASP": 2,
            "NVD": 3,
        }

    @staticmethod
    def _static_match_rank(doc: dict, query_text: str, cwe_id: str) -> tuple[int, int]:
        query_tokens = {
            token
            for token in query_text.lower().split()
            if len(token) > 2 and token != cwe_id.lower()
        }
        haystack = " ".join(
            str(doc.get(key, "")).lower()
            for key in ["title", "text", "source_id", "kisa_article", "owasp_id", "cve_id"]
        )
        token_hits = sum(1 for token in query_tokens if token in haystack)
        exact_cwe_rank = 0 if cwe_id and doc.get("cwe") == cwe_id else 1
        return (exact_cwe_rank, -token_hits)

    @staticmethod
    def _doc_rank(doc: dict, cwe_id: str, source_priority: dict[str, int]) -> tuple[int, int, int, int, int]:
        source = doc.get("source") or ""
        doc_cwe = doc.get("cwe") or ""
        identifier = (
            doc.get("kisa_article")
            or doc.get("source_id")
            or doc.get("owasp_id")
            or doc.get("cve_id")
            or doc.get("title")
            or ""
        )

        exact_cwe_rank = 0 if cwe_id and doc_cwe == cwe_id else 1
        source_rank = source_priority.get(source, 99)
        missing_cwe_rank = 1 if not doc_cwe else 0
        missing_identifier_rank = 1 if not identifier else 0
        source_penalty = 1 if source == "NVD" and cwe_id != "CWE-829" else 0

        return (
            source_rank,
            exact_cwe_rank,
            source_penalty,
            missing_cwe_rank,
            missing_identifier_rank,
        )

    @staticmethod
    def _parse_raw(docs: list[str], metas: list[dict], default_cwe: str) -> list[dict]:
        output: list[dict] = []
        for doc_text, meta in zip(docs, metas):
            entry = {
                "text": doc_text,
                "source": meta.get("source", ""),
                "cwe": meta.get("cwe", default_cwe),
                "kisa_article": meta.get("kisa_article", ""),
                "title": meta.get("title", ""),
                "source_id": meta.get("source_id", ""),
                "risk": meta.get("risk", ""),
                "sheet": meta.get("sheet", ""),
                "owasp_id": meta.get("owasp_id", ""),
                "cve_id": meta.get("cve_id", ""),
                "cvss_score": meta.get("cvss_score", ""),
            }
            output.append(entry)
        return output
