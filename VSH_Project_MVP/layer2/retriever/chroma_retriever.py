from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import chromadb
    from chromadb.utils import embedding_functions

    _CHROMA_OK = True
except ImportError:
    _CHROMA_OK = False

try:
    from config import CHROMA_COLLECTION, CHROMA_DB_DIR
except ImportError:
    CHROMA_DB_DIR = str(Path(__file__).parent.parent.parent / ".chroma_db")
    CHROMA_COLLECTION = "vsh_kisa_guide"


class ChromaRetriever:
    """
    ChromaDB에서 CWE와 코드 문맥 기준으로 KISA/FSI/OWASP/NVD 문서를 조회한다.
    chromadb 패키지나 DB가 없으면 비활성 상태로 동작한다.
    """

    def __init__(self, db_dir: Optional[Path] = None, collection_name: str = CHROMA_COLLECTION):
        self._db_dir = Path(db_dir or CHROMA_DB_DIR)
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
        if not self.ready:
            return []

        query_text = f"{cwe_id} {code_snippet[:300]}".strip()
        where = {"cwe": {"$eq": cwe_id}} if cwe_id else None

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

        return self._parse_raw(docs, metas, cwe_id)

    def query_by_source(
        self,
        cwe_id: str,
        code_snippet: str = "",
        source: str = "KISA",
        n_results: int = 3,
    ) -> list[dict]:
        if not self.ready:
            return []

        query_text = f"{cwe_id} {code_snippet[:300]}".strip()
        where = {"$and": [{"cwe": {"$eq": cwe_id}}, {"source": {"$eq": source}}]}

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

        return self._parse_raw(docs, metas, cwe_id)

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
