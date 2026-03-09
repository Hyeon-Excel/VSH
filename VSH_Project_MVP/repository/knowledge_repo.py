from typing import Optional, Dict, List
from .base_repository import BaseReadRepository
from modules.rag.retriever import KISARetriever


class RAGKnowledgeRepo(BaseReadRepository):
    """
    ChromaDB 기반 Knowledge Repository.
    CWE ID로 KISA 가이드 정보를 조회합니다.
    """

    def __init__(self):
        self._retriever = KISARetriever()

    def find_by_id(self, id: str) -> Optional[Dict]:
        """
        CWE ID로 KISA 가이드 항목을 조회합니다.

        Args:
            id (str): CWE ID (예: CWE-89)

        Returns:
            Optional[Dict]: ChromaDB에서 조회한 KISA 가이드 데이터, 없으면 None
        """
        docs = self._retriever.query_by_source(id, "", "KISA", n_results=1)
        if not docs:
            return None
        doc = docs[0]
        return {
            "id": id,
            "name": doc.get("kisa_article", id),
            "description": doc.get("text", ""),
            "pattern": "",
            "reference": doc.get("kisa_article", ""),
            "severity": "HIGH",
        }

    def find_all(self) -> List[Dict]:
        """
        ChromaDB에서 전체 KISA 가이드 항목을 조회합니다.

        Returns:
            List[Dict]: 전체 KISA 가이드 목록
        """
        docs = self._retriever.get_all_by_source("KISA")
        return [
            {
                "id": doc.get("cwe", ""),
                "name": doc.get("kisa_article", ""),
                "description": doc.get("text", ""),
                "pattern": "",
                "reference": doc.get("kisa_article", ""),
                "severity": "HIGH",
            }
            for doc in docs if doc.get("cwe")
        ]


# 하위 호환성을 위한 별칭
MockKnowledgeRepo = RAGKnowledgeRepo
