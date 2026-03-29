import json
import os
from typing import Optional, Dict, List
from .base_repository import BaseReadRepository
try:
    from config import KNOWLEDGE_PATH
except ImportError:
    # 테스트 등에서 config를 찾지 못하는 경우를 위한 fallback
    KNOWLEDGE_PATH = "mock_db/knowledge.json"

class MockKnowledgeRepo(BaseReadRepository):
    """
    Mock Knowledge DB(knowledge.json)를 읽기 위한 Repository 구현체.
    """

    def find_by_id(self, id: str) -> Optional[Dict]:
        """
        knowledge.json에서 ID로 항목을 조회합니다.

        Args:
            id (str): CWE ID (예: CWE-78)

        Returns:
            Optional[Dict]: 해당 항목 데이터, 없으면 None
        """
        if not os.path.exists(KNOWLEDGE_PATH):
            print(f"[WARN] Knowledge DB file not found: {KNOWLEDGE_PATH}")
            return None

        try:
            with open(KNOWLEDGE_PATH, "r", encoding="utf-8") as f:
                data: List[Dict] = json.load(f)
                
                if isinstance(data, list):
                    for item in data:
                        if item.get("id") == id:
                            return item
                else:
                    print(f"[ERROR] Knowledge DB structure is invalid (expected list).")
                    
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse Knowledge DB JSON: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error accessing Knowledge DB: {e}")
        
        return None

    def find_all(self) -> List[Dict]:
        """
        knowledge.json의 전체 목록을 조회합니다.

        Returns:
            List[Dict]: 전체 지식(패턴) 목록. 없으면 빈 리스트.
        """
        if not os.path.exists(KNOWLEDGE_PATH):
            return []

        try:
            with open(KNOWLEDGE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"[ERROR] Failed to read Knowledge DB: {e}")
            return []
