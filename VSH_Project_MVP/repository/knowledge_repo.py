import json
from pathlib import Path
from typing import Optional, Dict, List
from .base_repository import BaseReadRepository

try:
    from config import KNOWLEDGE_PATH
except ImportError:
    KNOWLEDGE_PATH = str(Path(__file__).resolve().parent.parent / "mock_db" / "knowledge.json")

KNOWLEDGE_PATH_OBJ = Path(KNOWLEDGE_PATH).resolve()
KNOWLEDGE_PATH_OBJ.parent.mkdir(parents=True, exist_ok=True)
if not KNOWLEDGE_PATH_OBJ.exists():
    KNOWLEDGE_PATH_OBJ.write_text("[]", encoding="utf-8")


class MockKnowledgeRepo(BaseReadRepository):
    """
    Mock Knowledge DB(knowledge.json)를 읽기 위한 Repository 구현체.
    """

    def find_by_id(self, id: str) -> Optional[Dict]:
        if not KNOWLEDGE_PATH_OBJ.exists():
            print(f"[WARN] Knowledge DB file not found: {KNOWLEDGE_PATH_OBJ}")
            return None

        try:
            with open(KNOWLEDGE_PATH_OBJ, "r", encoding="utf-8") as f:
                data: List[Dict] = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        if item.get("id") == id:
                            return item
                else:
                    print("[ERROR] Knowledge DB structure is invalid (expected list).")

        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse Knowledge DB JSON: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error accessing Knowledge DB: {e}")

        return None

    def find_all(self) -> List[Dict]:
        if not KNOWLEDGE_PATH_OBJ.exists():
            return []

        try:
            with open(KNOWLEDGE_PATH_OBJ, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"[ERROR] Failed to read Knowledge DB: {e}")
            return []
