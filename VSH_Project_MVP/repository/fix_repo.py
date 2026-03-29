import json
from pathlib import Path
from typing import Optional, Dict, List
from .base_repository import BaseReadRepository

try:
    from config import FIX_PATH
except ImportError:
    FIX_PATH = str(Path(__file__).resolve().parent.parent / "mock_db" / "kisa_fix.json")

FIX_PATH_OBJ = Path(FIX_PATH).resolve()
FIX_PATH_OBJ.parent.mkdir(parents=True, exist_ok=True)
if not FIX_PATH_OBJ.exists():
    FIX_PATH_OBJ.write_text("[]", encoding="utf-8")


class MockFixRepo(BaseReadRepository):
    """
    Mock Fix DB(kisa_fix.json)를 읽기 위한 Repository 구현체.
    """

    def find_by_id(self, id: str) -> Optional[Dict]:
        if not FIX_PATH_OBJ.exists():
            print(f"[WARN] Fix DB file not found: {FIX_PATH_OBJ}")
            return None

        try:
            with open(FIX_PATH_OBJ, "r", encoding="utf-8") as f:
                data: List[Dict] = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        if item.get("id") == id:
                            return item
                else:
                    print("[ERROR] Fix DB structure is invalid (expected list).")

        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse Fix DB JSON: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error accessing Fix DB: {e}")

        return None

    def find_all(self) -> List[Dict]:
        if not FIX_PATH_OBJ.exists():
            return []

        try:
            with open(FIX_PATH_OBJ, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"[ERROR] Failed to read Fix DB: {e}")
            return []
