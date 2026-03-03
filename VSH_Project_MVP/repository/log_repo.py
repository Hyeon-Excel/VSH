import json
import os
from typing import Optional, Dict, List
from dotenv import load_dotenv
from .base_repository import BaseWriteRepository

# Load environment variables
load_dotenv()
LOG_PATH = os.getenv("LOG_PATH", "mock_db/log.json")

class MockLogRepo(BaseWriteRepository):
    """
    Mock Log DB(log.json)를 읽고 쓰기 위한 Repository 구현체.
    """

    def _load_data(self) -> List[Dict]:
        """내부 헬퍼 메서드: JSON 파일 로드"""
        if not os.path.exists(LOG_PATH):
            return []
        
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, Exception) as e:
            print(f"[ERROR] Failed to load Log DB: {e}")
            return []

    def _save_data(self, data: List[Dict]) -> bool:
        """내부 헬퍼 메서드: JSON 파일 저장"""
        try:
            with open(LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save Log DB: {e}")
            return False

    def find_by_id(self, id: str) -> Optional[Dict]:
        """
        log.json에서 issue_id로 항목을 조회합니다.

        Args:
            id (str): issue_id

        Returns:
            Optional[Dict]: 해당 항목 데이터, 없으면 None
        """
        data = self._load_data()
        for item in data:
            if item.get("issue_id") == id:
                return item
        return None

    def find_all(self) -> List[Dict]:
        """
        log.json의 전체 목록을 조회합니다.

        Returns:
            List[Dict]: 전체 로그 목록. 없으면 빈 리스트.
        """
        return self._load_data()

    def save(self, data: Dict) -> bool:
        """
        분석 결과를 log.json에 추가합니다.

        Args:
            data (Dict): 저장할 로그 데이터 (ScanResult + FixSuggestion + Status)

        Returns:
            bool: 저장 성공 여부
        """
        logs = self._load_data()
        
        existing_idx = next((i for i, item in enumerate(logs) if item.get("issue_id") == data.get("issue_id")), -1)
        
        if existing_idx != -1:
             logs[existing_idx] = data # Update existing
        else:
             logs.append(data) # Append new

        return self._save_data(logs)

    def update_status(self, id: str, status: str) -> bool:
        """
        항목의 상태를 업데이트합니다.

        Args:
            id (str): issue_id
            status (str): "pending", "accepted", "dismissed"

        Returns:
            bool: 성공 여부
        """
        valid_statuses = {"pending", "accepted", "dismissed"}
        if status not in valid_statuses:
            raise ValueError(f"Invalid status: '{status}'. Must be one of {valid_statuses}")

        logs = self._load_data()
        for item in logs:
            if item.get("issue_id") == id:
                item["status"] = status
                return self._save_data(logs)
        
        return False
