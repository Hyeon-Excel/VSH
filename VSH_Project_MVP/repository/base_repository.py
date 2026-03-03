from abc import ABC, abstractmethod
from typing import Dict, Optional, List

class BaseReadRepository(ABC):
    """
    읽기 전용 저장소를 위한 추상 기본 클래스.
    """

    @abstractmethod
    def find_by_id(self, id: str) -> Optional[Dict]:
        """
        ID로 항목을 조회합니다.

        Args:
            id (str): 조회할 항목의 ID

        Returns:
            Optional[Dict]: 항목이 존재하면 해당 데이터(dict), 없으면 None
        """
        pass

    @abstractmethod
    def find_all(self) -> List[Dict]:
        """
        저장소의 전체 목록을 조회합니다.

        Returns:
            List[Dict]: 전체 항목 목록. 없으면 빈 리스트 반환.
        """
        pass

class BaseWriteRepository(BaseReadRepository):
    """
    읽기 및 쓰기가 가능한 저장소를 위한 추상 기본 클래스.
    BaseReadRepository를 상속받아 find_by_id, find_all 메서드를 포함합니다.
    """

    @abstractmethod
    def save(self, data: Dict) -> bool:
        """
        데이터를 저장소에 저장(추가)합니다.

        Args:
            data (Dict): 저장할 데이터

        Returns:
            bool: 저장 성공 여부
        """
        pass

    @abstractmethod
    def update_status(self, id: str, status: str) -> bool:
        """
        항목의 상태를 업데이트합니다.

        Args:
            id (str): 업데이트할 항목의 ID
            status (str): 새로운 상태 값

        Returns:
            bool: 업데이트 성공 여부
        """
        pass
