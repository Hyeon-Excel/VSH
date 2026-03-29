from typing import List
from pydantic import BaseModel
from models.vulnerability import Vulnerability

class ScanResult(BaseModel):
    """
    스캐너(L1)가 생성하는 전체 스캔 결과 모델.
    
    Attributes:
        file_path (str): 스캔 대상 파일 경로
        language (str): 파일의 언어 (예: python)
        findings (list[Vulnerability]): 발견된 취약점 리스트
    """
    file_path: str
    language: str
    findings: List[Vulnerability] = []

    def is_clean(self) -> bool:
        """
        발견된 취약점이 하나도 없으면 True를 반환합니다.
        
        Returns:
            bool: findings가 비어 있으면 True, 아니면 False
        """
        return not self.findings
