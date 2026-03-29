from typing import Dict, List

from pydantic import BaseModel, Field
from models.common_schema import PackageRecord, VulnRecord
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
    findings: List[Vulnerability] = Field(default_factory=list)
    vuln_records: List[VulnRecord] = Field(default_factory=list)
    package_records: List[PackageRecord] = Field(default_factory=list)
    annotated_files: Dict[str, str] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)

    def is_clean(self) -> bool:
        """
        발견된 취약점이 하나도 없으면 True를 반환합니다.
        
        Returns:
            bool: findings가 비어 있으면 True, 아니면 False
        """
        return not self.findings
