from abc import ABC, abstractmethod
from typing import Union
from l3.schema import VulnRecord, PackageRecord

class AbstractSonarQubeProvider(ABC):
    """SonarQube(SAST) 스캔을 담당하는 추상 클래스"""
    
    @abstractmethod
    async def scan(self, project_path: str) -> list[VulnRecord]:
        """프로젝트 경로를 스캔하여 취약점 목록을 반환한다."""
        pass

class AbstractSBOMProvider(ABC):
    """SBOM(공급망 취약점 및 라이선스) 분석을 담당하는 추상 클래스"""
    
    @abstractmethod
    async def scan(self, project_path: str) -> list[PackageRecord]:
        """프로젝트 경로를 스캔하여 패키지 취약점/라이선스 목록을 반환한다."""
        pass

class AbstractPoCProvider(ABC):
    """발견된 취약점의 실제 공격 가능성을 증명하는 추상 클래스"""
    
    @abstractmethod
    async def verify(self, record: VulnRecord) -> VulnRecord:
        """단일 취약점 레코드에 대해 PoC를 실행하고 상태를 업데이트하여 반환한다."""
        pass

class AbstractSharedDB(ABC):
    """취약점 및 패키지 분석 결과를 저장/조회하는 Shared Log DB 추상 클래스"""
    
    @abstractmethod
    async def write(self, record: VulnRecord | PackageRecord) -> None:
        """분석된 레코드를 DB에 저장한다."""
        pass
        
    @abstractmethod
    async def read_all_vuln(self) -> list[VulnRecord]:
        """저장된 모든 코드 취약점 기록을 조회한다."""
        pass
        
    @abstractmethod
    async def read_all_package(self) -> list[PackageRecord]:
        """저장된 모든 패키지 분석 기록을 조회한다."""
        pass