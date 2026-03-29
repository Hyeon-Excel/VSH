from l3.providers.base import AbstractSharedDB
from l3.schema import VulnRecord, PackageRecord

class MockSharedDB(AbstractSharedDB):
    """테스트 및 초기 개발을 위한 인메모리 Shared DB Mock"""
    
    def __init__(self):
        self._vuln_records: list[VulnRecord] = []
        self._package_records: list[PackageRecord] = []
        
    async def write(self, record: VulnRecord | PackageRecord) -> None:
        """타입을 확인하여 알맞은 리스트에 레코드를 저장한다."""
        print(f"[L3 MockDB] 저장: {type(record).__name__}")
        
        if isinstance(record, VulnRecord):
            self._vuln_records.append(record)
        elif isinstance(record, PackageRecord):
            self._package_records.append(record)
        else:
            raise ValueError(f"지원하지 않는 레코드 타입입니다: {type(record)}")
            
    async def read_all_vuln(self) -> list[VulnRecord]:
        """저장된 모든 코드 취약점 기록의 복사본을 반환한다."""
        return list(self._vuln_records)
        
    async def read_all_package(self) -> list[PackageRecord]:
        """저장된 모든 패키지 분석 기록의 복사본을 반환한다."""
        return list(self._package_records)

    def reset(self) -> None:
        """테스트 간 데이터 오염 방지용 DB 초기화 메서드."""
        self._vuln_records = []
        self._package_records = []
        print("[L3 MockDB] DB 초기화 완료")
