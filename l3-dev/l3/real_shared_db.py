from l3.providers.base import AbstractSharedDB
from l3.adapters import l3_vuln_to_pydantic, l3_package_to_pydantic
from l3.models.vuln_record import VulnRecord as L3VulnRecord
from l3.models.package_record import PackageRecord as L3PackageRecord


class RealSharedDB(AbstractSharedDB):
    """Pydantic 변환 어댑터를 거쳐 공통 스키마로 저장하는 인메모리 Shared DB"""

    def __init__(self):
        self._vulns: list = []
        self._packages: list = []

    async def write(self, record) -> None:
        if isinstance(record, L3VulnRecord):
            self._vulns.append(l3_vuln_to_pydantic(record))
        elif isinstance(record, L3PackageRecord):
            self._packages.append(l3_package_to_pydantic(record))
        else:
            raise TypeError(f"지원하지 않는 레코드 타입입니다: {type(record)}")

    async def read_all_vuln(self) -> list:
        return self._vulns

    async def read_all_package(self) -> list:
        return self._packages

    def reset(self) -> None:
        self._vulns = []
        self._packages = []
        print("[L3 RealDB] DB 초기화 완료")
