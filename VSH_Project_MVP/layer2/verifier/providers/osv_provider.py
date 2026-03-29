from __future__ import annotations

from abc import ABC, abstractmethod

from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

try:
    from config import VULNERABLE_PACKAGES
except ImportError:
    VULNERABLE_PACKAGES = {}


class OsvProvider(ABC):
    mode: str = "unknown"

    @abstractmethod
    def query_package(self, package_name: str, package_version: str | None) -> dict[str, str | None]:
        raise NotImplementedError


class MockOsvProvider(OsvProvider):
    mode = "mock-offline"

    def query_package(self, package_name: str, package_version: str | None) -> dict[str, str | None]:
        vuln_info = VULNERABLE_PACKAGES.get(package_name)
        if not vuln_info:
            return {"osv_status": "NOT_FOUND", "osv_summary": f"`{package_name}` advisory 없음(mock dataset)."}
        safe_floor = vuln_info.get("vulnerable_below")
        cve = vuln_info.get("cve")
        if not package_version:
            return {"osv_status": "UNKNOWN", "osv_summary": f"`{package_name}` advisory 존재, 버전 미기재."}
        if not safe_floor:
            return {"osv_status": "UNKNOWN", "osv_summary": f"`{package_name}` 안전 버전 정보 없음."}
        try:
            is_vuln = parse_version(package_version) < parse_version(safe_floor)
        except InvalidVersion:
            return {"osv_status": "ERROR", "osv_summary": f"버전 해석 실패: {package_version}"}
        if is_vuln:
            return {"osv_status": "FOUND", "osv_summary": f"{package_name}=={package_version} < {safe_floor}. {cve or ''}".strip()}
        return {"osv_status": "NOT_FOUND", "osv_summary": f"{package_name}=={package_version} >= {safe_floor}."}


class OnlineOsvProvider(OsvProvider):
    mode = "online-opt-in"

    def query_package(self, package_name: str, package_version: str | None) -> dict[str, str | None]:
        return {"osv_status": "UNIMPLEMENTED", "osv_summary": "online OSV API provider 확장 포인트(기본 비활성)."}
