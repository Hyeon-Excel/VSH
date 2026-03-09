import re
from typing import Dict

from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

from models.vulnerability import Vulnerability

try:
    from config import VULNERABLE_PACKAGES
except ImportError:
    VULNERABLE_PACKAGES = {}


class OsvVerifier:
    """
    공급망 finding에 대해 mock advisory dataset을 사용해 OSV 검증 결과를 정규화한다.
    """

    def verify(self, finding: Vulnerability) -> Dict[str, str | None]:
        if finding.cwe_id != "CWE-829":
            return {}

        package_name, package_version = self._parse_requirement(finding.code_snippet)
        if not package_name:
            return {
                "osv_status": "UNKNOWN",
                "osv_summary": "OSV 검증을 위한 패키지명을 파싱하지 못했습니다.",
            }

        vuln_info = VULNERABLE_PACKAGES.get(package_name)
        if not vuln_info:
            return {
                "osv_status": "NOT_FOUND",
                "osv_summary": f"`{package_name}`에 대한 advisory를 찾지 못했습니다.",
            }

        safe_floor = vuln_info.get("vulnerable_below")
        cve = vuln_info.get("cve")
        if not package_version:
            return {
                "osv_status": "UNKNOWN",
                "osv_summary": (
                    f"`{package_name}`는 advisory가 있지만 버전이 명시되지 않아 취약 여부를 확정할 수 없습니다."
                ),
            }

        if not safe_floor:
            return {
                "osv_status": "UNKNOWN",
                "osv_summary": f"`{package_name}` advisory의 안전 버전 정보가 없습니다.",
            }

        try:
            is_vulnerable = parse_version(package_version) < parse_version(safe_floor)
        except InvalidVersion:
            return {
                "osv_status": "ERROR",
                "osv_summary": f"`{package_name}=={package_version}` 버전을 해석하지 못했습니다.",
            }

        if is_vulnerable:
            summary = (
                f"`{package_name}=={package_version}`는 안전 기준 `{safe_floor}` 미만으로 확인되었습니다."
            )
            if cve:
                summary = f"{summary} Advisory: {cve}."
            return {
                "osv_status": "FOUND",
                "osv_summary": summary,
            }

        summary = f"`{package_name}=={package_version}`는 안전 기준 `{safe_floor}` 이상입니다."
        if cve:
            summary = f"{summary} 참고 advisory: {cve}."
        return {
            "osv_status": "NOT_FOUND",
            "osv_summary": summary,
        }

    @staticmethod
    def _parse_requirement(requirement_line: str) -> tuple[str | None, str | None]:
        match = re.match(r"^([a-zA-Z0-9_\-]+)(?:[=!<>~]+([0-9\.]+))?", requirement_line.strip())
        if not match:
            return None, None
        return match.group(1).lower(), match.group(2)
