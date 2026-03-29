from __future__ import annotations

from typing import Dict

from layer2.common.requirement_parser import parse_requirement_line
from layer2.verifier.providers import MockOsvProvider, OsvProvider
from models.vulnerability import Vulnerability


class OsvVerifier:
    def __init__(self, provider: OsvProvider | None = None):
        self.provider = provider or MockOsvProvider()

    def verify(self, finding: Vulnerability) -> Dict[str, str | None]:
        if finding.cwe_id != "CWE-829":
            return {}
        package_name, package_version = parse_requirement_line(finding.code_snippet)
        if not package_name:
            return {"osv_status": "UNKNOWN", "osv_summary": "OSV 검증을 위한 패키지명을 파싱하지 못했습니다."}
        res = self.provider.query_package(package_name, package_version)
        res["osv_mode"] = getattr(self.provider, "mode", "unknown")
        return res
