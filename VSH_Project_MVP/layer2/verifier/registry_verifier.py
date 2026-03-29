from __future__ import annotations

from typing import Dict

from layer2.common.requirement_parser import parse_requirement_line
from layer2.verifier.providers import OfflineRegistryProvider, RegistryProvider
from models.vulnerability import Vulnerability


class RegistryVerifier:
    def __init__(self, provider: RegistryProvider | None = None):
        self.provider = provider or OfflineRegistryProvider()

    def verify(self, finding: Vulnerability) -> Dict[str, str | None]:
        if finding.cwe_id != "CWE-829":
            return {}
        package_name, package_version = parse_requirement_line(finding.code_snippet)
        if not package_name:
            return {"registry_status": "UNKNOWN", "registry_summary": "의존성 라인에서 패키지명을 파싱하지 못했습니다."}
        ecosystem = finding.metadata.get("ecosystem", "PyPI")
        return self.provider.verify_package(ecosystem, package_name, package_version)
