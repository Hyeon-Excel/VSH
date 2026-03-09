import re
from typing import Dict

from models.vulnerability import Vulnerability


class RegistryVerifier:
    """
    공급망 finding에서 패키지 선언을 식별하고 registry 검증 대상 여부를 정리한다.
    현재는 네트워크 호출 없이 deterministic하게 동작하는 로컬 verifier다.
    """

    def verify(self, finding: Vulnerability) -> Dict[str, str | None]:
        if finding.cwe_id != "CWE-829":
            return {}

        package_name, package_version = self._parse_requirement(finding.code_snippet)
        if not package_name:
            return {
                "registry_status": "UNKNOWN",
                "registry_summary": "의존성 라인에서 패키지명을 파싱하지 못했습니다.",
            }

        if package_version:
            return {
                "registry_status": "FOUND",
                "registry_summary": (
                    f"registry 검증 대상 `{package_name}=={package_version}` 의존성 선언을 확인했습니다."
                ),
            }

        return {
            "registry_status": "FOUND",
            "registry_summary": (
                f"registry 검증 대상 `{package_name}` 의존성 선언을 확인했지만 버전이 명시되지 않았습니다."
            ),
        }

    @staticmethod
    def _parse_requirement(requirement_line: str) -> tuple[str | None, str | None]:
        match = re.match(r"^([a-zA-Z0-9_\-]+)(?:[=!<>~]+([0-9\.]+))?", requirement_line.strip())
        if not match:
            return None, None
        return match.group(1).lower(), match.group(2)
