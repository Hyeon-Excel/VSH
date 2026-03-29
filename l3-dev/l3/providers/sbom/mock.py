# 주의: pipeline.py에서 이 구체 클래스를 직접 import 하지 마세요 (DI 패턴 위반). mcp_server.py에서 주입해야 합니다.

from l3.providers.base import AbstractSBOMProvider
from l3.schema import PackageRecord

class MockSBOMProvider(AbstractSBOMProvider):
    """테스트 및 초기 개발을 위한 SBOM(공급망 취약점/라이선스) Mock Provider"""

    async def scan(self, project_path: str) -> list[PackageRecord]:
        """실제 스캔 없이 하드코딩된 Mock 데이터를 반환한다."""
        print(f"[L3 SBOM Mock] 스캔 완료: {project_path}")
        
        mock_package = PackageRecord(
            package_id="PKG-TEST0001",
            detected_at="2026-03-09T14:32:00",
            name="PyYAML",
            version="5.3.1",
            ecosystem="PyPI",
            cve_id="CVE-2022-1471",
            severity="CRITICAL",
            cvss_score=9.8,
            license="MIT",
            license_risk=False,
            status="upgrade_required",
            code_snippet="requirements.txt: PyYAML==5.3.1",
            fix_suggestion="6.0.1 이상으로 업그레이드"
        )

        
        return [mock_package]
