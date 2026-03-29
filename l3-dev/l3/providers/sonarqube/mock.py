# 주의: pipeline.py에서 이 구체 클래스를 직접 import 하지 마세요 (DI 패턴 위반). mcp_server.py에서 주입해야 합니다.

from l3.providers.base import AbstractSonarQubeProvider
from l3.schema import VulnRecord

class MockSonarQubeProvider(AbstractSonarQubeProvider):
    """테스트 및 초기 개발을 위한 SonarQube(SAST) Mock Provider"""

    async def scan(self, project_path: str) -> list[VulnRecord]:
        """실제 스캔 없이 하드코딩된 Mock 데이터를 반환한다."""
        print(f"[L3 SonarQube Mock] 스캔 완료: {project_path}")
        
        mock_vuln = VulnRecord(
            vuln_id="VSH-20260309-TEST0001",
            rule_id="VSH-PY-SQLI-001",
            source="L3_SONARQUBE",
            detected_at="2026-03-09T14:32:00",
            file_path="app/db.py",
            line_number=34,
            end_line_number=34,
            column_number=1,
            end_column_number=10,
            language="python",
            code_snippet="cursor.execute(query + user_input)",
            vuln_type="SQLi",
            cwe_id="CWE-89",
            cve_id="CVE-2023-32315",
            cvss_score=9.8,
            severity="CRITICAL",
            reachability_status="unknown",
            reachability_confidence="low",
            kisa_ref="입력데이터 검증 및 표현 1항",
            fss_ref="웹 취약점 점검 3-1항",
            owasp_ref="A03:2021",
            fix_suggestion="Parameterized Query 사용",
            status="pending",
            action_at=None
        )

        
        return [mock_vuln]
