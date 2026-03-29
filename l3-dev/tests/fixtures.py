import pytest
from datetime import datetime, timezone
import uuid

from l3.schema import VulnRecord, PackageRecord

def make_vuln_id() -> str:
    return f"VSH-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

def make_pkg_id() -> str:
    return f"PKG-{str(uuid.uuid4())[:8].upper()}"

# VulnRecord 기본 Mock
MOCK_VULN = VulnRecord(
    vuln_id="VSH-20260309-TEST0001",
    source="L3_SONARQUBE",
    detected_at="2026-03-09T14:32:00",
    file_path="app/db.py",
    line_number=34,
    code_snippet="cursor.execute(query + user_input)",
    vuln_type="SQLi",
    cwe_id="CWE-89",
    cve_id="CVE-2023-32315",
    cvss_score=9.8,
    severity="CRITICAL",
    kisa_ref="입력데이터 검증 및 표현 1항",
    fss_ref="웹 취약점 점검 3-1항",
    owasp_ref="A03:2021",
    reachability=True,
    fix_suggestion="Parameterized Query 사용",
    status="pending",
    action_at=None
)

# PackageRecord 기본 Mock
MOCK_PACKAGE = PackageRecord(
    package_id="PKG-TEST0001",
    source="L3_SBOM",
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
    fix_suggestion="6.0.1 이상으로 업그레이드"
)

# fss_ref 빈 문자열 테스트용
MOCK_VULN_EMPTY_FSS = VulnRecord(
    vuln_id="VSH-20260309-TEST0002",
    source="L1",
    detected_at="2026-03-09T14:33:00",
    file_path="app/auth.py",
    line_number=12,
    code_snippet="eval(user_input)",
    vuln_type="Code Injection",
    cwe_id="CWE-94",
    cve_id=None,
    cvss_score=8.5,
    severity="HIGH",
    kisa_ref="입력데이터 검증 및 표현 2항",
    fss_ref="",        # 빈 문자열 → None 변환 테스트
    owasp_ref=None,
    reachability=None, # 미확인 테스트
    fix_suggestion=None,
    status="pending",
    action_at=None
)