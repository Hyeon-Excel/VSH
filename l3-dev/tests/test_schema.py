import pytest
from l3.schema import VulnRecord, PackageRecord

@pytest.fixture
def valid_vuln_kwargs():
    return {
        "vuln_id": "VSH-20240315-ABCD1234",
        "rule_id": "VSH-PY-SQLI-001",
        "source": "L3_SONARQUBE",
        "detected_at": "2024-03-15T14:30:00",
        "file_path": "app/main.py",
        "line_number": 10,
        "end_line_number": 34,
        "column_number": 1,
        "end_column_number": 10,
        "language": "python",
        "code_snippet": "cursor.execute(query % user_input)",
        "vuln_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "cve_id": None,
        "cvss_score": None,
        "severity": "HIGH",
        "reachability_status": "unknown",
        "reachability_confidence": "low",
        "kisa_ref": "SW보안약점-1",
        "fss_ref": None,
        "owasp_ref": "A03:2021",
        "fix_suggestion": "parameterized query 사용",
        "status": "pending",
        "action_at": None
    }


@pytest.fixture
def valid_package_kwargs():
    return {
        "package_id": "PKG-ABCD1234",
        "detected_at": "2024-03-15T14:30:00",
        "name": "requests",
        "version": "2.28.0",
        "ecosystem": "PyPI",
        "cve_id": "CVE-2023-1234",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "license": "Apache-2.0",
        "license_risk": "low",
        "status": "upgrade_required",
        "code_snippet": "requirements.txt: PyYAML==5.3.1",
        "fix_suggestion": "2.31.0으로 업그레이드"
    }


# --- VulnRecord 테스트 ---

@pytest.mark.parametrize("severity", [
    "CRITICAL", "HIGH", "MEDIUM", "LOW"
])
def test_vuln_record_valid_severity(valid_vuln_kwargs, severity):
    kwargs = valid_vuln_kwargs.copy()
    kwargs["severity"] = severity
    record = VulnRecord(**kwargs)
    assert record.severity == severity

def test_vuln_record_fss_ref_empty_string(valid_vuln_kwargs):
    kwargs = valid_vuln_kwargs.copy()
    kwargs["fss_ref"] = ""
    record = VulnRecord(**kwargs)
    assert record.fss_ref is None

def test_vuln_record_fss_ref_none(valid_vuln_kwargs):
    kwargs = valid_vuln_kwargs.copy()
    kwargs["fss_ref"] = None
    record = VulnRecord(**kwargs)
    assert record.fss_ref is None

def test_vuln_record_status_default(valid_vuln_kwargs):
    kwargs = valid_vuln_kwargs.copy()
    kwargs.pop("status")
    record = VulnRecord(**kwargs)
    assert record.status == "pending"

def test_vuln_record_invalid_severity(valid_vuln_kwargs):
    kwargs = valid_vuln_kwargs.copy()
    kwargs["severity"] = "UNKNOWN"
    with pytest.raises(ValueError):
        VulnRecord(**kwargs)

def test_vuln_record_invalid_status(valid_vuln_kwargs):
    kwargs = valid_vuln_kwargs.copy()
    kwargs["status"] = "invalid_status"
    with pytest.raises(ValueError):
        VulnRecord(**kwargs)

@pytest.mark.parametrize("status", [
    "pending", "accepted", "dismissed",
    "poc_verified", "poc_failed",
    "poc_skipped", "scan_error"
])
def test_vuln_record_valid_status(valid_vuln_kwargs, status):
    kwargs = valid_vuln_kwargs.copy()
    kwargs["status"] = status
    record = VulnRecord(**kwargs)
    assert record.status == status

# --- PackageRecord 테스트 ---

def test_package_record_valid(valid_package_kwargs):
    record = PackageRecord(**valid_package_kwargs)
    assert record.severity == "HIGH"

def test_package_record_source_default(valid_package_kwargs):
    kwargs = valid_package_kwargs.copy()
    if "source" in kwargs:
        kwargs.pop("source")
    record = PackageRecord(**kwargs)
    assert record.source == "L3_SBOM"

@pytest.mark.parametrize("status", [
    "safe", "upgrade_required", "license_violation"
])
def test_package_record_valid_status(valid_package_kwargs, status):
    kwargs = valid_package_kwargs.copy()
    kwargs["status"] = status
    record = PackageRecord(**kwargs)
    assert record.status == status

def test_package_record_invalid_severity(valid_package_kwargs):
    kwargs = valid_package_kwargs.copy()
    kwargs["severity"] = "UNKNOWN"
    with pytest.raises(ValueError):
        PackageRecord(**kwargs)

def test_package_record_invalid_status(valid_package_kwargs):
    kwargs = valid_package_kwargs.copy()
    kwargs["status"] = "invalid_status"
    with pytest.raises(ValueError):
        PackageRecord(**kwargs)
