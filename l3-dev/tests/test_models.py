import pytest
from inspect import isclass
from l3.models.vuln_record import VulnRecord
from l3.models.package_record import PackageRecord

@pytest.fixture
def vuln_record_sample():
    return VulnRecord(
        vuln_id="VSH-20260303-001",
        rule_id="VSH-PY-SQLI-001",
        source="L1",
        detected_at="2026-03-03T14:21:00",
        file_path="app/db.py",
        line_number=34,
        end_line_number=34,
        column_number=5,
        end_column_number=44,
        language="python",
        code_snippet="cursor.execute(query % user_input)",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        cve_id=None,
        cvss_score=None,
        severity="CRITICAL",
        reachability_status="unknown",
        reachability_confidence="low",
        kisa_ref="입력데이터 검증 및 표현 1항",
        fss_ref=None,
        owasp_ref="A03:2021",
        fix_suggestion="Parameterized Query 적용",
        status="pending",
        action_at=None
    )

@pytest.fixture
def package_record_sample():
    return PackageRecord(
        package_id="PKG-001",
        detected_at="2026-03-03T14:32:00",
        name="PyYAML",
        version="5.3.1",
        ecosystem="PyPI",
        cve_id="CVE-2022-1471",
        severity="HIGH",
        cvss_score=8.1,
        license="MIT",
        license_risk=False,
        status="upgrade_required",
        code_snippet="requirements.txt: PyYAML==5.3.1",
        fix_suggestion="6.0.1 이상으로 업그레이드",
        source="L3_SBOM"
    )

def test_vuln_record_import():
    assert isclass(VulnRecord), f"expected: True, got: {isclass(VulnRecord)}"

def test_package_record_import():
    assert isclass(PackageRecord), f"expected: True, got: {isclass(PackageRecord)}"

def test_vuln_record_creation_success(vuln_record_sample):
    assert vuln_record_sample.vuln_id == "VSH-20260303-001", f"expected: VSH-20260303-001, got: {vuln_record_sample.vuln_id}"
    assert vuln_record_sample.source == "L1", f"expected: L1, got: {vuln_record_sample.source}"
    assert vuln_record_sample.severity == "CRITICAL", f"expected: CRITICAL, got: {vuln_record_sample.severity}"
    assert vuln_record_sample.reachability_status == "unknown", f"expected: unknown, got: {vuln_record_sample.reachability_status}"
    assert vuln_record_sample.reachability_confidence == "low", f"expected: low, got: {vuln_record_sample.reachability_confidence}"
    assert vuln_record_sample.status == "pending", f"expected: pending, got: {vuln_record_sample.status}"
    assert vuln_record_sample.action_at is None, f"expected: None, got: {vuln_record_sample.action_at}"

def test_package_record_creation_success(package_record_sample):
    assert package_record_sample.package_id == "PKG-001", f"expected: PKG-001, got: {package_record_sample.package_id}"
    assert package_record_sample.source == "L3_SBOM", f"expected: L3_SBOM, got: {package_record_sample.source}"
    assert package_record_sample.severity == "HIGH", f"expected: HIGH, got: {package_record_sample.severity}"
    assert package_record_sample.status == "upgrade_required", f"expected: upgrade_required, got: {package_record_sample.status}"
    assert package_record_sample.code_snippet == "requirements.txt: PyYAML==5.3.1", f"expected: requirements.txt: PyYAML==5.3.1, got: {package_record_sample.code_snippet}"
    assert package_record_sample.fix_suggestion == "6.0.1 이상으로 업그레이드", f"expected: 6.0.1 이상으로 업그레이드, got: {package_record_sample.fix_suggestion}"

VALID_BASE = {
    "vuln_id":                 "VSH-TEST-001",
    "rule_id":                 "RULE-001",
    "source":                  "L1",
    "detected_at":             "2026-01-01T00:00:00",
    "file_path":               "test.py",
    "line_number":             1,
    "end_line_number":         1,
    "column_number":           1,
    "end_column_number":       1,
    "language":                "python",
    "code_snippet":            "test_code",
    "vuln_type":               "TEST",
    "cwe_id":                  "CWE-89",
    "cve_id":                  None,
    "cvss_score":              None,
    "severity":                "HIGH",
    "reachability_status":     "unknown",
    "reachability_confidence": "low",
    "kisa_ref":                "׽Ʈ ׸",
    "fss_ref":                 None,
    "owasp_ref":               None,
    "fix_suggestion":          "׽Ʈ  ",
}

def test_vuln_record_invalid_source():
    params = {**VALID_BASE, "source": "INVALID_SOURCE"}
    with pytest.raises(ValueError):
        VulnRecord(**params)

def test_vuln_record_invalid_severity():
    params = {**VALID_BASE, "severity": "INVALID_SEVERITY"}
    with pytest.raises(ValueError):
        VulnRecord(**params)

def test_vuln_record_invalid_reachability_status():
    params = {**VALID_BASE, "reachability_status": "YES"}
    with pytest.raises(ValueError):
        VulnRecord(**params)

def test_vuln_record_invalid_reachability_confidence():
    params = {**VALID_BASE, "reachability_confidence": "HIGH"}
    with pytest.raises(ValueError):
        VulnRecord(**params)

def test_vuln_record_kisa_ref_none():
    params = {**VALID_BASE, "kisa_ref": None}
    with pytest.raises(ValueError):
        VulnRecord(**params)

def test_vuln_record_fss_ref_empty_string():
    params = {**VALID_BASE, "fss_ref": ""}
    record = VulnRecord(**params)
    assert record.fss_ref is None, f"expected: None, got: {record.fss_ref}"

def test_vuln_record_invalid_status():
    params = {**VALID_BASE, "status": "INVALID_STATUS"}
    with pytest.raises(ValueError):
        VulnRecord(**params)

VALID_PKG_BASE = {
    "package_id":    "PKG-TEST-001",
    "detected_at":   "2026-01-01T00:00:00",
    "name":          "test-package",
    "version":       "1.0.0",
    "ecosystem":     "PyPI",
    "cve_id":        None,
    "severity":      "HIGH",
    "cvss_score":    None,
    "license":       None,
    "license_risk":  False,
    "status":        "safe",
    "code_snippet":  "requirements.txt: test-package==1.0.0",
    "fix_suggestion": "׽Ʈ  ",
}

def test_package_record_invalid_source():
    params = {**VALID_PKG_BASE, "source": "L1"}
    with pytest.raises(ValueError):
        PackageRecord(**params)

def test_package_record_invalid_severity():
    params = {**VALID_PKG_BASE, "severity": "INVALID_SEVERITY"}
    with pytest.raises(ValueError):
        PackageRecord(**params)

def test_package_record_invalid_status():
    params = {**VALID_PKG_BASE, "status": "pending"}
    with pytest.raises(ValueError):
        PackageRecord(**params)
