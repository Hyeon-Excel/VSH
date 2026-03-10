from models.vulnerability import Vulnerability
from layer2.common.requirement_parser import parse_requirement_line
from layer2.verifier.registry_verifier import RegistryVerifier
from layer2.verifier.osv_verifier import OsvVerifier


def test_parse_requirement_line_normalizes_package_name():
    package_name, package_version = parse_requirement_line("Requests==2.9.0")

    assert package_name == "requests"
    assert package_version == "2.9.0"


def test_registry_verifier_detects_dependency_declaration():
    verifier = RegistryVerifier()
    finding = Vulnerability(
        file_path="requirements.txt",
        cwe_id="CWE-829",
        severity="HIGH",
        line_number=1,
        code_snippet="requests==2.9.0",
    )

    result = verifier.verify(finding)

    assert result["registry_status"] == "FOUND"
    assert "requests==2.9.0" in (result["registry_summary"] or "")


def test_osv_verifier_flags_vulnerable_dependency():
    verifier = OsvVerifier()
    finding = Vulnerability(
        file_path="requirements.txt",
        cwe_id="CWE-829",
        severity="HIGH",
        line_number=1,
        code_snippet="requests==2.9.0",
    )

    result = verifier.verify(finding)

    assert result["osv_status"] == "FOUND"
    assert "2.20.0" in (result["osv_summary"] or "")
    assert "CVE-2018-18074" in (result["osv_summary"] or "")


def test_osv_verifier_marks_safe_dependency_as_not_found():
    verifier = OsvVerifier()
    finding = Vulnerability(
        file_path="requirements.txt",
        cwe_id="CWE-829",
        severity="HIGH",
        line_number=1,
        code_snippet="requests==2.31.0",
    )

    result = verifier.verify(finding)

    assert result["osv_status"] == "NOT_FOUND"
    assert "2.31.0" in (result["osv_summary"] or "")
