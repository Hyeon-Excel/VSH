from models.fix_suggestion import FixSuggestion
from models.vulnerability import Vulnerability
from layer2.patch_builder import PatchBuilder


def test_patch_builder_generates_code_diff():
    builder = PatchBuilder()
    finding = Vulnerability(
        file_path="sample.py",
        cwe_id="CWE-89",
        severity="HIGH",
        line_number=7,
        code_snippet="cursor.execute(query % user_input)",
    )
    suggestion = FixSuggestion(
        issue_id="sample.py_CWE-89_7",
        file_path="sample.py",
        cwe_id="CWE-89",
        line_number=7,
        original_code="cursor.execute(query % user_input)",
        fixed_code="cursor.execute(query, (user_input,))",
        description="Use parameter binding.",
    )

    result = builder.build(finding, suggestion)

    assert result["patch_status"] == "GENERATED"
    assert "sample.py:7" in (result["patch_summary"] or "")
    assert "--- a/sample.py" in (result["patch_diff"] or "")
    assert "+++ b/sample.py" in (result["patch_diff"] or "")


def test_patch_builder_generates_dependency_diff():
    builder = PatchBuilder()
    finding = Vulnerability(
        file_path="requirements.txt",
        cwe_id="CWE-829",
        severity="HIGH",
        line_number=1,
        code_snippet="requests==2.9.0",
    )
    suggestion = FixSuggestion(
        issue_id="requirements.txt_CWE-829_1",
        file_path="requirements.txt",
        cwe_id="CWE-829",
        line_number=1,
        original_code="requests==2.9.0",
        fixed_code="requests>=2.20.0",
        description="Upgrade dependency.",
    )

    result = builder.build(finding, suggestion)

    assert result["patch_status"] == "GENERATED"
    assert "requirements.txt" in (result["patch_summary"] or "")
    assert "-requests==2.9.0" in (result["patch_diff"] or "")
    assert "+requests>=2.20.0" in (result["patch_diff"] or "")
