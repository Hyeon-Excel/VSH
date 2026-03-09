import importlib

from models.fix_suggestion import FixSuggestion
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from pipeline.analysis_pipeline import AnalysisPipeline


class DummyScanner:
    def __init__(self, finding: Vulnerability):
        self.finding = finding

    def scan(self, file_path: str) -> ScanResult:
        return ScanResult(file_path=file_path, language="python", findings=[self.finding])


class DummyAnalyzer:
    def __init__(self, suggestion: FixSuggestion):
        self.suggestion = suggestion
        self.last_error = None

    def analyze(self, scan_result, knowledge, fix_hints, evidence_map=None):
        return [self.suggestion]


class FailingAnalyzer:
    def __init__(self, error_message: str):
        self.last_error = error_message

    def analyze(self, scan_result, knowledge, fix_hints, evidence_map=None):
        return []


class DummyReadRepo:
    def find_by_id(self, id: str):
        return None

    def find_all(self):
        return []


class DummyWriteRepo(DummyReadRepo):
    def __init__(self):
        self.saved = []

    def save(self, data):
        self.saved.append(data)
        return True

    def update_status(self, id: str, status: str):
        return False


def test_fix_suggestion_preserves_l2_metadata():
    suggestion = FixSuggestion(
        issue_id="issue-1",
        file_path="requirements.txt",
        cwe_id="CWE-89",
        line_number=7,
        reachability="User-controlled input reaches the query.",
        kisa_reference="KISA DB-01",
        original_code="cursor.execute(query % user_input)",
        fixed_code="cursor.execute(query, (user_input,))",
        description="Use parameter binding instead of string interpolation.",
    )

    payload = suggestion.model_dump()

    assert payload["file_path"] == "requirements.txt"
    assert payload["cwe_id"] == "CWE-89"
    assert payload["line_number"] == 7
    assert payload["reachability"] == "User-controlled input reaches the query."
    assert payload["kisa_reference"] == "KISA DB-01"
    assert payload["evidence_refs"] == []
    assert payload["evidence_summary"] is None


def test_pipeline_package_exports_factory_without_optional_import_masking():
    pipeline_module = importlib.import_module("pipeline")

    assert pipeline_module.PipelineFactory.__name__ == "PipelineFactory"


def test_pipeline_uses_structured_l2_metadata_for_logging(tmp_path):
    vulnerable_file = tmp_path / "sample.py"
    vulnerable_file.write_text("print('hello')\n", encoding="utf-8")

    finding = Vulnerability(
        file_path=str(vulnerable_file),
        cwe_id="CWE-89",
        severity="HIGH",
        line_number=7,
        code_snippet="cursor.execute(query % user_input)",
    )
    suggestion = FixSuggestion(
        issue_id="custom-issue-id",
        file_path=str(vulnerable_file),
        cwe_id="CWE-89",
        line_number=7,
        reachability="User input is directly reachable from the sink.",
        kisa_reference="KISA DB-01",
        evidence_refs=["CWE-89", "KISA 시큐어코딩 DB-01"],
        evidence_summary="sample.py에서 SQL Injection 패턴이 확인되었습니다.",
        original_code="cursor.execute(query % user_input)",
        fixed_code="cursor.execute(query, (user_input,))",
        description="Use parameter binding instead of string interpolation.",
    )
    log_repo = DummyWriteRepo()
    pipeline = AnalysisPipeline(
        scanners=[DummyScanner(finding)],
        analyzer=DummyAnalyzer(suggestion),
        knowledge_repo=DummyReadRepo(),
        fix_repo=DummyReadRepo(),
        log_repo=log_repo,
    )

    result = pipeline.run(str(vulnerable_file))

    assert result["fix_suggestions"][0]["cwe_id"] == "CWE-89"
    assert result["fix_suggestions"][0]["line_number"] == 7
    assert result["fix_suggestions"][0]["file_path"] == str(vulnerable_file)
    assert result["fix_suggestions"][0]["issue_id"] == f"{vulnerable_file}_CWE-89_7"
    assert result["fix_suggestions"][0]["reachability"] == "User input is directly reachable from the sink."
    assert result["fix_suggestions"][0]["kisa_reference"] == "KISA DB-01"
    assert result["fix_suggestions"][0]["evidence_refs"] == ["CWE-89", "KISA 시큐어코딩 DB-01"]
    assert result["fix_suggestions"][0]["evidence_summary"] == "sample.py에서 SQL Injection 패턴이 확인되었습니다."
    assert len(log_repo.saved) == 1
    assert log_repo.saved[0]["issue_id"] == f"{vulnerable_file}_CWE-89_7"
    assert log_repo.saved[0]["file_path"] == str(vulnerable_file)
    assert log_repo.saved[0]["description"] == "Use parameter binding instead of string interpolation."
    assert log_repo.saved[0]["reachability"] == "User input is directly reachable from the sink."
    assert log_repo.saved[0]["kisa_reference"] == "KISA DB-01"
    assert log_repo.saved[0]["evidence_refs"] == ["CWE-89", "KISA 시큐어코딩 DB-01"]
    assert log_repo.saved[0]["evidence_summary"] == "sample.py에서 SQL Injection 패턴이 확인되었습니다."


def test_pipeline_logs_cross_file_findings_with_structured_file_path(tmp_path):
    scanned_file = tmp_path / "app.py"
    scanned_file.write_text("print('hello')\n", encoding="utf-8")
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("requests==2.9.0\n", encoding="utf-8")

    finding = Vulnerability(
        file_path=str(requirements_file),
        cwe_id="CWE-829",
        severity="HIGH",
        line_number=1,
        code_snippet="requests==2.9.0",
    )
    suggestion = FixSuggestion(
        issue_id=f"{requirements_file}_CWE-829_1",
        file_path=str(requirements_file),
        cwe_id="CWE-829",
        line_number=1,
        reachability="Dependency version is below the safe threshold.",
        kisa_reference="OSV/Registry",
        original_code="requests==2.9.0",
        fixed_code="requests>=2.20.0",
        description="Upgrade the vulnerable dependency.",
    )
    log_repo = DummyWriteRepo()
    pipeline = AnalysisPipeline(
        scanners=[DummyScanner(finding)],
        analyzer=DummyAnalyzer(suggestion),
        knowledge_repo=DummyReadRepo(),
        fix_repo=DummyReadRepo(),
        log_repo=log_repo,
    )

    result = pipeline.run(str(scanned_file))

    assert result["fix_suggestions"][0]["file_path"] == str(requirements_file)
    assert log_repo.saved[0]["file_path"] == str(requirements_file)
    assert log_repo.saved[0]["issue_id"] == f"{requirements_file}_CWE-829_1"


def test_pipeline_logs_analysis_failures(tmp_path):
    vulnerable_file = tmp_path / "sample.py"
    vulnerable_file.write_text("print('hello')\n", encoding="utf-8")

    finding = Vulnerability(
        file_path=str(vulnerable_file),
        cwe_id="CWE-89",
        severity="HIGH",
        line_number=7,
        code_snippet="cursor.execute(query % user_input)",
    )
    log_repo = DummyWriteRepo()
    pipeline = AnalysisPipeline(
        scanners=[DummyScanner(finding)],
        analyzer=FailingAnalyzer("Gemini SDK unavailable"),
        knowledge_repo=DummyReadRepo(),
        fix_repo=DummyReadRepo(),
        log_repo=log_repo,
    )

    result = pipeline.run(str(vulnerable_file))

    assert result["is_clean"] is False
    assert result["fix_suggestions"] == []
    assert len(log_repo.saved) == 1
    assert log_repo.saved[0]["status"] == "analysis_failed"
    assert log_repo.saved[0]["analysis_error"] == "Gemini SDK unavailable"
    assert log_repo.saved[0]["file_path"] == str(vulnerable_file)
    assert log_repo.saved[0]["issue_id"] == f"{vulnerable_file}_CWE-89_7"


def test_deduplicate_keeps_findings_from_different_files():
    findings = [
        Vulnerability(
            file_path="app.py",
            cwe_id="CWE-89",
            severity="HIGH",
            line_number=5,
            code_snippet="cursor.execute(query % user_input)",
        ),
        Vulnerability(
            file_path="requirements.txt",
            cwe_id="CWE-89",
            severity="HIGH",
            line_number=5,
            code_snippet="requests==2.9.0",
        ),
    ]

    deduplicated = AnalysisPipeline._deduplicate(findings)

    assert len(deduplicated) == 2
