import importlib
from pathlib import Path

from models.fix_suggestion import FixSuggestion
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from pipeline.analysis_pipeline import AnalysisPipeline
from shared.finding_dedup import deduplicate_findings


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


class CapturingAnalyzer(DummyAnalyzer):
    def __init__(self, suggestion: FixSuggestion):
        super().__init__(suggestion)
        self.captured_evidence_map = None

    def analyze(self, scan_result, knowledge, fix_hints, evidence_map=None):
        self.captured_evidence_map = evidence_map
        return super().analyze(scan_result, knowledge, fix_hints, evidence_map=evidence_map)


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


class DummyEvidenceRetriever:
    def __init__(
        self,
        retrieval_backend: str = "static_only",
        chroma_status: str = "MISSING_DEPENDENCY",
        chroma_summary: str = "chromadb 패키지가 설치되지 않아 Chroma RAG가 비활성화되었습니다.",
        chroma_hits: int = 0,
    ):
        self._retrieval_backend = retrieval_backend
        self._chroma_status = chroma_status
        self._chroma_summary = chroma_summary
        self._chroma_hits = chroma_hits

    def runtime_status(self):
        return {
            "status": self._chroma_status,
            "summary": self._chroma_summary,
        }

    def retrieve(self, scan_result, knowledge, fix_hints):
        evidence_map = {}
        for finding in scan_result.findings:
            issue_id = f"{finding.file_path}_{finding.cwe_id}_{finding.line_number}"
            evidence_map[issue_id] = {
                "issue_id": issue_id,
                "file_path": finding.file_path,
                "cwe_id": finding.cwe_id,
                "line_number": finding.line_number,
                "knowledge_description": "테스트용 근거 설명",
                "remediation_summary": "테스트용 수정 요약",
                "evidence_summary": f"{Path(finding.file_path).name}에서 테스트용 근거가 생성되었습니다.",
                "evidence_refs": [finding.cwe_id, "KISA 시큐어코딩 DB-01"],
                "primary_reference": "KISA 시큐어코딩 DB-01",
                "recommended_fix": None,
                "retrieval_backend": self._retrieval_backend,
                "chroma_status": self._chroma_status,
                "chroma_summary": self._chroma_summary,
                "chroma_hits": self._chroma_hits,
                "decision_status": None,
                "confidence_score": 0,
                "confidence_reason": None,
            }
        return evidence_map


def test_fix_suggestion_preserves_l2_metadata():
    suggestion = FixSuggestion(
        issue_id="issue-1",
        file_path="requirements.txt",
        cwe_id="CWE-89",
        line_number=7,
        metadata={"l2": {"reachability_note": "User-controlled input reaches the query."}},
        kisa_ref="KISA DB-01",
        original_code="cursor.execute(query % user_input)",
        fixed_code="cursor.execute(query, (user_input,))",
        description="Use parameter binding instead of string interpolation.",
    )

    payload = suggestion.model_dump()

    assert payload["file_path"] == "requirements.txt"
    assert payload["vuln_id"] == "issue-1"
    assert payload["cwe_id"] == "CWE-89"
    assert payload["line_number"] == 7
    assert payload["kisa_ref"] == "KISA DB-01"
    assert payload["evidence"] == "cursor.execute(query % user_input)"
    assert payload["fix_suggestion"] == "Use parameter binding instead of string interpolation."
    assert payload["metadata"]["l2"]["reachability_note"] == "User-controlled input reaches the query."
    assert payload["metadata"]["l2"]["evidence_refs"] == []
    assert payload["metadata"]["l2"]["evidence_summary"] is None
    assert payload["metadata"]["l2"]["retrieval_backend"] is None
    assert payload["metadata"]["l2"]["chroma_status"] is None
    assert payload["metadata"]["l2"]["chroma_summary"] is None
    assert payload["metadata"]["l2"]["chroma_hits"] == 0
    assert payload["metadata"]["l2"]["registry_status"] is None
    assert payload["metadata"]["l2"]["registry_summary"] is None
    assert payload["metadata"]["l2"]["osv_status"] is None
    assert payload["metadata"]["l2"]["osv_summary"] is None
    assert payload["metadata"]["l2"]["verification_summary"] is None
    assert payload["metadata"]["l2"]["decision_status"] is None
    assert payload["metadata"]["l2"]["confidence_score"] == 0
    assert payload["metadata"]["l2"]["confidence_reason"] is None
    assert payload["metadata"]["l2"]["patch_status"] is None
    assert payload["metadata"]["l2"]["patch_summary"] is None
    assert payload["metadata"]["l2"]["patch_diff"] is None
    assert payload["metadata"]["l2"]["processing_trace"] == []
    assert payload["metadata"]["l2"]["processing_summary"] is None
    assert payload["metadata"]["l2"]["category"] is None
    assert payload["metadata"]["l2"]["remediation_kind"] is None
    assert payload["metadata"]["l2"]["target_ref"] is None
    assert payload["metadata"]["l2"]["confidence_score"] == 0
    assert payload["metadata"]["l2"]["processing_trace"] == []


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
        evidence_retriever=DummyEvidenceRetriever(),
        knowledge_repo=DummyReadRepo(),
        fix_repo=DummyReadRepo(),
        log_repo=log_repo,
    )

    result = pipeline.run(str(vulnerable_file))
    metadata = result["fix_suggestions"][0]["metadata"]["l2"]

    assert result["fix_suggestions"][0]["cwe_id"] == "CWE-89"
    assert result["fix_suggestions"][0]["line_number"] == 7
    assert result["fix_suggestions"][0]["file_path"] == str(vulnerable_file)
    assert result["fix_suggestions"][0]["vuln_id"] == f"{vulnerable_file}_CWE-89_7"
    assert result["fix_suggestions"][0]["kisa_ref"] == "KISA DB-01"
    assert metadata["reachability_note"] == "User input is directly reachable from the sink."
    assert metadata["evidence_refs"] == ["CWE-89", "KISA 시큐어코딩 DB-01"]
    assert metadata["evidence_summary"] == "sample.py에서 SQL Injection 패턴이 확인되었습니다."
    assert metadata["retrieval_backend"] == "static_only"
    assert metadata["chroma_status"] == "MISSING_DEPENDENCY"
    assert metadata["chroma_hits"] == 0
    assert metadata["decision_status"] == "confirmed"
    assert metadata["confidence_score"] > 0
    assert metadata["confidence_reason"]
    assert metadata["patch_status"] == "GENERATED"
    assert metadata["patch_summary"]
    assert "-cursor.execute(query % user_input)" in (metadata["patch_diff"] or "")
    assert "+cursor.execute(query, (user_input,))" in (metadata["patch_diff"] or "")
    assert metadata["category"] == "code"
    assert metadata["remediation_kind"] == "code_patch"
    assert metadata["target_ref"] == f"{vulnerable_file}:7"
    assert metadata["processing_trace"] == [
        "scan:detected",
        "retrieval:enriched",
        "retrieval:backend:static_only",
        "retrieval:chroma:MISSING_DEPENDENCY",
        "analysis:confirmed",
        "patch:GENERATED",
    ]
    assert metadata["processing_summary"]
    assert len(log_repo.saved) == 1
    assert log_repo.saved[0]["issue_id"] == f"{vulnerable_file}_CWE-89_7"
    assert log_repo.saved[0]["vuln_id"] == f"{vulnerable_file}_CWE-89_7"
    assert log_repo.saved[0]["metadata"]["l2"]["decision_status"] == "confirmed"
    assert log_repo.saved[0]["file_path"] == str(vulnerable_file)
    assert log_repo.saved[0]["l2_vuln_record"]["source"] == "L2"
    assert log_repo.saved[0]["l2_vuln_record"]["cwe_id"] == "CWE-89"
    assert log_repo.saved[0]["l2_vuln_record"]["kisa_ref"] == "KISA DB-01"
    assert log_repo.saved[0]["description"] == "Use parameter binding instead of string interpolation."
    assert log_repo.saved[0]["reachability"] == "User input is directly reachable from the sink."
    assert log_repo.saved[0]["kisa_reference"] == "KISA DB-01"
    assert log_repo.saved[0]["evidence_refs"] == ["CWE-89", "KISA 시큐어코딩 DB-01"]
    assert log_repo.saved[0]["evidence_summary"] == "sample.py에서 SQL Injection 패턴이 확인되었습니다."
    assert log_repo.saved[0]["retrieval_backend"] == "static_only"
    assert log_repo.saved[0]["chroma_status"] == "MISSING_DEPENDENCY"
    assert log_repo.saved[0]["chroma_hits"] == 0
    assert log_repo.saved[0]["registry_status"] is None
    assert log_repo.saved[0]["osv_status"] is None
    assert log_repo.saved[0]["decision_status"] == "confirmed"
    assert log_repo.saved[0]["confidence_score"] > 0
    assert log_repo.saved[0]["confidence_reason"]
    assert log_repo.saved[0]["patch_status"] == "GENERATED"
    assert log_repo.saved[0]["patch_summary"]
    assert log_repo.saved[0]["patch_diff"]
    assert log_repo.saved[0]["category"] == "code"
    assert log_repo.saved[0]["remediation_kind"] == "code_patch"
    assert log_repo.saved[0]["target_ref"] == f"{vulnerable_file}:7"
    assert log_repo.saved[0]["processing_trace"] == [
        "scan:detected",
        "retrieval:enriched",
        "retrieval:backend:static_only",
        "retrieval:chroma:MISSING_DEPENDENCY",
        "analysis:confirmed",
        "patch:GENERATED",
    ]
    assert log_repo.saved[0]["processing_summary"]
    assert result["summary"]["findings_total"] == 1
    assert result["summary"]["patch_generated_total"] == 1
    assert result["summary"]["l2_vuln_records_total"] == 1
    assert result["summary"]["chroma_status"] == "MISSING_DEPENDENCY"
    assert result["summary"]["retrieval_static_only_total"] == 1
    assert result["summary"]["chroma_enriched_total"] == 0
    assert result["summary"]["decision_confirmed_total"] == 1
    assert result["summary"]["confidence_high_total"] == 0


def test_pipeline_passes_verification_context_into_analyzer(tmp_path):
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
        original_code="requests==2.9.0",
        fixed_code="requests>=2.20.0",
        description="Upgrade the vulnerable dependency.",
    )
    analyzer = CapturingAnalyzer(suggestion)
    pipeline = AnalysisPipeline(
        scanners=[DummyScanner(finding)],
        analyzer=analyzer,
        evidence_retriever=DummyEvidenceRetriever(retrieval_backend="hybrid", chroma_status="READY", chroma_hits=2),
        knowledge_repo=DummyReadRepo(),
        fix_repo=DummyReadRepo(),
        log_repo=DummyWriteRepo(),
    )

    pipeline.run(str(scanned_file))

    assert analyzer.captured_evidence_map is not None
    context = analyzer.captured_evidence_map[f"{requirements_file}_CWE-829_1"]
    assert context["retrieval_backend"] == "hybrid"
    assert context["chroma_status"] == "READY"
    assert context["chroma_hits"] == 2
    assert context["registry_status"] == "FOUND"
    assert context["osv_status"] == "FOUND"
    assert context["verification_summary"]


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
        evidence_retriever=DummyEvidenceRetriever(),
        knowledge_repo=DummyReadRepo(),
        fix_repo=DummyReadRepo(),
        log_repo=log_repo,
    )

    result = pipeline.run(str(scanned_file))
    metadata = result["fix_suggestions"][0]["metadata"]["l2"]

    assert result["fix_suggestions"][0]["file_path"] == str(requirements_file)
    assert metadata["registry_status"] == "FOUND"
    assert metadata["osv_status"] == "FOUND"
    assert "requests==2.9.0" in (metadata["registry_summary"] or "")
    assert "CVE-2018-18074" in (metadata["osv_summary"] or "")
    assert metadata["patch_status"] == "GENERATED"
    assert "-requests==2.9.0" in (metadata["patch_diff"] or "")
    assert "+requests>=2.20.0" in (metadata["patch_diff"] or "")
    assert metadata["decision_status"] == "confirmed"
    assert metadata["confidence_score"] >= 85
    assert metadata["confidence_reason"]
    assert metadata["category"] == "supply_chain"
    assert metadata["remediation_kind"] == "version_bump_patch"
    assert metadata["target_ref"] == "dependency:requests"
    assert metadata["processing_trace"] == [
        "scan:detected",
        "retrieval:enriched",
        "retrieval:backend:static_only",
        "retrieval:chroma:MISSING_DEPENDENCY",
        "verification:registry:FOUND",
        "verification:osv:FOUND",
        "analysis:confirmed",
        "patch:GENERATED",
    ]
    assert log_repo.saved[0]["file_path"] == str(requirements_file)
    assert log_repo.saved[0]["issue_id"] == f"{requirements_file}_CWE-829_1"
    assert log_repo.saved[0]["verification_summary"]
    assert log_repo.saved[0]["decision_status"] == "confirmed"
    assert log_repo.saved[0]["confidence_score"] >= 85
    assert log_repo.saved[0]["confidence_reason"]
    assert log_repo.saved[0]["patch_summary"]
    assert log_repo.saved[0]["category"] == "supply_chain"
    assert log_repo.saved[0]["remediation_kind"] == "version_bump_patch"
    assert log_repo.saved[0]["target_ref"] == "dependency:requests"
    assert result["summary"]["verified_total"] == 1
    assert result["summary"]["supply_chain_findings_total"] == 1
    assert result["summary"]["supply_chain_fix_suggestions_total"] == 1
    assert result["summary"]["decision_confirmed_total"] == 1
    assert result["summary"]["confidence_high_total"] == 1


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
        evidence_retriever=DummyEvidenceRetriever(),
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
    assert log_repo.saved[0]["registry_status"] is None
    assert log_repo.saved[0]["osv_status"] is None
    assert log_repo.saved[0]["decision_status"] == "analysis_failed"
    assert log_repo.saved[0]["confidence_score"] == 0
    assert log_repo.saved[0]["confidence_reason"]
    assert log_repo.saved[0]["patch_status"] is None
    assert log_repo.saved[0]["patch_diff"] is None
    assert log_repo.saved[0]["category"] == "code"
    assert log_repo.saved[0]["target_ref"] == f"{vulnerable_file}:7"
    assert log_repo.saved[0]["processing_trace"] == [
        "scan:detected",
        "retrieval:enriched",
        "retrieval:backend:static_only",
        "retrieval:chroma:MISSING_DEPENDENCY",
        "analysis:failed",
    ]
    assert log_repo.saved[0]["processing_summary"]


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

    deduplicated = deduplicate_findings(findings)

    assert len(deduplicated) == 2


def test_log_repo_uses_absolute_default_path_and_creates_parent_dir(tmp_path, monkeypatch):
    config_module = importlib.import_module("config")
    log_repo_module = importlib.import_module("repository.log_repo")

    assert Path(config_module.LOG_PATH).is_absolute()

    nested_log_path = tmp_path / "nested" / "logs" / "log.json"
    monkeypatch.setattr(log_repo_module, "LOG_PATH", str(nested_log_path))
    repo = log_repo_module.MockLogRepo()

    assert repo.save({"issue_id": "issue-1", "status": "pending"}) is True
    assert nested_log_path.exists()
