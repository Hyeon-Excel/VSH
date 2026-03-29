from layer2.analyzer.mock_analyzer import MockAnalyzer
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from repository.fix_repo import MockFixRepo
from repository.knowledge_repo import MockKnowledgeRepo
from pipeline.pipeline_factory import PipelineFactory
from layer2.retriever.evidence_retriever import EvidenceRetriever


def test_mock_analyzer_uses_fix_repo_templates():
    analyzer = MockAnalyzer()
    knowledge = MockKnowledgeRepo().find_all()
    fix_hints = MockFixRepo().find_all()
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/e2e_target.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=5,
                code_snippet="cursor.execute('SELECT * FROM users WHERE id = %s' % user_input)",
            )
        ],
    )

    suggestions = analyzer.analyze(scan_result, knowledge, fix_hints)

    assert len(suggestions) == 1
    assert suggestions[0].fixed_code == "cursor.execute('SELECT * FROM users WHERE id = %s', (user_input,))"
    assert suggestions[0].kisa_reference == "KISA 시큐어코딩 DB-01"
    assert suggestions[0].issue_id == "tests/e2e_target.py_CWE-89_5"
    assert "KISA 시큐어코딩 DB-01" in suggestions[0].evidence_refs
    assert suggestions[0].decision_status == "confirmed"
    assert suggestions[0].confidence_score > 0
    assert suggestions[0].confidence_reason


def test_mock_analyzer_builds_dependency_upgrade_suggestion():
    analyzer = MockAnalyzer()
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="requirements.txt",
                cwe_id="CWE-829",
                severity="HIGH",
                line_number=1,
                code_snippet="requests==2.9.0",
            )
        ],
    )

    evidence_map = EvidenceRetriever().retrieve(scan_result, knowledge=[], fix_hints=[])
    suggestions = analyzer.analyze(scan_result, knowledge=[], fix_hints=[], evidence_map=evidence_map)

    assert len(suggestions) == 1
    assert suggestions[0].fixed_code == "requests>=2.20.0"
    assert "CVE-2018-18074" in (suggestions[0].kisa_reference or "")
    assert suggestions[0].file_path == "requirements.txt"
    assert "Safe floor: 2.20.0" in suggestions[0].evidence_refs
    assert suggestions[0].decision_status == "confirmed"
    assert suggestions[0].confidence_score > 0
    assert suggestions[0].confidence_reason


def test_pipeline_factory_supports_mock_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    pipeline = PipelineFactory.create()

    assert pipeline.analyzer.__class__.__name__ == "MockAnalyzer"


def test_mock_analyzer_reflects_verification_context_in_supply_chain_output():
    analyzer = MockAnalyzer()
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="requirements.txt",
                cwe_id="CWE-829",
                severity="HIGH",
                line_number=1,
                code_snippet="requests==2.9.0",
            )
        ],
    )

    evidence_map = {
        "requirements.txt_CWE-829_1": {
            "issue_id": "requirements.txt_CWE-829_1",
            "file_path": "requirements.txt",
            "cwe_id": "CWE-829",
            "line_number": 1,
            "evidence_refs": ["CWE-829", "CVE-2018-18074"],
            "evidence_summary": "requirements.txt에 취약 버전 의존성이 탐지되었습니다.",
            "primary_reference": "CVE-2018-18074",
            "recommended_fix": "requests>=2.20.0",
            "registry_status": "FOUND",
            "registry_summary": "registry에서 requests==2.9.0 선언을 확인했습니다.",
            "osv_status": "FOUND",
            "osv_summary": "OSV advisory에서 취약 버전으로 확인되었습니다.",
            "verification_summary": "Registry[FOUND] registry에서 requests==2.9.0 선언을 확인했습니다. | OSV[FOUND] OSV advisory에서 취약 버전으로 확인되었습니다.",
            "retrieval_backend": "hybrid",
            "chroma_status": "READY",
            "chroma_summary": "Chroma collection `vsh_kisa_guide` 연결이 활성화되었습니다.",
            "chroma_hits": 2,
        }
    }

    suggestions = analyzer.analyze(scan_result, knowledge=[], fix_hints=[], evidence_map=evidence_map)

    assert len(suggestions) == 1
    suggestion = suggestions[0]
    assert suggestion.registry_status == "FOUND"
    assert suggestion.osv_status == "FOUND"
    assert suggestion.verification_summary
    assert suggestion.retrieval_backend == "hybrid"
    assert suggestion.chroma_status == "READY"
    assert suggestion.chroma_hits == 2
    assert "Registry[FOUND]" in (suggestion.reachability or "")
    assert "검증 결과:" in suggestion.description
    assert suggestion.decision_status == "confirmed"
    assert suggestion.confidence_score >= 85
    assert suggestion.confidence_reason


def test_mock_analyzer_dependency_fix_falls_back_to_valid_requirement_when_safe_version_missing():
    analyzer = MockAnalyzer()

    package_name, fixed_requirement, reference = analyzer._build_dependency_fix("simplejson")

    assert package_name == "simplejson"
    assert fixed_requirement == "simplejson"
    assert reference == "Dependency policy"


def test_mock_analyzer_dependency_fix_returns_empty_fix_when_requirement_parse_fails():
    analyzer = MockAnalyzer()

    package_name, fixed_requirement, reference = analyzer._build_dependency_fix("./local-package.whl")

    assert package_name == ""
    assert fixed_requirement == ""
    assert reference == "Dependency policy"
