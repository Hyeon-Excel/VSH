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


def test_pipeline_factory_supports_mock_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    pipeline = PipelineFactory.create()

    assert pipeline.analyzer.__class__.__name__ == "MockAnalyzer"
