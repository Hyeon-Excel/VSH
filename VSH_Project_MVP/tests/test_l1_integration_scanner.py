from orchestration.pipeline_factory import PipelineFactory
from layer1.scanner import VSHL1Scanner


def test_vsh_l1_scanner_detects_pattern_and_typosquatting(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text(
        "\n".join(
            [
                "import reqeusts",
                "user_input = input()",
                'cursor.execute(f"SELECT * FROM users WHERE id={user_input}")',
            ]
        ),
        encoding="utf-8",
    )

    scanner = VSHL1Scanner()
    result = scanner.scan(str(sample))

    cwe_ids = {finding.cwe_id for finding in result.findings}
    assert "CWE-89" in cwe_ids
    assert "CWE-1104" in cwe_ids

    sql_finding = next(finding for finding in result.findings if finding.cwe_id == "CWE-89")
    typo_finding = next(finding for finding in result.findings if finding.cwe_id == "CWE-1104")

    assert sql_finding.reachability_status == "YES"
    assert typo_finding.metadata["similar_to"] == "requests"


def test_pipeline_factory_can_enable_integrated_l1_scanner(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("L1_SCANNER_MODE", "integrated")

    pipeline = PipelineFactory.create()

    assert len(pipeline.scanners) == 1
    assert isinstance(pipeline.scanners[0], VSHL1Scanner)
