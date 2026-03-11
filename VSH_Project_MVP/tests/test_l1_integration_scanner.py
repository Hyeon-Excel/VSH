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
    assert len(result.vuln_records) >= 2
    assert result.vuln_records[0].source == "L1"
    assert result.vuln_records[0].kisa_ref
    assert result.vuln_records[0].reachability_status == "unknown"
    assert result.vuln_records[0].fix_suggestion
    assert result.package_records
    assert all(record.source == "L1" for record in result.package_records)
    assert any(record.name == "requests" for record in result.package_records)


def test_vsh_l1_scanner_can_build_annotation_preview(tmp_path):
    sample = tmp_path / "annotate_me.py"
    sample.write_text(
        "\n".join(
            [
                "user_input = input()",
                'cursor.execute(f"SELECT * FROM users WHERE id={user_input}")',
            ]
        ),
        encoding="utf-8",
    )

    scanner = VSHL1Scanner()
    result = scanner.scan(str(sample))
    annotated = scanner.annotate(result)

    assert str(sample) in annotated.annotated_files
    assert "[VSH-L1]" in annotated.annotated_files[str(sample)]
    assert "Reachability: YES" in annotated.annotated_files[str(sample)]


def test_pipeline_factory_can_enable_integrated_l1_scanner(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("L1_SCANNER_MODE", "integrated")

    pipeline = PipelineFactory.create()

    assert len(pipeline.scanners) == 1
    assert isinstance(pipeline.scanners[0], VSHL1Scanner)


def test_integrated_pipeline_exposes_l1_normalized_outputs(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("L1_SCANNER_MODE", "integrated")

    sample = tmp_path / "integrated.py"
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

    pipeline = PipelineFactory.create()
    scan_only_result = pipeline.run_scan_only(str(sample))
    run_result = pipeline.run(str(sample))

    assert scan_only_result["vuln_records"]
    assert scan_only_result["package_records"]
    assert scan_only_result["annotated_files"]
    assert run_result["vuln_records"]
    assert run_result["package_records"]
    assert run_result["vuln_records"][0]["kisa_ref"]
    assert run_result["vuln_records"][0]["reachability_status"] == "unknown"
    assert "fix_suggestion" in run_result["vuln_records"][0]
    assert run_result["annotated_files"]
    assert str(sample) in run_result["annotated_files"]
    assert "fix_suggestions" in run_result
    assert run_result["summary"]["l1_vuln_records_total"] >= 2
    assert run_result["summary"]["l1_package_records_total"] >= 1
    assert run_result["summary"]["annotation_preview_total"] >= 1
    assert run_result["summary"]["rule_tagged_total"] >= 2
    assert run_result["summary"]["reachable_findings_total"] >= 1
    assert run_result["summary"]["typosquatting_findings_total"] >= 1
