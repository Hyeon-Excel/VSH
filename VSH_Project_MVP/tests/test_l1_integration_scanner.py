from models.vulnerability import Vulnerability
from orchestration.pipeline_factory import PipelineFactory
from layer1.scanner import VSHL1Scanner
from shared.finding_dedup import deduplicate_findings


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
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")

    try:
        import config
        config.VULNERABLE_PACKAGES["requests"] = {"vulnerable_below": "2.26.0", "cve": "CVE-9999"}
    except Exception:
        pass

    scanner = VSHL1Scanner()
    result = scanner.scan(str(sample))

    cwe_ids = {finding.cwe_id for finding in result.findings}
    assert "CWE-89" in cwe_ids
    assert "CWE-1104" in cwe_ids

    sql_finding = next(finding for finding in result.findings if finding.cwe_id == "CWE-89")
    typo_finding = next(finding for finding in result.findings if finding.cwe_id == "CWE-1104")

    assert sql_finding.reachability_status == "reachable"
    assert typo_finding.metadata["similar_to"] == "requests"
    assert len(result.vuln_records) >= 2
    assert result.vuln_records[0].source == "L1"
    assert result.vuln_records[0].kisa_ref
    assert result.vuln_records[0].reachability_status == "reachable"
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
    assert "Reachability: reachable" in annotated.annotated_files[str(sample)]


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
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    try:
        import config
        config.VULNERABLE_PACKAGES["requests"] = {"vulnerable_below": "2.26.0", "cve": "CVE-9999"}
    except Exception:
        pass

    pipeline = PipelineFactory.create()
    scan_only_result = pipeline.run_scan_only(str(sample))
    run_result = pipeline.run(str(sample))

    assert scan_only_result["vuln_records"]
    assert scan_only_result["package_records"]
    assert scan_only_result["annotated_files"]
    assert run_result["vuln_records"]
    assert run_result["package_records"]
    assert run_result["l2_vuln_records"]
    assert run_result["vuln_records"][0]["kisa_ref"]
    assert run_result["vuln_records"][0]["reachability_status"] == "reachable"
    assert "fix_suggestion" in run_result["vuln_records"][0]
    assert run_result["l2_vuln_records"][0]["source"] == "L2"
    assert run_result["l2_vuln_records"][0]["vuln_id"]
    assert run_result["l2_vuln_records"][0]["fix_suggestion"]
    assert run_result["annotated_files"]
    assert str(sample) in run_result["annotated_files"]
    assert "fix_suggestions" in run_result
    assert run_result["summary"]["l1_vuln_records_total"] >= 2
    assert run_result["summary"]["l1_package_records_total"] >= 1
    assert run_result["summary"]["l2_vuln_records_total"] >= 2
    assert run_result["summary"]["annotation_preview_total"] >= 1
    assert run_result["summary"]["rule_tagged_total"] >= 2
    assert run_result["summary"]["reachable_findings_total"] >= 1
    assert run_result["summary"]["typosquatting_findings_total"] >= 1


def test_deduplicate_findings_merges_metadata_without_losing_signal():
    first = Vulnerability(
        file_path="sample.py",
        rule_id="RULE-1",
        cwe_id="CWE-89",
        severity="MEDIUM",
        line_number=10,
        code_snippet="cursor.execute(query)",
        reachability_status="unknown",
        references=["KISA-1"],
        metadata={"scanner": "pattern"},
    )
    second = Vulnerability(
        file_path="sample.py",
        rule_id=None,
        cwe_id="CWE-89",
        severity="HIGH",
        line_number=10,
        code_snippet="cursor.execute(query % user_input)",
        reachability_status="reachable",
        references=["OWASP-A03"],
        metadata={"source": "tree-sitter"},
    )

    merged = deduplicate_findings([first, second])

    assert len(merged) == 1
    finding = merged[0]
    assert finding.rule_id == "RULE-1"
    assert finding.severity == "HIGH"
    assert finding.reachability_status == "reachable"
    assert finding.references == ["KISA-1", "OWASP-A03"]
    assert finding.metadata["scanner"] == "pattern"
    assert finding.metadata["source"] == "tree-sitter"
    assert finding.code_snippet == "cursor.execute(query % user_input)"


def test_sbom_scanner_is_target_aware(tmp_path):
    # project structure with package.json and requirements
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text('{"dependencies": {"express": "4.17.1", "lodash": "4.17.21"}}', encoding="utf-8")
    (project / "requirements.txt").write_text("requests==2.25.1\n", encoding="utf-8")

    # vulnerable package configured in config.py optionally; fallback by dynamic injection
    try:
        from config import VULNERABLE_PACKAGES
        VULNERABLE_PACKAGES["requests"] = {"vulnerable_below": "2.26.0", "cve": "CVE-XXXX"}
    except ImportError:
        pass

    from layer1.scanner.sbom_scanner import SBOMScanner

    scanner = SBOMScanner()
    result = scanner.scan(str(project))

    assert result.file_path == str(project)
    assert any(f.cwe_id == "CWE-829" for f in result.findings)
    assert any("requests" in f.metadata.get("package", "") for f in result.findings)
    assert any(f.metadata.get("sbom_source") in {"package.json", "requirements.txt"} for f in result.findings)


def test_mixed_language_detection_project(tmp_path):
    folder = tmp_path / "ml"
    folder.mkdir()
    (folder / "app.py").write_text("print(\"Hello\")\n", encoding="utf-8")
    (folder / "app.js").write_text("console.log('hi')\n", encoding="utf-8")

    from layer1.common.import_risk import detect_project_languages
    langs = detect_project_languages(str(folder))

    assert "python" in langs
    assert "javascript" in langs

