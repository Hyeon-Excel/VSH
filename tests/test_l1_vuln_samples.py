from __future__ import annotations

from pathlib import Path

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.service import L1Service


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_l1_detects_python_sqli_and_secret_together() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("python_multi_bad.py"),
            language="python",
            file_path="tests/fixtures/python_multi_bad.py",
            mode=ScanMode.FILE,
        )
    )

    rule_ids = {finding.rule_id for finding in response.findings}
    assert "vsh.python.sqli.fstring" in rule_ids
    assert "vsh.common.secret.hardcoded" in rule_ids
    assert any(candidate.package_name == "sqlite3" for candidate in response.import_candidates)


def test_l1_detects_javascript_xss_and_secret_together() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("javascript_multi_bad.js"),
            language="javascript",
            file_path="tests/fixtures/javascript_multi_bad.js",
            mode=ScanMode.FILE,
        )
    )

    rule_ids = {finding.rule_id for finding in response.findings}
    assert "vsh.js.xss.innerhtml" in rule_ids
    assert "vsh.common.secret.hardcoded" in rule_ids


def test_l1_detects_typescript_xss() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("typescript_xss_bad.ts"),
            language="typescript",
            file_path="tests/fixtures/typescript_xss_bad.ts",
            mode=ScanMode.FILE,
        )
    )

    assert any(finding.rule_id == "vsh.js.xss.innerhtml" for finding in response.findings)


def test_l1_detects_multiple_hardcoded_secrets() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("secrets_multiple_bad.txt"),
            language="auto",
            file_path="tests/fixtures/secrets_multiple_bad.txt",
            mode=ScanMode.FILE,
        )
    )

    secret_hits = [finding for finding in response.findings if finding.rule_id == "vsh.common.secret.hardcoded"]
    assert len(secret_hits) >= 2
