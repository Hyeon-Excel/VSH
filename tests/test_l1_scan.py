from __future__ import annotations

from pathlib import Path

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.service import L1Service


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_l1_detects_python_sqli() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("python_sqli_bad.py"),
            language="python",
            file_path="tests/fixtures/python_sqli_bad.py",
            mode=ScanMode.FILE,
        )
    )

    assert response.errors == []
    assert len(response.findings) >= 1
    assert any(finding.rule_id == "vsh.python.sqli.fstring" for finding in response.findings)
    assert any(candidate.package_name == "sqlite3" for candidate in response.import_candidates)


def test_l1_detects_js_xss() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("js_xss_bad.js"),
            language="javascript",
            file_path="tests/fixtures/js_xss_bad.js",
            mode=ScanMode.FILE,
        )
    )

    assert response.errors == []
    assert len(response.findings) >= 1
    assert any(finding.rule_id == "vsh.js.xss.innerhtml" for finding in response.findings)


def test_l1_returns_no_findings_for_safe_samples() -> None:
    service = L1Service()
    python_response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("python_sqli_good.py"),
            language="python",
            file_path="tests/fixtures/python_sqli_good.py",
            mode=ScanMode.FILE,
        )
    )
    js_response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("js_xss_good.js"),
            language="javascript",
            file_path="tests/fixtures/js_xss_good.js",
            mode=ScanMode.FILE,
        )
    )

    assert python_response.errors == []
    assert js_response.errors == []
    assert python_response.findings == []
    assert js_response.findings == []
    assert any(candidate.package_name == "sqlite3" for candidate in python_response.import_candidates)
