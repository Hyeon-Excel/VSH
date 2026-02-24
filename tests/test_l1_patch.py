from __future__ import annotations

from pathlib import Path

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.service import L1Service


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_l1_annotation_patch_has_unified_diff_format() -> None:
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
    assert response.annotation_patch.startswith("--- a/tests/fixtures/python_sqli_bad.py")
    assert "\n+++ b/tests/fixtures/python_sqli_bad.py\n" in response.annotation_patch
    assert "\n@@ " in response.annotation_patch
    assert "VSH Alert" in response.annotation_patch
    assert "Recommendation:" in response.annotation_patch


def test_l1_annotation_patch_is_empty_without_findings() -> None:
    service = L1Service()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("python_sqli_good.py"),
            language="python",
            file_path="tests/fixtures/python_sqli_good.py",
            mode=ScanMode.FILE,
        )
    )

    assert response.errors == []
    assert response.findings == []
    assert response.annotation_patch == ""
