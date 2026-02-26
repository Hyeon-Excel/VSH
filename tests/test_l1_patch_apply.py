from __future__ import annotations

from pathlib import Path

import pytest

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.patch_apply import PatchApplyError, apply_unified_patch
from vsh.l1_hot.service import L1Service


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_apply_unified_patch_adds_annotation_block() -> None:
    service = L1Service()
    code = _load_fixture("python_sqli_bad.py")
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=code,
            language="python",
            file_path="tests/fixtures/python_sqli_bad.py",
            mode=ScanMode.FILE,
        )
    )
    assert response.annotation_patch.strip()

    patched = apply_unified_patch(code, response.annotation_patch)
    assert "VSH Alert [HIGH] vsh.python.sqli.fstring" in patched
    assert "Recommendation: Use parameterized queries instead of string interpolation." in patched
    assert "query = f\"SELECT * FROM users WHERE username = '{username}'\"" in patched


def test_apply_unified_patch_returns_original_for_empty_patch() -> None:
    code = _load_fixture("python_sqli_good.py")
    assert apply_unified_patch(code, "") == code


def test_apply_unified_patch_raises_on_context_mismatch() -> None:
    service = L1Service()
    original_code = _load_fixture("python_sqli_bad.py")
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=original_code,
            language="python",
            file_path="tests/fixtures/python_sqli_bad.py",
            mode=ScanMode.FILE,
        )
    )
    mismatched_code = original_code.replace("users", "accounts", 1)

    with pytest.raises(PatchApplyError):
        apply_unified_patch(mismatched_code, response.annotation_patch)
