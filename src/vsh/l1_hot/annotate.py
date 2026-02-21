"""Build L1 annotation patches."""

from __future__ import annotations

from vsh.common.models import Finding


def build_annotation_patch(code: str, findings: list[Finding], file_path: str) -> str:
    """Return unified diff text for inline annotations.

    TODO:
    - Insert structured warning comments near finding lines
    - Keep patch minimal and deterministic
    """

    del code, findings, file_path
    return ""
