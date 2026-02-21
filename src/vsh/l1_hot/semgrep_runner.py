"""Semgrep runner for L1 scanning."""

from __future__ import annotations

from typing import Any


class SemgrepRunner:
    """Thin wrapper around semgrep CLI.

    TODO:
    - Execute semgrep with timeout
    - Provide minimal ruleset selection by language
    - Return JSON result compatible with normalize step
    """

    def run_semgrep(self, code: str, language: str) -> dict[str, Any]:
        raise NotImplementedError("Semgrep runner is not implemented yet.")
