"""Syft runner adapter."""

from __future__ import annotations


class SyftRunner:
    """Generates SBOM files from repository path.

    TODO:
    - Execute syft with deterministic output format
    - Return output path and parseable metadata
    """

    def generate(self, repo_path: str) -> str | None:
        del repo_path
        return None
