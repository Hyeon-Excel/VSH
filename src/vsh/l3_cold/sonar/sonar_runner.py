"""SonarQube runner adapter."""

from __future__ import annotations

from vsh.common.models import Finding


class SonarRunner:
    """Runs project-wide SAST scan.

    TODO:
    - Integrate sonar-scanner execution
    - Convert result issues to Finding model
    """

    def scan(self, repo_path: str) -> list[Finding]:
        del repo_path
        return []
