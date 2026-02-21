"""Report rendering utilities."""

from __future__ import annotations

from pathlib import Path

from vsh.common.models import Finding


class ReportRenderer:
    """Renders markdown/json report files for L3 output."""

    def render_markdown(self, repo_path: str, findings: list[Finding]) -> str:
        artifacts = Path(repo_path) / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        report_path = artifacts / "report.md"
        report_path.write_text(
            "# VSH Report\n\nThis is a placeholder report generated during design phase.\n",
            encoding="utf-8",
        )
        del findings
        return str(report_path)

    def render_json(self, repo_path: str, findings: list[Finding]) -> str:
        artifacts = Path(repo_path) / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        report_path = artifacts / "report.json"
        report_path.write_text('{"status":"placeholder","findings":[]}\n', encoding="utf-8")
        del findings
        return str(report_path)
