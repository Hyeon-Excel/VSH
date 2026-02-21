"""L3 orchestration service."""

from __future__ import annotations

from vsh.common.models import L3FullReportRequest, L3FullReportResponse
from vsh.l3_cold.report.renderer import ReportRenderer
from vsh.l3_cold.sbom.syft_runner import SyftRunner
from vsh.l3_cold.sonar.sonar_runner import SonarRunner


class L3Service:
    def __init__(
        self,
        sonar_runner: SonarRunner | None = None,
        syft_runner: SyftRunner | None = None,
        report_renderer: ReportRenderer | None = None,
    ) -> None:
        self.sonar_runner = sonar_runner or SonarRunner()
        self.syft_runner = syft_runner or SyftRunner()
        self.report_renderer = report_renderer or ReportRenderer()

    def full_report(self, request: L3FullReportRequest) -> L3FullReportResponse:
        findings = list(request.baseline_findings)
        findings.extend(self.sonar_runner.scan(request.repo_path))

        sbom_path = self.syft_runner.generate(request.repo_path)
        report_md_path = self.report_renderer.render_markdown(request.repo_path, findings)
        report_json_path = self.report_renderer.render_json(request.repo_path, findings)

        return L3FullReportResponse(
            report_md_path=report_md_path,
            report_json_path=report_json_path,
            sbom_path=sbom_path,
            summary="L3 placeholder report completed.",
            errors=[],
        )
