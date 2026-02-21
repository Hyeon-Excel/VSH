"""L1 orchestration service."""

from __future__ import annotations

import time

from vsh.common.models import L1ScanAnnotateRequest, L1ScanAnnotateResponse
from vsh.l1_hot.annotate import build_annotation_patch
from vsh.l1_hot.normalize import semgrep_json_to_findings
from vsh.l1_hot.semgrep_runner import SemgrepRunner


class L1Service:
    def __init__(self, runner: SemgrepRunner | None = None) -> None:
        self.runner = runner or SemgrepRunner()

    def scan_annotate(self, request: L1ScanAnnotateRequest) -> L1ScanAnnotateResponse:
        started = time.perf_counter()
        errors: list[str] = []
        findings = []
        patch = ""

        try:
            semgrep_json = self.runner.run_semgrep(request.code, request.language)
            findings = semgrep_json_to_findings(semgrep_json, request.file_path)
            patch = build_annotation_patch(request.code, findings, request.file_path)
        except NotImplementedError as exc:
            errors.append(str(exc))
        except Exception as exc:  # pragma: no cover - defensive path
            errors.append(f"L1 unexpected error: {exc}")

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return L1ScanAnnotateResponse(
            findings=findings,
            annotation_patch=patch,
            timing_ms=elapsed_ms,
            errors=errors,
        )
