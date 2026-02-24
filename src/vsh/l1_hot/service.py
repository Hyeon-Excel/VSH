"""L1 orchestration service."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from vsh.common.models import L1ScanAnnotateRequest, L1ScanAnnotateResponse
from vsh.l1_hot.annotate import build_annotation_patch
from vsh.l1_hot.normalize import semgrep_json_to_findings
from vsh.l1_hot.semgrep_runner import L1ScanError, L1TimeoutError, SemgrepRunner


class L1Service:
    def __init__(self, runner: SemgrepRunner | None = None) -> None:
        self.runner = runner or SemgrepRunner()
        self._scan_cache: dict[str, dict[str, Any]] = {}

    def scan_annotate(self, request: L1ScanAnnotateRequest) -> L1ScanAnnotateResponse:
        started = time.perf_counter()
        errors: list[str] = []
        findings = []
        patch = ""

        try:
            cache_key = self._cache_key(request.code, request.language)
            semgrep_json = self._scan_cache.get(cache_key)
            if semgrep_json is None:
                semgrep_json = self.runner.run_semgrep(request.code, request.language)
                self._scan_cache[cache_key] = semgrep_json
            findings = semgrep_json_to_findings(semgrep_json, request.file_path)
            patch = build_annotation_patch(request.code, findings, request.file_path)
        except L1TimeoutError as exc:
            errors.append(str(exc))
        except L1ScanError as exc:
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

    def _cache_key(self, code: str, language: str) -> str:
        ruleset_version = self.runner.ruleset_version()
        raw = f"{language}\0{ruleset_version}\0{code}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
