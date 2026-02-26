"""L1 orchestration service."""

from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from vsh.common.models import L1ScanAnnotateRequest, L1ScanAnnotateResponse, SupplyChainCandidate
from vsh.l1_hot.annotate import build_annotation_patch
from vsh.l1_hot.normalize import semgrep_json_to_findings
from vsh.l1_hot.semgrep_runner import L1ScanError, L1TimeoutError, SemgrepRunner
from vsh.l1_hot.tree_sitter_runner import TreeSitterRunner, TreeSitterRunnerError


class L1Service:
    def __init__(
        self,
        runner: SemgrepRunner | None = None,
        tree_runner: TreeSitterRunner | None = None,
    ) -> None:
        self.runner = runner or SemgrepRunner()
        self.tree_runner = tree_runner or TreeSitterRunner()
        self._semgrep_cache: dict[str, dict[str, Any]] = {}
        self._tree_cache: dict[str, list[SupplyChainCandidate]] = {}

    def scan_annotate(self, request: L1ScanAnnotateRequest) -> L1ScanAnnotateResponse:
        started = time.perf_counter()
        errors: list[str] = []
        findings = []
        import_candidates: list[SupplyChainCandidate] = []
        patch = ""

        with ThreadPoolExecutor(max_workers=2) as executor:
            semgrep_future = executor.submit(
                self._run_semgrep_cached,
                request.code,
                request.language,
            )
            tree_future = executor.submit(
                self._run_tree_sitter_cached,
                request.code,
                request.language,
            )

            semgrep_json: dict[str, Any] = {"results": [], "errors": []}
            try:
                semgrep_json = semgrep_future.result()
            except L1TimeoutError as exc:
                errors.append(str(exc))
            except L1ScanError as exc:
                errors.append(str(exc))
            except Exception as exc:  # pragma: no cover - defensive path
                errors.append(f"L1 unexpected semgrep error: {exc}")

            try:
                import_candidates = tree_future.result()
            except TreeSitterRunnerError as exc:
                errors.append(str(exc))
            except Exception as exc:  # pragma: no cover - defensive path
                errors.append(f"L1 unexpected tree-sitter error: {exc}")

        try:
            findings = semgrep_json_to_findings(semgrep_json, request.file_path)
            patch = build_annotation_patch(request.code, findings, request.file_path)
        except Exception as exc:  # pragma: no cover - defensive path
            errors.append(f"L1 post-processing error: {exc}")

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return L1ScanAnnotateResponse(
            findings=findings,
            import_candidates=import_candidates,
            annotation_patch=patch,
            timing_ms=elapsed_ms,
            errors=errors,
        )

    def _cache_key(self, stage: str, code: str, language: str) -> str:
        ruleset_version = self.runner.ruleset_version()
        raw = f"{stage}\0{language}\0{ruleset_version}\0{code}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _run_semgrep_cached(self, code: str, language: str) -> dict[str, Any]:
        cache_key = self._cache_key("semgrep", code, language)
        result = self._semgrep_cache.get(cache_key)
        if result is None:
            result = self.runner.run_semgrep(code, language)
            self._semgrep_cache[cache_key] = result
        return result

    def _run_tree_sitter_cached(self, code: str, language: str) -> list[SupplyChainCandidate]:
        cache_key = self._cache_key("tree-sitter", code, language)
        result = self._tree_cache.get(cache_key)
        if result is None:
            result = self.tree_runner.run_tree_sitter(code, language)
            self._tree_cache[cache_key] = result
        return [candidate.model_copy() for candidate in result]
