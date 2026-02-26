from __future__ import annotations

import time

from vsh.common.models import L1ScanAnnotateRequest, ScanMode, SupplyChainCandidate
from vsh.l1_hot.service import L1Service


class SlowSemgrepRunner:
    def __init__(self, starts: dict[str, float]) -> None:
        self.starts = starts

    @staticmethod
    def ruleset_version() -> str:
        return "test-rules"

    def run_semgrep(self, code: str, language: str) -> dict[str, object]:
        del code, language
        self.starts["semgrep"] = time.perf_counter()
        time.sleep(0.30)
        return {"results": [], "errors": [], "engine": "unit-test"}


class SlowTreeSitterRunner:
    def __init__(self, starts: dict[str, float]) -> None:
        self.starts = starts

    def run_tree_sitter(self, code: str, language: str) -> list[SupplyChainCandidate]:
        del code, language
        self.starts["tree"] = time.perf_counter()
        time.sleep(0.30)
        return [
            SupplyChainCandidate(
                package_name="requests",
                line=1,
                source_type="import",
                extraction_method="unit-test",
            )
        ]


def test_l1_extracts_javascript_import_candidates() -> None:
    service = L1Service()
    code = 'import lodash from "lodash";\nconst express = require("express");\n'
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=code,
            language="javascript",
            file_path="tests/fixtures/js_imports_sample.js",
            mode=ScanMode.SNIPPET,
        )
    )
    packages = {candidate.package_name for candidate in response.import_candidates}
    assert "lodash" in packages
    assert "express" in packages


def test_l1_runs_semgrep_and_tree_sitter_concurrently() -> None:
    starts: dict[str, float] = {}
    service = L1Service(
        runner=SlowSemgrepRunner(starts),
        tree_runner=SlowTreeSitterRunner(starts),
    )
    started = time.perf_counter()
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code='import requests\nprint("ok")\n',
            language="python",
            file_path="tests/fixtures/parallel_sample.py",
            mode=ScanMode.SNIPPET,
        )
    )
    elapsed = time.perf_counter() - started

    assert response.errors == []
    assert len(response.import_candidates) == 1
    assert response.import_candidates[0].package_name == "requests"
    assert "semgrep" in starts and "tree" in starts
    assert abs(starts["semgrep"] - starts["tree"]) < 0.12
    assert elapsed < 0.55
