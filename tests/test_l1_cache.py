from __future__ import annotations

import time

from vsh.common.models import L1ScanAnnotateRequest, ScanMode, SupplyChainCandidate
from vsh.l1_hot.service import L1Service


class SlowCountingSemgrepRunner:
    def __init__(self) -> None:
        self.calls = 0

    @staticmethod
    def ruleset_version() -> str:
        return "test-rules"

    def run_semgrep(self, code: str, language: str) -> dict[str, object]:
        del code, language
        self.calls += 1
        time.sleep(0.09)
        return {"results": [], "errors": [], "engine": "unit-test"}


class SlowCountingTreeSitterRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run_tree_sitter(self, code: str, language: str) -> list[SupplyChainCandidate]:
        del code, language
        self.calls += 1
        time.sleep(0.09)
        return [
            SupplyChainCandidate(
                package_name="requests",
                line=1,
                source_type="import",
                extraction_method="unit-test",
            )
        ]


def test_l1_cache_hit_avoids_duplicate_runner_calls() -> None:
    semgrep_runner = SlowCountingSemgrepRunner()
    tree_runner = SlowCountingTreeSitterRunner()
    service = L1Service(runner=semgrep_runner, tree_runner=tree_runner)
    request = L1ScanAnnotateRequest(
        code='import requests\nprint("ok")\n',
        language="python",
        file_path="tests/fixtures/cache_sample.py",
        mode=ScanMode.SNIPPET,
    )

    start_first = time.perf_counter()
    first_response = service.scan_annotate(request)
    first_elapsed = time.perf_counter() - start_first

    start_second = time.perf_counter()
    second_response = service.scan_annotate(request)
    second_elapsed = time.perf_counter() - start_second

    assert first_response.errors == []
    assert second_response.errors == []
    assert first_response.import_candidates
    assert second_response.import_candidates
    assert semgrep_runner.calls == 1
    assert tree_runner.calls == 1
    assert second_elapsed < first_elapsed * 0.5
