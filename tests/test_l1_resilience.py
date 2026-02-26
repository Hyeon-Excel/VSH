from __future__ import annotations

from pathlib import Path

from vsh.common.models import L1ScanAnnotateRequest, ScanMode, SupplyChainCandidate
from vsh.l1_hot.semgrep_runner import L1ScanError
from vsh.l1_hot.service import L1Service
from vsh.l1_hot.tree_sitter_runner import TreeSitterRunnerError


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FailingSemgrepRunner:
    @staticmethod
    def ruleset_version() -> str:
        return "test-rules"

    def run_semgrep(self, code: str, language: str) -> dict[str, object]:
        del code, language
        raise L1ScanError("L1_SCAN_FAILED: forced semgrep failure for isolation test.")


class StaticTreeSitterRunner:
    def run_tree_sitter(self, code: str, language: str) -> list[SupplyChainCandidate]:
        del code, language
        return [
            SupplyChainCandidate(
                package_name="sqlite3",
                line=1,
                source_type="import",
                extraction_method="unit-test",
            )
        ]


class FailingTreeSitterRunner:
    def run_tree_sitter(self, code: str, language: str) -> list[SupplyChainCandidate]:
        del code, language
        raise TreeSitterRunnerError("L1_TREE_SITTER_FAILED: forced tree-sitter failure for isolation test.")


def test_l1_preserves_import_candidates_when_semgrep_fails() -> None:
    service = L1Service(
        runner=FailingSemgrepRunner(),
        tree_runner=StaticTreeSitterRunner(),
    )
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("python_sqli_good.py"),
            language="python",
            file_path="tests/fixtures/python_sqli_good.py",
            mode=ScanMode.FILE,
        )
    )

    assert response.findings == []
    assert response.annotation_patch == ""
    assert len(response.import_candidates) == 1
    assert response.import_candidates[0].package_name == "sqlite3"
    assert any("L1_SCAN_FAILED" in error for error in response.errors)
    assert all("L1_TREE_SITTER_FAILED" not in error for error in response.errors)


def test_l1_preserves_findings_when_tree_sitter_fails() -> None:
    service = L1Service(tree_runner=FailingTreeSitterRunner())
    response = service.scan_annotate(
        L1ScanAnnotateRequest(
            code=_load_fixture("python_sqli_bad.py"),
            language="python",
            file_path="tests/fixtures/python_sqli_bad.py",
            mode=ScanMode.FILE,
        )
    )

    assert len(response.findings) >= 1
    assert response.annotation_patch.strip()
    assert response.import_candidates == []
    assert any("L1_TREE_SITTER_FAILED" in error for error in response.errors)
    assert all("L1_SCAN_FAILED" not in error for error in response.errors)
