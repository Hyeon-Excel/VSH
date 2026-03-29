from __future__ import annotations

from pathlib import Path
from typing import List

from layer1.common import (
    annotate_files,
    annotate_reachability,
    detect_project_languages,
    detect_typosquatting_findings,
    guess_language,
    normalize_scan_result,
    scan_file_with_patterns,
)
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from repository.base_repository import BaseReadRepository
from shared.contracts import BaseScanner
from shared.finding_dedup import deduplicate_findings
from .mock_semgrep_scanner import MockSemgrepScanner
from .sbom_scanner import SBOMScanner


class VSHL1Scanner(BaseScanner):
    def __init__(self, knowledge_repo: BaseReadRepository | None = None):
        self.knowledge_repo = knowledge_repo
        self.pattern_scanner = MockSemgrepScanner(knowledge_repo=knowledge_repo) if knowledge_repo else None
        self.sbom_scanner = SBOMScanner()
        try:
            from .treesitter_scanner import TreeSitterScanner
            self.tree_sitter_scanner = TreeSitterScanner(knowledge_repo=knowledge_repo) if knowledge_repo else None
        except ModuleNotFoundError:
            self.tree_sitter_scanner = None

    def scan(self, file_path: str) -> ScanResult:
        target = Path(file_path)
        if not target.exists():
            return ScanResult(file_path=file_path, language=guess_language(file_path), findings=[])
        return self._scan_project(target) if target.is_dir() else self._scan_file(target)

    def _scan_file(self, path: Path) -> ScanResult:
        language = guess_language(str(path))
        findings = self._scan_single_file_findings(path, language)
        findings = annotate_reachability(str(path), deduplicate_findings(findings))
        findings.extend(self.sbom_scanner.scan(str(path)).findings)
        result = ScanResult(file_path=str(path), language=language, findings=deduplicate_findings(findings))
        return normalize_scan_result(result)

    def _scan_project(self, root: Path) -> ScanResult:
        findings: List[Vulnerability] = []
        for src in root.rglob("*"):
            if not src.is_file() or src.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"}:
                continue
            language = guess_language(str(src))
            file_findings = annotate_reachability(str(src), self._scan_single_file_findings(src, language))
            findings.extend(file_findings)
        findings.extend(self.sbom_scanner.scan(str(root)).findings)
        result = ScanResult(file_path=str(root), language="multi", findings=deduplicate_findings(findings))
        result.notes.append(f"project_languages={','.join(sorted(detect_project_languages(str(root))))}")
        return normalize_scan_result(result)

    def _scan_single_file_findings(self, path: Path, language: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        if self.pattern_scanner is not None and language == "python":
            findings.extend(self.pattern_scanner.scan(str(path)).findings)
        if self.tree_sitter_scanner is not None and language == "python":
            findings.extend(self.tree_sitter_scanner.scan(str(path)).findings)
        findings.extend(scan_file_with_patterns(str(path)))
        findings.extend(detect_typosquatting_findings(str(path)))
        return deduplicate_findings(findings)

    def supported_languages(self) -> List[str]:
        return ["python", "javascript", "typescript", "multi"]

    def annotate(self, result: ScanResult) -> ScanResult:
        result.annotated_files = annotate_files(result.findings)
        return result
