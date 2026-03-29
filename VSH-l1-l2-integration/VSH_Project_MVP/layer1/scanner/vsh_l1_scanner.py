from __future__ import annotations

from pathlib import Path
from typing import List

from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from repository.base_repository import BaseReadRepository
from shared.contracts import BaseScanner
from shared.finding_dedup import deduplicate_findings

from layer1.common import (
    annotate_files,
    annotate_reachability,
    detect_typosquatting_findings,
    guess_language,
    normalize_scan_result,
    scan_file_with_patterns,
)
from .mock_semgrep_scanner import MockSemgrepScanner
from .sbom_scanner import SBOMScanner


class VSHL1Scanner(BaseScanner):
    """
    hyeonexcel 수정: donor L1 브랜치의 확장 아이디어를 현재 layer2 구조에 이식하기 위한
    통합형 L1 scanner다. 현재 계약은 ScanResult/Vulnerability를 유지하면서,
    패턴 스캔 + 공급망 스캔 + typo 패키지 탐지를 한 경로로 묶는다.
    """

    def __init__(self, knowledge_repo: BaseReadRepository | None = None):
        self.knowledge_repo = knowledge_repo
        self.pattern_scanner = (
            MockSemgrepScanner(knowledge_repo=knowledge_repo) if knowledge_repo is not None else None
        )
        self.sbom_scanner = SBOMScanner()

        try:
            from .treesitter_scanner import TreeSitterScanner
        except ModuleNotFoundError:
            self.tree_sitter_scanner = None
        else:
            self.tree_sitter_scanner = (
                TreeSitterScanner(knowledge_repo=knowledge_repo) if knowledge_repo is not None else None
            )

    def scan(self, file_path: str) -> ScanResult:
        language = guess_language(file_path)
        if not Path(file_path).exists():
            return ScanResult(file_path=file_path, language=language, findings=[])
        findings: List[Vulnerability] = []

        # hyeonexcel 수정: 기존 layer2 branch의 knowledge 기반 mock scanner를 유지하면서
        # donor L1의 규칙성 패턴 스캔을 같이 태워 현재 구조에서 점진 통합이 가능하게 만든다.
        if self.pattern_scanner is not None and language == "python":
            findings.extend(self.pattern_scanner.scan(file_path).findings)

        if self.tree_sitter_scanner is not None and language == "python":
            findings.extend(self.tree_sitter_scanner.scan(file_path).findings)

        findings.extend(scan_file_with_patterns(file_path))
        findings.extend(detect_typosquatting_findings(file_path))
        findings = annotate_reachability(file_path, deduplicate_findings(findings))

        if language == "python":
            findings.extend(self.sbom_scanner.scan(file_path).findings)

        result = ScanResult(
            file_path=file_path,
            language=language,
            findings=deduplicate_findings(findings),
        )
        return normalize_scan_result(result)

    def supported_languages(self) -> List[str]:
        return ["python", "javascript", "typescript"]

    def annotate(self, result: ScanResult) -> ScanResult:
        """
        hyeonexcel 수정: donor L1 브랜치의 code annotator 개념을 side-effect 없는 preview로 옮겨
        실제 파일 수정 없이 annotated_files만 반환한다.
        """
        result.annotated_files = annotate_files(result.findings)
        return result
