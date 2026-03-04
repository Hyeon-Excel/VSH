from __future__ import annotations

from dataclasses import dataclass

from modules.scanner.base_scanner import BaseScanner
from vsh.core.models import ScanResult


@dataclass
class AnalysisPipeline:
    """Composable analysis pipeline with explicit layer separation.

    L1: scanner (required)
    L2: analyzer (optional, external)
    L3: reporter (optional, external)
    """

    scanner: BaseScanner
    analyzer: object | None = None
    reporter: object | None = None

    def run_l1(self) -> ScanResult:
        return self.scanner.scan()

    def run(self) -> ScanResult:
        result = self.run_l1()

        if self.analyzer and hasattr(self.analyzer, "analyze"):
            self.analyzer.analyze(result)

        if self.reporter and hasattr(self.reporter, "generate"):
            self.reporter.generate(result)

        return result
