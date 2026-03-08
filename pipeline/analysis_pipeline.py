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
    
    L1 Extended Features:
    - run_l1(scan_only=True): Fast detection only
    - run_l1(scan_only=False, annotate=True): Detection + code annotation
    """

    scanner: BaseScanner
    analyzer: object | None = None
    reporter: object | None = None

    def run_l1(self, scan_only: bool = True, annotate: bool = False) -> ScanResult:
        """
        Run L1 scanner with optional features.
        
        Args:
            scan_only: If True, return scan results only (no annotations)
            annotate: If True, inject annotations into source code (requires scan_only=False)
        
        Returns:
            ScanResult with normalized VulnRecord/PackageRecord and optional annotations
        """
        result = self.scanner.scan()
        
        # Handle code annotation (only if scanner supports it)
        if not scan_only and annotate:
            if hasattr(self.scanner, "annotate"):
                result = self.scanner.annotate(result)
        
        return result

    def run(self) -> ScanResult:
        """Run full pipeline: L1 -> L2 -> L3."""
        result = self.run_l1(scan_only=False, annotate=False)

        if self.analyzer and hasattr(self.analyzer, "analyze"):
            self.analyzer.analyze(result)

        if self.reporter and hasattr(self.reporter, "generate"):
            self.reporter.generate(result)

        return result
