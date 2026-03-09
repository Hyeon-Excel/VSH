from .base_module import BaseScanner, BaseAnalyzer
from .scanner.mock_semgrep_scanner import MockSemgrepScanner as SemgrepScanner
from .scanner.sbom_scanner import SBOMScanner
from .analyzer.analyzer_factory import AnalyzerFactory

__all__ = [
    "BaseScanner",
    "BaseAnalyzer",
    "SemgrepScanner",
    "TreeSitterScanner",
    "SBOMScanner",
    "EvidenceRetriever",
    "ClaudeAnalyzer",
    "GeminiAnalyzer",
    "MockAnalyzer",
    "AnalyzerFactory",
]


def __getattr__(name: str):
    if name == "TreeSitterScanner":
        from .scanner import TreeSitterScanner

        return TreeSitterScanner
    if name == "EvidenceRetriever":
        from .retriever import EvidenceRetriever

        return EvidenceRetriever
    if name == "ClaudeAnalyzer":
        from .analyzer import ClaudeAnalyzer

        return ClaudeAnalyzer
    if name == "GeminiAnalyzer":
        from .analyzer import GeminiAnalyzer

        return GeminiAnalyzer
    if name == "MockAnalyzer":
        from .analyzer import MockAnalyzer

        return MockAnalyzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
