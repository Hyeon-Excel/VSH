from .base_module import BaseScanner, BaseAnalyzer
from .scanner.mock_semgrep_scanner import MockSemgrepScanner as SemgrepScanner
from .scanner.sbom_scanner import SBOMScanner

__all__ = [
    "BaseScanner",
    "BaseAnalyzer",
    "SemgrepScanner",
    "TreeSitterScanner",
    "SBOMScanner",
    "EvidenceRetriever",
    "RegistryVerifier",
    "OsvVerifier",
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
        from layer2.retriever import EvidenceRetriever

        return EvidenceRetriever
    if name == "RegistryVerifier":
        from layer2.verifier import RegistryVerifier

        return RegistryVerifier
    if name == "OsvVerifier":
        from layer2.verifier import OsvVerifier

        return OsvVerifier
    if name == "ClaudeAnalyzer":
        from layer2.analyzer import ClaudeAnalyzer

        return ClaudeAnalyzer
    if name == "GeminiAnalyzer":
        from layer2.analyzer import GeminiAnalyzer

        return GeminiAnalyzer
    if name == "MockAnalyzer":
        from layer2.analyzer import MockAnalyzer

        return MockAnalyzer
    if name == "AnalyzerFactory":
        from layer2.analyzer import AnalyzerFactory

        return AnalyzerFactory
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
