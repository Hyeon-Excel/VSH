from shared.contracts import BaseScanner, BaseAnalyzer
from layer1.scanner import SBOMScanner
from layer1.scanner import SemgrepScanner

__all__ = [
    "BaseScanner",
    "BaseAnalyzer",
    "SemgrepScanner",
    "VSHL1Scanner",
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
    if name == "VSHL1Scanner":
        from layer1.scanner import VSHL1Scanner

        return VSHL1Scanner
    if name == "TreeSitterScanner":
        from layer1.scanner import TreeSitterScanner

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
