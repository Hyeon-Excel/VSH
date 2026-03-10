__all__ = [
    "AnalyzerFactory",
    "ClaudeAnalyzer",
    "GeminiAnalyzer",
    "MockAnalyzer",
    "EvidenceRetriever",
    "RegistryVerifier",
    "OsvVerifier",
]


def __getattr__(name: str):
    if name == "AnalyzerFactory":
        from .analyzer import AnalyzerFactory

        return AnalyzerFactory
    if name == "ClaudeAnalyzer":
        from .analyzer import ClaudeAnalyzer

        return ClaudeAnalyzer
    if name == "GeminiAnalyzer":
        from .analyzer import GeminiAnalyzer

        return GeminiAnalyzer
    if name == "MockAnalyzer":
        from .analyzer import MockAnalyzer

        return MockAnalyzer
    if name == "EvidenceRetriever":
        from .retriever import EvidenceRetriever

        return EvidenceRetriever
    if name == "RegistryVerifier":
        from .verifier import RegistryVerifier

        return RegistryVerifier
    if name == "OsvVerifier":
        from .verifier import OsvVerifier

        return OsvVerifier
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
