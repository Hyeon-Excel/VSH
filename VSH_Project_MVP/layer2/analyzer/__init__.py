from .analyzer_factory import AnalyzerFactory

__all__ = [
    "BaseLlmAnalyzer",
    "ClaudeAnalyzer",
    "GeminiAnalyzer",
    "MockAnalyzer",
    "AnalyzerFactory",
]


def __getattr__(name: str):
    if name == "BaseLlmAnalyzer":
        from .base_llm_analyzer import BaseLlmAnalyzer

        return BaseLlmAnalyzer
    if name == "ClaudeAnalyzer":
        from .claude_analyzer import ClaudeAnalyzer

        return ClaudeAnalyzer
    if name == "GeminiAnalyzer":
        from .gemini_analyzer import GeminiAnalyzer

        return GeminiAnalyzer
    if name == "MockAnalyzer":
        from .mock_analyzer import MockAnalyzer

        return MockAnalyzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
