from shared.contracts import BaseAnalyzer

class AnalyzerFactory:
    """
    설정에 따라 적절한 Analyzer 인스턴스를 생성하는 팩토리 클래스.
    """

    @staticmethod
    def create(provider: str, api_key: str) -> BaseAnalyzer:
        """
        제공된 provider에 맞는 Analyzer를 생성합니다.

        Args:
            provider (str): "claude" 또는 "gemini"
            api_key (str): 해당 provider의 API 키

        Returns:
            BaseAnalyzer: 생성된 Analyzer 인스턴스

        Raises:
            ValueError: 지원하지 않는 provider인 경우
        """
        provider = provider.lower()
        if provider == "claude":
            from .claude_analyzer import ClaudeAnalyzer
            return ClaudeAnalyzer(api_key=api_key)
        elif provider == "gemini":
            from .gemini_analyzer import GeminiAnalyzer
            return GeminiAnalyzer(api_key=api_key)
        elif provider == "mock":
            from .mock_analyzer import MockAnalyzer
            return MockAnalyzer(api_key=api_key)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}. Use 'claude', 'gemini', or 'mock'.")
