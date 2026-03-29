import anthropic
from .base_llm_analyzer import BaseLlmAnalyzer

class ClaudeAnalyzer(BaseLlmAnalyzer):
    """
    Anthropic Claude API를 사용하여 보안 취약점을 분석하고 수정 제안을 생성하는 클래스.
    """

    def __init__(self, api_key: str):
        """
        ClaudeAnalyzer 초기화.

        Args:
            api_key (str): Anthropic API 키
        """
        super().__init__(api_key)
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-3-5-sonnet-20241022"
        self.provider_label = "Claude"

    def _generate_response_text(self, prompt: str) -> str:
        message = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self.system_instruction,
            messages=[
                {"role": "user", "content": prompt}
            ],
        )
        if not message.content or not message.content[0].text:
            raise ValueError("Claude API returned an empty response.")
        return message.content[0].text
