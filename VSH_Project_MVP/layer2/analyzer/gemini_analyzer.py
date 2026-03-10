from google import genai
from google.genai import types

from .base_llm_analyzer import BaseLlmAnalyzer


class GeminiAnalyzer(BaseLlmAnalyzer):
    """
    Google Gemini API를 사용하여 보안 취약점을 분석하고 수정 제안을 생성하는 클래스.
    """

    def __init__(self, api_key: str):
        """
        GeminiAnalyzer 초기화.

        Args:
            api_key (str): Gemini API 키
        """
        super().__init__(api_key)
        # hyeonexcel 수정: legacy google.generativeai 지원 종료에 대응해
        # Client 기반 google.genai SDK로 전환하고 L2 analyzer 인터페이스는 그대로 유지한다.
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-2.5-flash"
        self.provider_label = "Gemini"

    def _generate_response_text(self, prompt: str) -> str:
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=self.system_instruction,
                response_mime_type="application/json",
            ),
        )
        if not response or not response.text:
            raise ValueError("Gemini API returned an empty response.")
        return response.text
