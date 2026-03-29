import os
import re
import asyncio
from google.genai import types
import google.genai as genai
from l3.llm.base import LLMAdapter

class GeminiAdapter(LLMAdapter):
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model_name = "gemini-2.0-flash"
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            self.client = None

    async def classify_cwe(self, rule_id: str, issue_message: str) -> str:
        if not self.api_key:
            return "CWE-UNKNOWN"
            
        try:
            config = types.GenerateContentConfig(
                system_instruction=(
                    "당신은 SonarQube 규칙 ID를 CWE ID로 분류하는"
                    " 보안 분류 도구입니다."
                    " 반드시 'CWE-숫자' 형태로만 응답하세요."
                    " 다른 텍스트, 설명, 코드는 절대 포함하지 마세요."
                )
            )
            prompt = f"rule_id: {rule_id}\nissue_message: {issue_message}"
            
            response = await asyncio.to_thread(
                lambda: self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config
                )
            )
            
            return self._parse_cwe(response.text)
        except Exception:
            return "CWE-UNKNOWN"

    def _parse_cwe(self, raw: str) -> str:
        match = re.search(r"CWE-\d+", raw)
        if match:
            return match.group()
        return "CWE-UNKNOWN"