import os
import re
import anthropic
from l3.llm.base import LLMAdapter

class ClaudeAdapter(LLMAdapter):
    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = "claude-sonnet-4-5"

    async def classify_cwe(self, rule_id: str, issue_message: str) -> str:
        if not self.api_key:
            return "CWE-UNKNOWN"
            
        try:
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            response = await client.messages.create(
                model=self.model,
                max_tokens=50,
                system="당신은 SonarQube 규칙 ID를 CWE ID로 분류하는 보안 분류 도구입니다. 반드시 'CWE-숫자' 형태로만 응답하세요. 다른 텍스트, 설명, 코드는 절대 포함하지 마세요.",
                messages=[
                    {"role": "user", "content": f"rule_id: {rule_id}\nissue_message: {issue_message}"}
                ]
            )
            return self._parse_cwe(response.content[0].text)
        except Exception:
            return "CWE-UNKNOWN"

    def _parse_cwe(self, raw: str) -> str:
        match = re.search(r"CWE-\d+", raw)
        if match:
            return match.group()
        return "CWE-UNKNOWN"