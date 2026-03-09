import json
import re
from typing import List, Dict
import anthropic
from ..base_module import BaseAnalyzer
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

class ClaudeAnalyzer(BaseAnalyzer):
    """
    Anthropic Claude API를 사용하여 보안 취약점을 분석하고 수정 제안을 생성하는 클래스.
    """

    def __init__(self, api_key: str):
        """
        ClaudeAnalyzer 초기화.

        Args:
            api_key (str): Anthropic API 키
        """
        self.api_key = api_key
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-3-5-sonnet-20241022"
        self.last_error: str | None = None

    def analyze(self, 
                scan_result: ScanResult, 
                knowledge: List[Dict], 
                fix_hints: List[Dict]) -> List[FixSuggestion]:
        """
        L1 스캔 결과를 Claude API에 전달하여 심층 분석을 수행합니다.

        Args:
            scan_result (ScanResult): L1 스캔 결과
            knowledge (List[Dict]): 보안 규칙 목록
            fix_hints (List[Dict]): 수정 예시 목록

        Returns:
            List[FixSuggestion]: 실제 위협으로 판단된 취약점에 대한 수정 제안 목록
        """
        if not scan_result.findings:
            return []

        self.last_error = None
        prompt, finding_context = self._build_prompt(scan_result, knowledge, fix_hints)
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system="You are a security code reviewer. Analyze the given vulnerabilities and for each one determine: 1. Is this a real threat? (Reachability) 2. What is the KISA guideline reference? 3. Provide a safe code fix. Always respond with a JSON array. Never include markdown or code blocks in your response.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            if not message.content or not message.content[0].text:
                raise ValueError("Claude API returned an empty response.")
            
            response_text = message.content[0].text
            raw_data = self._parse_response(response_text)
            
            suggestions = []
            for item in raw_data:
                if item.get("is_real_threat") is True:
                    context = finding_context.get(item.get("finding_id"), {})
                    file_path = item.get("file_path") or context.get("file_path") or scan_result.file_path
                    cwe_id = item.get("cwe_id") or context.get("cwe_id")
                    line_number = item.get("line_number") or context.get("line_number")
                    issue_id = self._build_issue_id(file_path, cwe_id, line_number)
                    
                    suggestion = FixSuggestion(
                        issue_id=issue_id,
                        file_path=file_path,
                        cwe_id=cwe_id,
                        line_number=line_number,
                        reachability=item.get("reachability"),
                        kisa_reference=item.get("kisa_reference"),
                        original_code=item.get("original_code", ""),
                        fixed_code=item.get("fixed_code", ""),
                        description=item.get("description", "")
                    )
                    suggestions.append(suggestion)
            
            return suggestions

        except Exception as e:
            self.last_error = str(e)
            print(f"[ERROR] Claude API Call Error: {e}")
            return []

    def _build_prompt(self, 
                      scan_result: ScanResult, 
                      knowledge: List[Dict], 
                      fix_hints: List[Dict]) -> tuple[str, Dict[str, Dict]]:
        """
        Claude에게 보낼 유저 프롬프트를 생성합니다.
        """
        prompt_lines = [
            f"Analyzing file: {scan_result.file_path}",
            f"Language: {scan_result.language}",
            "\nDetected potential vulnerabilities:",
        ]
        finding_context: Dict[str, Dict] = {}

        knowledge_map = {item.get("id"): item for item in knowledge}
        fix_map = {item.get("id"): item for item in fix_hints}

        for index, f in enumerate(scan_result.findings, start=1):
            finding_id = f"finding-{index}"
            finding_file_path = f.file_path or scan_result.file_path
            cwe_id = f.cwe_id
            k_info = knowledge_map.get(cwe_id, {}).get("description", "No knowledge available")
            h_info = (
                fix_map.get(cwe_id, {}).get("safe")
                or fix_map.get(cwe_id, {}).get("fixed_code")
                or "No fix hint available"
            )
            finding_context[finding_id] = {
                "file_path": finding_file_path,
                "cwe_id": cwe_id,
                "line_number": f.line_number,
            }

            prompt_lines.append(f"---")
            prompt_lines.append(f"Finding ID: {finding_id}")
            prompt_lines.append(f"File Path: {finding_file_path}")
            prompt_lines.append(f"CWE_ID: {cwe_id}")
            prompt_lines.append(f"Line: {f.line_number}")
            prompt_lines.append(f"Severity: {f.severity}")
            prompt_lines.append(f"Code Snippet: {f.code_snippet}")
            prompt_lines.append(f"KISA Knowledge: {k_info}")
            prompt_lines.append(f"Fix Example: {h_info}")

        prompt_lines.append("\nRespond ONLY with a JSON array of objects with the following structure:")
        prompt_lines.append('[{"finding_id": "string", "file_path": "string", "cwe_id": "string", "line_number": int, "is_real_threat": boolean, "reachability": "string", "kisa_reference": "string", "original_code": "string", "fixed_code": "string", "description": "string"}]')

        return "\n".join(prompt_lines), finding_context

    def _parse_response(self, response_text: str) -> List[Dict]:
        """
        LLM 응답 문자열에서 JSON 데이터를 파싱합니다.
        """
        try:
            clean_text = re.sub(r'```(?:json)?\s*(.*?)\s*```', r'\1', response_text, flags=re.DOTALL).strip()
            parsed = json.loads(clean_text)
            if not isinstance(parsed, list):
                raise ValueError("Claude response must be a JSON array.")
            return parsed
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Claude JSON parsing failed: {e}") from e

    @staticmethod
    def _build_issue_id(file_path: str | None, cwe_id: str | None, line_number: int | None) -> str:
        normalized_file_path = file_path or "unknown-file"
        normalized_cwe_id = cwe_id or "UNKNOWN"
        normalized_line_number = line_number if line_number is not None else "unknown"
        return f"{normalized_file_path}_{normalized_cwe_id}_{normalized_line_number}"
