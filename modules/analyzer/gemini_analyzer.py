import json
import re
from typing import List, Dict
import google.generativeai as genai
from ..base_module import BaseAnalyzer
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

class GeminiAnalyzer(BaseAnalyzer):
    """
    Google Gemini API를 사용하여 보안 취약점을 분석하고 수정 제안을 생성하는 클래스.
    """

    def __init__(self, api_key: str):
        """
        GeminiAnalyzer 초기화.

        Args:
            api_key (str): Gemini API 키
        """
        self.api_key = api_key
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")

    def analyze(self, 
                scan_result: ScanResult, 
                knowledge: List[Dict], 
                fix_hints: List[Dict]) -> List[FixSuggestion]:
        """
        L1 스캔 결과를 Gemini API에 전달하여 심층 분석을 수행합니다.
        """
        if not scan_result.findings:
            return []

        prompt = self._build_prompt(scan_result, knowledge, fix_hints)
        
        system_instruction = (
            "You are a security code reviewer. Analyze the given vulnerabilities and for each one determine: "
            "1. Is this a real threat? (Reachability) "
            "2. What is the KISA guideline reference? "
            "3. Provide a safe code fix. "
            "Always respond with a JSON array. Never include markdown or code blocks in your response."
        )

        try:
            full_prompt = f"{system_instruction}\n\n{prompt}"
            
            response = self.model.generate_content(full_prompt)
            
            if not response or not response.text:
                return []
                
            response_text = response.text
            raw_data = self._parse_response(response_text)
            
            suggestions = []
            for item in raw_data:
                if item.get("is_real_threat") is True:
                    issue_id = f"{scan_result.file_path}_{item.get('cwe_id')}_{item.get('line_number')}"
                    
                    suggestion = FixSuggestion(
                        issue_id=issue_id,
                        original_code=item.get("original_code", ""),
                        fixed_code=item.get("fixed_code", ""),
                        description=item.get("description", "")
                    )
                    suggestions.append(suggestion)
            
            return suggestions

        except Exception as e:
            print(f"[ERROR] Gemini API Call Error: {e}")
            return []

    def _build_prompt(self, 
                      scan_result: ScanResult, 
                      knowledge: List[Dict], 
                      fix_hints: List[Dict]) -> str:
        """
        Gemini에게 보낼 유저 프롬프트를 생성합니다.
        """
        prompt_lines = [
            f"Analyzing file: {scan_result.file_path}",
            f"Language: {scan_result.language}",
            "\nDetected potential vulnerabilities:",
        ]

        knowledge_map = {item.get("id"): item for item in knowledge}
        fix_map = {item.get("id"): item for item in fix_hints}

        for f in scan_result.findings:
            cwe_id = f.cwe_id
            k_info = knowledge_map.get(cwe_id, {}).get("description", "No knowledge available")
            h_info = fix_map.get(cwe_id, {}).get("fixed_code", "No fix hint available")

            prompt_lines.append(f"---")
            prompt_lines.append(f"CWE_ID: {cwe_id}")
            prompt_lines.append(f"Line: {f.line_number}")
            prompt_lines.append(f"Severity: {f.severity}")
            prompt_lines.append(f"Code Snippet: {f.code_snippet}")
            prompt_lines.append(f"KISA Knowledge: {k_info}")
            prompt_lines.append(f"Fix Example: {h_info}")

        prompt_lines.append("\nRespond ONLY with a JSON array of objects with the following structure:")
        prompt_lines.append('[{"cwe_id": "string", "line_number": int, "is_real_threat": boolean, "reachability": "string", "kisa_reference": "string", "original_code": "string", "fixed_code": "string", "description": "string"}]')

        return "\n".join(prompt_lines)

    def _parse_response(self, response_text: str) -> List[Dict]:
        """
        LLM 응답 문자열에서 JSON 데이터를 파싱합니다.
        """
        try:
            clean_text = re.sub(r'```(?:json)?\s*(.*?)\s*```', r'\1', response_text, flags=re.DOTALL).strip()
            return json.loads(clean_text)
        except (json.JSONDecodeError, Exception) as e:
            print(f"[ERROR] JSON Parsing Error: {e}")
            return []
