import json
import re
from typing import List, Dict
import google.generativeai as genai
from modules.base_module import BaseAnalyzer
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion
from .confidence_support import build_decision_metadata

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
        self.last_error: str | None = None

    def analyze(self, 
                scan_result: ScanResult, 
                knowledge: List[Dict], 
                fix_hints: List[Dict],
                evidence_map: Dict[str, Dict] | None = None) -> List[FixSuggestion]:
        """
        L1 스캔 결과를 Gemini API에 전달하여 심층 분석을 수행합니다.
        """
        if not scan_result.findings:
            return []

        self.last_error = None
        evidence_map = evidence_map or {}
        prompt, finding_context = self._build_prompt(scan_result, knowledge, fix_hints, evidence_map)
        
        system_instruction = (
            "You are a security code reviewer. Analyze the given vulnerabilities and for each one determine: "
            "1. Is this a real threat? (Reachability) "
            "2. What is the KISA guideline reference? "
            "3. Provide a safe code fix. "
            "4. Provide decision_status, confidence_score (0-100), and confidence_reason. "
            "Always respond with a JSON array. Never include markdown or code blocks in your response."
        )

        try:
            full_prompt = f"{system_instruction}\n\n{prompt}"
            
            response = self.model.generate_content(full_prompt)
            
            if not response or not response.text:
                raise ValueError("Gemini API returned an empty response.")
                
            response_text = response.text
            raw_data = self._parse_response(response_text)
            
            suggestions = []
            for item in raw_data:
                if item.get("is_real_threat") is True:
                    context = finding_context.get(item.get("finding_id"), {})
                    file_path = item.get("file_path") or context.get("file_path") or scan_result.file_path
                    cwe_id = item.get("cwe_id") or context.get("cwe_id")
                    line_number = item.get("line_number") or context.get("line_number")
                    issue_id = self._build_issue_id(file_path, cwe_id, line_number)
                    decision_status, confidence_score, confidence_reason = build_decision_metadata(
                        cwe_id,
                        context,
                        decision_status=item.get("decision_status"),
                        confidence_score=item.get("confidence_score"),
                        confidence_reason=item.get("confidence_reason"),
                    )
                    
                    suggestion = FixSuggestion(
                        issue_id=issue_id,
                        file_path=file_path,
                        cwe_id=cwe_id,
                        line_number=line_number,
                        reachability=item.get("reachability"),
                        kisa_reference=item.get("kisa_reference") or context.get("primary_reference"),
                        evidence_refs=context.get("evidence_refs", []),
                        evidence_summary=context.get("evidence_summary"),
                        retrieval_backend=context.get("retrieval_backend"),
                        chroma_status=context.get("chroma_status"),
                        chroma_summary=context.get("chroma_summary"),
                        chroma_hits=context.get("chroma_hits", 0),
                        registry_status=context.get("registry_status"),
                        registry_summary=context.get("registry_summary"),
                        osv_status=context.get("osv_status"),
                        osv_summary=context.get("osv_summary"),
                        verification_summary=context.get("verification_summary"),
                        decision_status=decision_status,
                        confidence_score=confidence_score,
                        confidence_reason=confidence_reason,
                        original_code=item.get("original_code", ""),
                        fixed_code=item.get("fixed_code", ""),
                        description=item.get("description", "")
                    )
                    suggestions.append(suggestion)
            
            return suggestions

        except Exception as e:
            self.last_error = str(e)
            print(f"[ERROR] Gemini API Call Error: {e}")
            return []

    def _build_prompt(self, 
                      scan_result: ScanResult, 
                      knowledge: List[Dict], 
                      fix_hints: List[Dict],
                      evidence_map: Dict[str, Dict]) -> tuple[str, Dict[str, Dict]]:
        """
        Gemini에게 보낼 유저 프롬프트를 생성합니다.
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
            issue_id = self._build_issue_id(finding_file_path, f.cwe_id, f.line_number)
            evidence_context = evidence_map.get(issue_id, {})
            cwe_id = f.cwe_id
            k_info = evidence_context.get("knowledge_description") or knowledge_map.get(cwe_id, {}).get("description", "No knowledge available")
            h_info = evidence_context.get("remediation_summary") or (
                fix_map.get(cwe_id, {}).get("safe")
                or fix_map.get(cwe_id, {}).get("fixed_code")
                or "No fix hint available"
            )
            refs = evidence_context.get("evidence_refs", [])
            finding_context[finding_id] = {
                "file_path": finding_file_path,
                "cwe_id": cwe_id,
                "line_number": f.line_number,
                "primary_reference": evidence_context.get("primary_reference"),
                "evidence_refs": refs,
                "evidence_summary": evidence_context.get("evidence_summary"),
                "retrieval_backend": evidence_context.get("retrieval_backend"),
                "chroma_status": evidence_context.get("chroma_status"),
                "chroma_summary": evidence_context.get("chroma_summary"),
                "chroma_hits": evidence_context.get("chroma_hits", 0),
                "registry_status": evidence_context.get("registry_status"),
                "registry_summary": evidence_context.get("registry_summary"),
                "osv_status": evidence_context.get("osv_status"),
                "osv_summary": evidence_context.get("osv_summary"),
                "verification_summary": evidence_context.get("verification_summary"),
            }

            prompt_lines.append(f"---")
            prompt_lines.append(f"Finding ID: {finding_id}")
            prompt_lines.append(f"File Path: {finding_file_path}")
            prompt_lines.append(f"CWE_ID: {cwe_id}")
            prompt_lines.append(f"Line: {f.line_number}")
            prompt_lines.append(f"Severity: {f.severity}")
            prompt_lines.append(f"Code Snippet: {f.code_snippet}")
            prompt_lines.append(f"KISA Knowledge: {k_info}")
            if evidence_context.get("evidence_summary"):
                prompt_lines.append(f"Evidence Summary: {evidence_context['evidence_summary']}")
            if refs:
                prompt_lines.append(f"Evidence References: {', '.join(refs)}")
            if evidence_context.get("retrieval_backend"):
                prompt_lines.append(f"Retrieval Backend: {evidence_context['retrieval_backend']}")
            if evidence_context.get("chroma_status"):
                prompt_lines.append(f"Chroma Status: {evidence_context['chroma_status']}")
            if evidence_context.get("chroma_summary"):
                prompt_lines.append(f"Chroma Summary: {evidence_context['chroma_summary']}")
            if evidence_context.get("verification_summary"):
                prompt_lines.append(f"Verification Summary: {evidence_context['verification_summary']}")
            prompt_lines.append(f"Fix Example: {h_info}")

        prompt_lines.append("\nRespond ONLY with a JSON array of objects with the following structure:")
        prompt_lines.append('[{"finding_id": "string", "file_path": "string", "cwe_id": "string", "line_number": int, "is_real_threat": boolean, "decision_status": "string", "confidence_score": int, "confidence_reason": "string", "reachability": "string", "kisa_reference": "string", "original_code": "string", "fixed_code": "string", "description": "string"}]')

        return "\n".join(prompt_lines), finding_context

    def _parse_response(self, response_text: str) -> List[Dict]:
        """
        LLM 응답 문자열에서 JSON 데이터를 파싱합니다.
        """
        try:
            clean_text = re.sub(r'```(?:json)?\s*(.*?)\s*```', r'\1', response_text, flags=re.DOTALL).strip()
            parsed = json.loads(clean_text)
            if not isinstance(parsed, list):
                raise ValueError("Gemini response must be a JSON array.")
            return parsed
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Gemini JSON parsing failed: {e}") from e

    @staticmethod
    def _build_issue_id(file_path: str | None, cwe_id: str | None, line_number: int | None) -> str:
        normalized_file_path = file_path or "unknown-file"
        normalized_cwe_id = cwe_id or "UNKNOWN"
        normalized_line_number = line_number if line_number is not None else "unknown"
        return f"{normalized_file_path}_{normalized_cwe_id}_{normalized_line_number}"
