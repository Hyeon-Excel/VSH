import json
import re
from typing import List, Dict, Optional
import anthropic
from ..base_module import BaseAnalyzer
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

# RAG 모듈 (선택적 — chromadb 미설치 시 폴백으로 동작)
try:
    from ..rag import KISARetriever
    _RAG_AVAILABLE = True
except ImportError:
    _RAG_AVAILABLE = False


class ClaudeAnalyzer(BaseAnalyzer):
    """
    Anthropic Claude API를 사용하여 보안 취약점을 분석하고 수정 제안을 생성하는 클래스.
    RAG(ChromaDB)가 설정된 경우 KISA/FSI/OWASP/NVD 지식 베이스를 참조합니다.
    """

    def __init__(self, api_key: str, use_rag: bool = True):
        """
        Args:
            api_key:  Anthropic API 키
            use_rag:  True면 ChromaDB RAG 사용, False면 JSON 폴백만 사용
        """
        self.api_key = api_key
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-6"

        self._retriever: Optional["KISARetriever"] = None
        if use_rag and _RAG_AVAILABLE:
            try:
                self._retriever = KISARetriever()
                if self._retriever._ready:
                    print(f"[RAG] ChromaDB 연결 완료 — {self._retriever._col.count()}개 문서")
                else:
                    print("[RAG] .chroma_db 없음 — JSON 폴백 사용")
                    self._retriever = None
            except Exception as e:
                print(f"[RAG] 초기화 실패: {e} — JSON 폴백 사용")
                self._retriever = None

    def analyze(self,
                scan_result: ScanResult,
                knowledge: List[Dict],
                fix_hints: List[Dict]) -> List[FixSuggestion]:
        """
        L1 스캔 결과를 Claude API에 전달하여 심층 분석을 수행합니다.

        RAG 사용 가능 시: ChromaDB에서 KISA/FSI/OWASP/NVD 컨텍스트 검색 후 LLM 전달
        RAG 미사용 시:    기존 knowledge/fix_hints JSON 사용

        Args:
            scan_result: L1 스캔 결과
            knowledge:   보안 규칙 목록 (JSON 폴백용)
            fix_hints:   수정 예시 목록 (JSON 폴백용)

        Returns:
            실제 위협으로 판단된 취약점에 대한 수정 제안 목록
        """
        if not scan_result.findings:
            return []

        prompt = self._build_prompt(scan_result, knowledge, fix_hints)

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=(
                    "당신은 KISA 시큐어코딩 가이드와 금융보안원 보안 기준에 정통한 보안 전문가입니다. "
                    "L1 정적 분석이 탐지한 취약점을 검토하고 판단 결과를 JSON 배열로만 응답하세요. "
                    "마크다운 코드 블록을 절대 포함하지 마세요."
                ),
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text
            raw_data = self._parse_response(response_text)

            suggestions = []
            for item in raw_data:
                if item.get("is_real_threat") is True:
                    issue_id = (
                        f"{scan_result.file_path}"
                        f"_{item.get('cwe_id')}"
                        f"_{item.get('line_number')}"
                    )
                    # fss_ref / owasp_ref 빈 문자열 → None (스키마 규칙)
                    fss_ref = item.get("fss_ref") or None
                    owasp_ref = item.get("owasp_ref") or None
                    suggestions.append(FixSuggestion(
                        issue_id=issue_id,
                        original_code=item.get("original_code", ""),
                        fixed_code=item.get("fixed_code", ""),
                        description=item.get("description", ""),
                        kisa_ref=item.get("kisa_reference", ""),
                        fss_ref=fss_ref,
                        owasp_ref=owasp_ref,
                        reachability=bool(item.get("reachability", False)),
                        cve_id=item.get("cve_id") or None,
                        cvss_score=float(item.get("cvss_score", 0.0)),
                    ))
            return suggestions

        except Exception as e:
            print(f"[ERROR] Claude API 호출 오류: {e}")
            return []

    # ------------------------------------------------------------------ #
    # 프롬프트 생성
    # ------------------------------------------------------------------ #

    def _build_prompt(self,
                      scan_result: ScanResult,
                      knowledge: List[Dict],
                      fix_hints: List[Dict]) -> str:
        lines = [
            f"분석 파일: {scan_result.file_path}",
            f"언어: {scan_result.language}",
            "\n탐지된 잠재 취약점:",
        ]

        knowledge_map = {item.get("id"): item for item in knowledge}
        fix_map = {item.get("id"): item for item in fix_hints}

        for f in scan_result.findings:
            cwe_id = f.cwe_id
            lines.append("---")
            lines.append(f"CWE_ID: {cwe_id}")
            lines.append(f"Line: {f.line_number}")
            lines.append(f"Severity: {f.severity}")
            lines.append(f"Code Snippet: {f.code_snippet}")

            # RAG 컨텍스트 우선, 없으면 JSON 폴백
            if self._retriever:
                rag_ctx = self._retriever.get_context_string(cwe_id, f.code_snippet)
                lines.append(f"보안 가이드라인 (RAG):\n{rag_ctx}")
            else:
                k_info = knowledge_map.get(cwe_id, {}).get("description", "정보 없음")
                h_info = fix_map.get(cwe_id, {}).get("fixed_code", "수정 예시 없음")
                lines.append(f"KISA Knowledge: {k_info}")
                lines.append(f"Fix Example: {h_info}")

        lines.append(
            "\n아래 JSON 배열 형식으로만 응답하세요:\n"
            '[{"cwe_id": "string", "line_number": int, "is_real_threat": boolean, '
            '"reachability": boolean, "kisa_reference": "string", '
            '"fss_ref": "string or null", "owasp_ref": "string or null", '
            '"cve_id": "string or null", "cvss_score": float, '
            '"original_code": "string", "fixed_code": "string", "description": "string"}]'
        )
        return "\n".join(lines)

    def _parse_response(self, response_text: str) -> List[Dict]:
        try:
            clean = re.sub(
                r'```(?:json)?\s*(.*?)\s*```', r'\1',
                response_text, flags=re.DOTALL
            ).strip()
            return json.loads(clean)
        except Exception as e:
            print(f"[ERROR] JSON 파싱 오류: {e}")
            return []
