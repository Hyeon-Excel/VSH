from pathlib import Path
from typing import Dict, List, Tuple

from layer2.common.requirement_parser import parse_requirement_line
from shared.contracts import BaseAnalyzer
from models.fix_suggestion import FixSuggestion
from models.scan_result import ScanResult
from .confidence_support import build_decision_metadata

try:
    from config import VULNERABLE_PACKAGES
except ImportError:
    VULNERABLE_PACKAGES = {}


class MockAnalyzer(BaseAnalyzer):
    """
    외부 LLM 없이도 deterministic한 수정 제안을 생성하는 테스트용 Analyzer.
    """

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.last_error: str | None = None

    def analyze(
        self,
        scan_result: ScanResult,
        knowledge: List[Dict],
        fix_hints: List[Dict],
        evidence_map: Dict[str, Dict] | None = None,
    ) -> List[FixSuggestion]:
        self.last_error = None
        if not scan_result.findings:
            return []

        evidence_map = evidence_map or {}
        knowledge_map = {item.get("id"): item for item in knowledge}
        fix_map = {item.get("id"): item for item in fix_hints}
        suggestions: List[FixSuggestion] = []

        for finding in scan_result.findings:
            file_path = finding.file_path or scan_result.file_path
            issue_id = self._build_issue_id(file_path, finding.cwe_id, finding.line_number)
            evidence_context = evidence_map.get(issue_id, {})
            fix_hint = fix_map.get(finding.cwe_id, {})
            knowledge_entry = knowledge_map.get(finding.cwe_id, {})
            fixed_code, description, reference = self._resolve_fix(
                finding.cwe_id,
                finding.code_snippet,
                fix_hint,
                knowledge_entry,
            )
            primary_reference = (
                evidence_context.get("primary_reference")
                or reference
                or knowledge_entry.get("reference")
            )
            evidence_refs = evidence_context.get("evidence_refs") or []
            if primary_reference and primary_reference not in evidence_refs:
                evidence_refs = [*evidence_refs, primary_reference]
            evidence_summary = evidence_context.get("evidence_summary")
            if not evidence_summary:
                evidence_summary = self._build_evidence_summary(
                    finding.cwe_id,
                    file_path,
                    knowledge_entry,
                )
            verification_summary = evidence_context.get("verification_summary")
            description_text = evidence_context.get("remediation_summary") or description
            if verification_summary and verification_summary not in description_text:
                description_text = f"{description_text} 검증 결과: {verification_summary}"
            decision_status, confidence_score, confidence_reason = build_decision_metadata(
                finding.cwe_id,
                evidence_context,
            )

            suggestions.append(
                FixSuggestion(
                    issue_id=issue_id,
                    file_path=file_path,
                    cwe_id=finding.cwe_id,
                    line_number=finding.line_number,
                    reachability=self._build_reachability(
                        finding.cwe_id,
                        file_path,
                        finding.reachability_status,
                        verification_summary=verification_summary,
                    ),
                    kisa_reference=primary_reference,
                    evidence_refs=evidence_refs,
                    evidence_summary=evidence_summary,
                    retrieval_backend=evidence_context.get("retrieval_backend"),
                    chroma_status=evidence_context.get("chroma_status"),
                    chroma_summary=evidence_context.get("chroma_summary"),
                    chroma_hits=evidence_context.get("chroma_hits", 0),
                    registry_status=evidence_context.get("registry_status"),
                    registry_summary=evidence_context.get("registry_summary"),
                    osv_status=evidence_context.get("osv_status"),
                    osv_summary=evidence_context.get("osv_summary"),
                    verification_summary=verification_summary,
                    decision_status=decision_status,
                    confidence_score=confidence_score,
                    confidence_reason=confidence_reason,
                    original_code=finding.code_snippet,
                    fixed_code=evidence_context.get("recommended_fix") or fixed_code,
                    description=description_text,
                )
            )

        return suggestions

    def _resolve_fix(
        self,
        cwe_id: str,
        code_snippet: str,
        fix_hint: Dict,
        knowledge_entry: Dict,
    ) -> Tuple[str, str, str | None]:
        if cwe_id == "CWE-829":
            package_name, safe_requirement, reference = self._build_dependency_fix(code_snippet)
            description = (
                f"{package_name} 의존성 버전을 안전 기준 이상으로 상향합니다."
                if package_name
                else "취약한 의존성을 안전한 버전 범위로 상향합니다."
            )
            return safe_requirement, description, reference

        fixed_code = fix_hint.get("safe") or fix_hint.get("fixed_code") or code_snippet
        description = (
            fix_hint.get("description")
            or knowledge_entry.get("description")
            or "정적 규칙 기반 analyzer가 수정 방향을 제안했습니다."
        )
        reference = knowledge_entry.get("reference")
        return fixed_code, description, reference

    def _build_dependency_fix(self, requirement_line: str) -> Tuple[str, str, str | None]:
        package_name, _ = parse_requirement_line(requirement_line)
        if not package_name:
            return "", "", "Dependency policy"

        vuln_info = VULNERABLE_PACKAGES.get(package_name, {})
        safe_version = vuln_info.get("vulnerable_below")
        if safe_version:
            fixed_requirement = f"{package_name}>={safe_version}"
        else:
            fixed_requirement = package_name

        reference_parts = ["Dependency policy"]
        if safe_version:
            reference_parts.append(f"safe floor {safe_version}")
        if vuln_info.get("cve"):
            reference_parts.append(vuln_info["cve"])

        return package_name, fixed_requirement, " | ".join(reference_parts)

    @staticmethod
    def _build_reachability(
        cwe_id: str,
        file_path: str,
        reachability_status: str | None = None,
        verification_summary: str | None = None,
    ) -> str:
        file_name = Path(file_path).name
        if cwe_id == "CWE-829":
            base = f"{file_name}에 취약 버전 의존성이 직접 선언되어 있어 즉시 수정 대상입니다."
        else:
            base = f"{file_name}에서 탐지 규칙과 일치하는 위험 코드가 직접 발견되었습니다."
        if reachability_status:
            base = f"{base} Reachability={reachability_status}."
        if verification_summary:
            return f"{base} {verification_summary}"
        return base

    @staticmethod
    def _build_evidence_summary(cwe_id: str, file_path: str, knowledge_entry: Dict) -> str:
        file_name = Path(file_path).name
        description = knowledge_entry.get("description")
        if description:
            return f"{file_name}에서 `{cwe_id}` 관련 위험 코드가 탐지되었습니다. {description}."
        return f"{file_name}에서 `{cwe_id}` 관련 위험 코드가 탐지되었습니다."

    @staticmethod
    def _build_issue_id(file_path: str, cwe_id: str, line_number: int) -> str:
        return f"{file_path}_{cwe_id}_{line_number}"
