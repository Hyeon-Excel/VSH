from pathlib import Path
from typing import Dict, List, Optional

from .chroma_retriever import ChromaRetriever
from layer2.common.requirement_parser import parse_requirement_line
from models.scan_result import ScanResult

try:
    from config import VULNERABLE_PACKAGES
except ImportError:
    VULNERABLE_PACKAGES = {}


class EvidenceRetriever:
    """
    finding별로 관련 근거와 수정 맥락을 정리하는 L2 retrieval 컴포넌트.
    """

    def __init__(self, chroma_retriever: Optional[ChromaRetriever] = None):
        self.chroma_retriever = chroma_retriever or ChromaRetriever()

    def runtime_status(self) -> Dict[str, str]:
        status = getattr(self.chroma_retriever, "status", None)
        summary = getattr(self.chroma_retriever, "status_summary", None)

        if status is None:
            status = "READY" if getattr(self.chroma_retriever, "ready", False) else "DISABLED"
        if summary is None:
            summary = "Chroma RAG 활성화 상태를 확인하지 못했습니다."

        return {
            "status": status,
            "summary": summary,
        }

    def retrieve(
        self,
        scan_result: ScanResult,
        knowledge: List[Dict],
        fix_hints: List[Dict],
    ) -> Dict[str, Dict]:
        knowledge_map = {item.get("id"): item for item in knowledge}
        fix_map = {item.get("id"): item for item in fix_hints}
        evidence_map: Dict[str, Dict] = {}
        chroma_runtime = self.runtime_status()

        for finding in scan_result.findings:
            file_path = finding.file_path or scan_result.file_path
            issue_id = self._build_issue_id(file_path, finding.cwe_id, finding.line_number)
            knowledge_entry = knowledge_map.get(finding.cwe_id, {})
            fix_entry = fix_map.get(finding.cwe_id, {})
            chroma_docs = self._query_chroma(finding.cwe_id, finding.code_snippet)
            retrieval_backend = self._build_retrieval_backend(
                chroma_docs=chroma_docs,
                knowledge_entry=knowledge_entry,
                fix_entry=fix_entry,
            )

            evidence_map[issue_id] = {
                "issue_id": issue_id,
                "file_path": file_path,
                "cwe_id": finding.cwe_id,
                "line_number": finding.line_number,
                "retrieval_backend": retrieval_backend,
                "chroma_status": chroma_runtime["status"],
                "chroma_summary": chroma_runtime["summary"],
                "chroma_hits": len(chroma_docs),
                "knowledge_description": self._build_knowledge_description(
                    knowledge_entry,
                    chroma_docs,
                ),
                "remediation_summary": self._build_remediation_summary(
                    finding.cwe_id,
                    fix_entry,
                    knowledge_entry,
                    finding.code_snippet,
                ),
                "evidence_summary": self._build_evidence_summary(
                    file_path,
                    finding.cwe_id,
                    finding.code_snippet,
                    knowledge_entry,
                    chroma_docs,
                ),
                "evidence_refs": self._build_evidence_refs(
                    finding.cwe_id,
                    knowledge_entry,
                    finding.code_snippet,
                    chroma_docs,
                ),
                "primary_reference": self._build_primary_reference(
                    finding.cwe_id,
                    knowledge_entry,
                    finding.code_snippet,
                    chroma_docs,
                ),
                "recommended_fix": (
                    fix_entry.get("safe")
                    or fix_entry.get("fixed_code")
                    or self._build_dependency_fix(finding.code_snippet)
                ),
            }

        return evidence_map

    def _query_chroma(self, cwe_id: str, code_snippet: str) -> List[Dict]:
        if not self.chroma_retriever.ready:
            return []
        if hasattr(self.chroma_retriever, "query_related"):
            return self.chroma_retriever.query_related(cwe_id, code_snippet, n_results=4)
        return self.chroma_retriever.query(cwe_id, code_snippet, n_results=4)

    @staticmethod
    def _build_knowledge_description(knowledge_entry: Dict, chroma_docs: List[Dict]) -> str | None:
        if knowledge_entry.get("description"):
            return knowledge_entry["description"]

        top_doc = chroma_docs[0] if chroma_docs else {}
        text = (top_doc.get("text") or "").strip()
        return text[:300] if text else None

    def _build_remediation_summary(
        self,
        cwe_id: str,
        fix_entry: Dict,
        knowledge_entry: Dict,
        code_snippet: str,
    ) -> str:
        if cwe_id == "CWE-829":
            dependency_fix = self._build_dependency_fix(code_snippet)
            if dependency_fix:
                return f"취약 버전 의존성을 `{dependency_fix}` 기준으로 상향합니다."
            return "취약 의존성을 안전한 버전 범위로 상향합니다."

        return (
            fix_entry.get("description")
            or knowledge_entry.get("description")
            or "관련 보안 규칙에 맞춰 안전한 구현으로 변경합니다."
        )

    def _build_evidence_summary(
        self,
        file_path: str,
        cwe_id: str,
        code_snippet: str,
        knowledge_entry: Dict,
        chroma_docs: List[Dict],
    ) -> str:
        file_name = Path(file_path).name
        if cwe_id == "CWE-829":
            package_name, package_version = self._parse_requirement(code_snippet)
            vuln_info = VULNERABLE_PACKAGES.get(package_name or "", {})
            safe_floor = vuln_info.get("vulnerable_below")
            if package_name and package_version and safe_floor:
                return (
                    f"{file_name}에 선언된 `{package_name}=={package_version}`가 "
                    f"안전 기준 `{safe_floor}` 미만으로 탐지되었습니다."
                )
            return f"{file_name}에 취약 의존성 선언이 탐지되었습니다."

        description = knowledge_entry.get("description")
        if description:
            return f"{file_name}에서 `{cwe_id}` 패턴과 일치하는 코드가 발견되었습니다. {description}."

        chroma_context = self._build_chroma_summary(chroma_docs)
        if chroma_context:
            return f"{file_name}에서 `{cwe_id}` 관련 위험 코드가 탐지되었습니다. {chroma_context}"
        return f"{file_name}에서 `{cwe_id}`와 관련된 위험 코드가 탐지되었습니다."

    def _build_evidence_refs(
        self,
        cwe_id: str,
        knowledge_entry: Dict,
        code_snippet: str,
        chroma_docs: List[Dict],
    ) -> List[str]:
        refs: List[str] = []
        refs.append(cwe_id)

        if knowledge_entry.get("reference"):
            refs.append(knowledge_entry["reference"])

        refs.extend(self._build_chroma_refs(chroma_docs))

        if cwe_id == "CWE-829":
            package_name, _ = self._parse_requirement(code_snippet)
            vuln_info = VULNERABLE_PACKAGES.get(package_name or "", {})
            if package_name:
                refs.append(f"Package: {package_name}")
            if vuln_info.get("vulnerable_below"):
                refs.append(f"Safe floor: {vuln_info['vulnerable_below']}")
            if vuln_info.get("cve"):
                refs.append(vuln_info["cve"])

        return refs

    def _build_primary_reference(
        self,
        cwe_id: str,
        knowledge_entry: Dict,
        code_snippet: str,
        chroma_docs: List[Dict],
    ) -> str | None:
        if knowledge_entry.get("reference"):
            return knowledge_entry["reference"]

        if cwe_id == "CWE-829":
            package_name, _ = self._parse_requirement(code_snippet)
            vuln_info = VULNERABLE_PACKAGES.get(package_name or "", {})
            if vuln_info.get("cve"):
                return vuln_info["cve"]

        # hyeonexcel 수정: 공급망 finding은 내부 deterministic CVE 기준을 먼저 유지하고
        # 그 외 코드 취약점은 Chroma 상위 문서를 primary reference로 사용한다.
        chroma_reference = self._build_primary_chroma_reference(chroma_docs)
        if chroma_reference:
            return chroma_reference

        return None

    def _build_dependency_fix(self, requirement_line: str) -> str | None:
        package_name, _ = self._parse_requirement(requirement_line)
        vuln_info = VULNERABLE_PACKAGES.get(package_name or "", {})
        safe_floor = vuln_info.get("vulnerable_below")
        if package_name and safe_floor:
            return f"{package_name}>={safe_floor}"
        return None

    @staticmethod
    def _build_retrieval_backend(
        chroma_docs: List[Dict],
        knowledge_entry: Dict,
        fix_entry: Dict,
    ) -> str:
        has_static_context = bool(knowledge_entry or fix_entry)
        has_chroma_context = bool(chroma_docs)

        if has_static_context and has_chroma_context:
            return "hybrid"
        if has_chroma_context:
            return "chroma_only"
        if has_static_context:
            return "static_only"
        return "empty"

    @staticmethod
    def _build_chroma_summary(chroma_docs: List[Dict]) -> str | None:
        if not chroma_docs:
            return None

        parts: List[str] = []
        for doc in chroma_docs[:2]:
            source = doc.get("source") or "RAG"
            title = (
                doc.get("kisa_article")
                or doc.get("title")
                or doc.get("source_id")
                or doc.get("cve_id")
            )
            text = (doc.get("text") or "").strip()
            if not text:
                continue
            prefix = f"[{source}]"
            if title:
                prefix = f"{prefix} {title}"
            parts.append(f"{prefix} {text[:140]}")

        if not parts:
            return None
        return " | ".join(parts)

    @staticmethod
    def _build_chroma_refs(chroma_docs: List[Dict]) -> List[str]:
        refs: List[str] = []
        for doc in chroma_docs:
            source = doc.get("source") or "RAG"
            identifier = (
                doc.get("kisa_article")
                or doc.get("source_id")
                or doc.get("owasp_id")
                or doc.get("cve_id")
                or doc.get("title")
            )
            if identifier:
                refs.append(f"{source}: {identifier}")
            cvss_score = doc.get("cvss_score")
            if cvss_score:
                refs.append(f"CVSS: {cvss_score}")
        return list(dict.fromkeys(refs))

    @staticmethod
    def _build_primary_chroma_reference(chroma_docs: List[Dict]) -> str | None:
        refs = EvidenceRetriever._build_chroma_refs(chroma_docs)
        return refs[0] if refs else None

    @staticmethod
    def _parse_requirement(requirement_line: str) -> tuple[str | None, str | None]:
        return parse_requirement_line(requirement_line)

    @staticmethod
    def _build_issue_id(file_path: str, cwe_id: str, line_number: int) -> str:
        return f"{file_path}_{cwe_id}_{line_number}"
