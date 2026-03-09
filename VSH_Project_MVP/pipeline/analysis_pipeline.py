import os
import re
from typing import Dict, List, Optional
from .base_pipeline import BasePipeline
from modules.base_module import BaseScanner, BaseAnalyzer
from layer2.patch_builder import PatchBuilder
from layer2.retriever.evidence_retriever import EvidenceRetriever
from layer2.verifier.registry_verifier import RegistryVerifier
from layer2.verifier.osv_verifier import OsvVerifier
from repository.base_repository import BaseReadRepository, BaseWriteRepository
from models.vulnerability import Vulnerability
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion

class AnalysisPipeline(BasePipeline):
    """
    Scanner(L1)와 Analyzer(L2)를 연결하고 결과를 LogRepo에 저장하는 핵심 파이프라인.
    """

    def __init__(self,
                 scanners: List[BaseScanner],
                 analyzer: BaseAnalyzer,
                 knowledge_repo: BaseReadRepository,
                 fix_repo: BaseReadRepository,
                 log_repo: BaseWriteRepository,
                 evidence_retriever: EvidenceRetriever | None = None,
                 registry_verifier: RegistryVerifier | None = None,
                 osv_verifier: OsvVerifier | None = None,
                 patch_builder: PatchBuilder | None = None):
        self.scanners = scanners
        self.analyzer = analyzer
        self.evidence_retriever = evidence_retriever or EvidenceRetriever()
        self.registry_verifier = registry_verifier or RegistryVerifier()
        self.osv_verifier = osv_verifier or OsvVerifier()
        self.patch_builder = patch_builder or PatchBuilder()
        self.knowledge_repo = knowledge_repo
        self.fix_repo = fix_repo
        self.log_repo = log_repo

    def run(self, file_path: str) -> dict:
        """
        파일에 대해 L1 스캔, 중복 제거, L2 분석, 결과 저장을 수행합니다.
        파일이 없으면 빈 결과 dict를 반환합니다.
        """
        if not os.path.exists(file_path):
            return {
                "file_path": file_path,
                "scan_results": [],
                "fix_suggestions": [],
                "is_clean": True,
                "summary": self._build_run_summary([], []),
            }

        # 1. 각 Scanner 실행
        all_findings: List[Vulnerability] = []
        for scanner in self.scanners:
            # 지원하는 언어인지 먼저 확인하거나 예외를 잡을 수 있지만, 
            # 여기서는 Scanner 내부의 언어 체크에 맡기고 실행
            try:
                result = scanner.scan(file_path)
                if result and result.findings:
                    all_findings.extend(result.findings)
            except ValueError as e:
                print(f"[WARN] Unsupported language: {e}")
                # 해당 Scanner 결과만 건너뛰고 계속 진행
            except Exception as e:
                print(f"[WARN] Scanner execution failed: {e}")
                
        # 2 & 3. 중복 제거
        unique_findings = self._deduplicate(all_findings)
        
        # 4. 중복 제거된 findings로 새 ScanResult 생성
        integrated_scan_result = ScanResult(
            file_path=file_path,
            language="python", # MVP에서는 python 고정
            findings=unique_findings
        )

        is_clean = integrated_scan_result.is_clean()
        fix_suggestions: List[FixSuggestion] = []

        if not is_clean:
            # 5. Repository에서 데이터 조회
            knowledge_data = self.knowledge_repo.find_all()
            fix_data = self.fix_repo.find_all()
            evidence_map = self.evidence_retriever.retrieve(
                integrated_scan_result,
                knowledge_data,
                fix_data,
            )
            verification_map = self._build_verification_map(
                default_file_path=file_path,
                findings=unique_findings,
            )

            # 6. Analyzer 실행 (L2)
            fix_suggestions = self.analyzer.analyze(
                integrated_scan_result,
                knowledge_data,
                fix_data,
                evidence_map,
            )
            analysis_error = getattr(self.analyzer, "last_error", None)

            # 7. LogRepo 저장
            if analysis_error:
                for finding in unique_findings:
                    evidence_context = self._build_evidence_context(file_path, finding, evidence_map)
                    verification_context = self._build_verification_context(file_path, finding, verification_map)
                    self.log_repo.save(
                        self._build_analysis_failure_log(
                            default_file_path=file_path,
                            finding=finding,
                            evidence_context=evidence_context,
                            verification_context=verification_context,
                            error_message=analysis_error,
                        )
                    )
            else:
                for suggestion in fix_suggestions:
                    matching_vuln = self._find_matching_vulnerability(
                        file_path=file_path,
                        findings=unique_findings,
                        suggestion=suggestion,
                    )
                    
                    if matching_vuln:
                        finding_file_path = self._resolve_finding_file_path(matching_vuln, file_path)
                        evidence_context = self._build_evidence_context(file_path, matching_vuln, evidence_map)
                        verification_context = self._build_verification_context(
                            file_path,
                            matching_vuln,
                            verification_map,
                        )
                        patch_context = self.patch_builder.build(matching_vuln, suggestion)
                        category = self._classify_category(matching_vuln.cwe_id)
                        remediation_kind = self._build_remediation_kind(category, patch_context)
                        target_ref = self._build_target_ref(finding_file_path, matching_vuln, category)
                        processing_trace = self._build_processing_trace(
                            evidence_context=evidence_context,
                            verification_context=verification_context,
                            patch_context=patch_context,
                            analysis_failed=False,
                        )
                        canonical_issue_id = self._build_issue_id(
                            finding_file_path,
                            matching_vuln.cwe_id,
                            matching_vuln.line_number,
                        )
                        normalized_suggestion = suggestion.model_copy(
                            update={
                                "issue_id": canonical_issue_id,
                                "file_path": finding_file_path,
                                "cwe_id": matching_vuln.cwe_id,
                                "line_number": matching_vuln.line_number,
                                "evidence_refs": suggestion.evidence_refs or evidence_context.get("evidence_refs", []),
                                "evidence_summary": suggestion.evidence_summary or evidence_context.get("evidence_summary"),
                                "kisa_reference": suggestion.kisa_reference or evidence_context.get("primary_reference"),
                                "registry_status": suggestion.registry_status or verification_context.get("registry_status"),
                                "registry_summary": suggestion.registry_summary or verification_context.get("registry_summary"),
                                "osv_status": suggestion.osv_status or verification_context.get("osv_status"),
                                "osv_summary": suggestion.osv_summary or verification_context.get("osv_summary"),
                                "verification_summary": (
                                    suggestion.verification_summary
                                    or verification_context.get("verification_summary")
                                ),
                                "patch_status": suggestion.patch_status or patch_context.get("patch_status"),
                                "patch_summary": suggestion.patch_summary or patch_context.get("patch_summary"),
                                "patch_diff": suggestion.patch_diff or patch_context.get("patch_diff"),
                                "processing_trace": suggestion.processing_trace or processing_trace,
                                "processing_summary": suggestion.processing_summary or self._summarize_trace(processing_trace),
                                "category": suggestion.category or category,
                                "remediation_kind": suggestion.remediation_kind or remediation_kind,
                                "target_ref": suggestion.target_ref or target_ref,
                            }
                        )
                        log_data = {
                            "issue_id": normalized_suggestion.issue_id,
                            "file_path": finding_file_path,
                            "cwe_id": matching_vuln.cwe_id,
                            "severity": matching_vuln.severity,
                            "line_number": matching_vuln.line_number,
                            "code_snippet": matching_vuln.code_snippet,
                            "original_code": normalized_suggestion.original_code or matching_vuln.code_snippet,
                            "fixed_code": normalized_suggestion.fixed_code,
                            "description": normalized_suggestion.description,
                            "reachability": normalized_suggestion.reachability,
                            "kisa_reference": normalized_suggestion.kisa_reference,
                            "evidence_refs": normalized_suggestion.evidence_refs,
                            "evidence_summary": normalized_suggestion.evidence_summary,
                            "registry_status": normalized_suggestion.registry_status,
                            "registry_summary": normalized_suggestion.registry_summary,
                            "osv_status": normalized_suggestion.osv_status,
                            "osv_summary": normalized_suggestion.osv_summary,
                            "verification_summary": normalized_suggestion.verification_summary,
                            "patch_status": normalized_suggestion.patch_status,
                            "patch_summary": normalized_suggestion.patch_summary,
                            "patch_diff": normalized_suggestion.patch_diff,
                            "processing_trace": normalized_suggestion.processing_trace,
                            "processing_summary": normalized_suggestion.processing_summary,
                            "category": normalized_suggestion.category,
                            "remediation_kind": normalized_suggestion.remediation_kind,
                            "target_ref": normalized_suggestion.target_ref,
                            "status": "pending"
                        }
                        suggestion.issue_id = normalized_suggestion.issue_id
                        suggestion.file_path = normalized_suggestion.file_path
                        suggestion.cwe_id = normalized_suggestion.cwe_id
                        suggestion.line_number = normalized_suggestion.line_number
                        suggestion.evidence_refs = normalized_suggestion.evidence_refs
                        suggestion.evidence_summary = normalized_suggestion.evidence_summary
                        suggestion.kisa_reference = normalized_suggestion.kisa_reference
                        suggestion.registry_status = normalized_suggestion.registry_status
                        suggestion.registry_summary = normalized_suggestion.registry_summary
                        suggestion.osv_status = normalized_suggestion.osv_status
                        suggestion.osv_summary = normalized_suggestion.osv_summary
                        suggestion.verification_summary = normalized_suggestion.verification_summary
                        suggestion.patch_status = normalized_suggestion.patch_status
                        suggestion.patch_summary = normalized_suggestion.patch_summary
                        suggestion.patch_diff = normalized_suggestion.patch_diff
                        suggestion.processing_trace = normalized_suggestion.processing_trace
                        suggestion.processing_summary = normalized_suggestion.processing_summary
                        suggestion.category = normalized_suggestion.category
                        suggestion.remediation_kind = normalized_suggestion.remediation_kind
                        suggestion.target_ref = normalized_suggestion.target_ref
                        self.log_repo.save(log_data)

        # 8. 결과 dict로 변환 (Pydantic model_dump 사용)
        return {
            "file_path": file_path,
            "scan_results": [v.model_dump() for v in integrated_scan_result.findings],
            "fix_suggestions": [f.model_dump() for f in fix_suggestions],
            "is_clean": is_clean,
            "summary": self._build_run_summary(integrated_scan_result.findings, fix_suggestions),
        }

    @staticmethod
    def _deduplicate(findings: List[Vulnerability]) -> List[Vulnerability]:
        """
        cwe_id와 line_number 조합을 기준으로 중복된 취약점을 제거합니다.
        
        Args:
            findings (List[Vulnerability]): 원본 취약점 리스트
            
        Returns:
            List[Vulnerability]: 중복 제거된 취약점 리스트
        """
        unique_map = {}
        for f in findings:
            key = f"{f.file_path or ''}_{f.cwe_id}_{f.line_number}"
            if key not in unique_map:
                unique_map[key] = f
        
        return list(unique_map.values())

    @staticmethod
    def _find_matching_vulnerability(
        file_path: str,
        findings: List[Vulnerability],
        suggestion: FixSuggestion,
    ) -> Optional[Vulnerability]:
        """
        FixSuggestion의 구조화된 메타데이터를 우선 사용하여 원본 취약점을 찾습니다.
        메타데이터가 없으면 기존 issue_id 기반 매칭으로 fallback 합니다.
        """
        if suggestion.cwe_id and suggestion.line_number is not None:
            suggestion_file_path = suggestion.file_path or file_path
            match = next(
                (
                    finding
                    for finding in findings
                    if finding.cwe_id == suggestion.cwe_id
                    and finding.line_number == suggestion.line_number
                    and AnalysisPipeline._resolve_finding_file_path(finding, file_path) == suggestion_file_path
                ),
                None,
            )
            if match:
                return match

            if suggestion.file_path is None:
                return next(
                    (
                        finding
                        for finding in findings
                        if finding.cwe_id == suggestion.cwe_id and finding.line_number == suggestion.line_number
                    ),
                    None,
                )

        return next(
            (
                finding
                for finding in findings
                if AnalysisPipeline._build_issue_id(
                    AnalysisPipeline._resolve_finding_file_path(finding, file_path),
                    finding.cwe_id,
                    finding.line_number,
                ) == suggestion.issue_id
                or f"{file_path}_{finding.cwe_id}_{finding.line_number}" == suggestion.issue_id
            ),
            None,
        )

    @staticmethod
    def _resolve_finding_file_path(finding: Vulnerability, default_file_path: str) -> str:
        return finding.file_path or default_file_path

    @staticmethod
    def _build_issue_id(file_path: str, cwe_id: str, line_number: int) -> str:
        return f"{file_path}_{cwe_id}_{line_number}"

    @classmethod
    def _build_analysis_failure_log(
        cls,
        default_file_path: str,
        finding: Vulnerability,
        evidence_context: dict,
        verification_context: dict,
        error_message: str,
    ) -> dict:
        finding_file_path = cls._resolve_finding_file_path(finding, default_file_path)
        return {
            "issue_id": cls._build_issue_id(finding_file_path, finding.cwe_id, finding.line_number),
            "file_path": finding_file_path,
            "cwe_id": finding.cwe_id,
            "severity": finding.severity,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "original_code": finding.code_snippet,
            "fixed_code": "",
            "description": "L2 분석 실패로 수정 제안을 생성하지 못했습니다.",
            "reachability": None,
            "kisa_reference": evidence_context.get("primary_reference"),
            "evidence_refs": evidence_context.get("evidence_refs", []),
            "evidence_summary": evidence_context.get("evidence_summary"),
            "registry_status": verification_context.get("registry_status"),
            "registry_summary": verification_context.get("registry_summary"),
            "osv_status": verification_context.get("osv_status"),
            "osv_summary": verification_context.get("osv_summary"),
            "verification_summary": verification_context.get("verification_summary"),
            "patch_status": None,
            "patch_summary": None,
            "patch_diff": None,
            "category": cls._classify_category(finding.cwe_id),
            "remediation_kind": None,
            "target_ref": cls._build_target_ref(
                finding_file_path,
                finding,
                cls._classify_category(finding.cwe_id),
            ),
            "processing_trace": cls._build_processing_trace(
                evidence_context=evidence_context,
                verification_context=verification_context,
                patch_context={},
                analysis_failed=True,
            ),
            "processing_summary": cls._summarize_trace(
                cls._build_processing_trace(
                    evidence_context=evidence_context,
                    verification_context=verification_context,
                    patch_context={},
                    analysis_failed=True,
                )
            ),
            "analysis_error": error_message,
            "status": "analysis_failed",
        }

    @classmethod
    def _build_evidence_context(
        cls,
        default_file_path: str,
        finding: Vulnerability,
        evidence_map: dict,
    ) -> dict:
        issue_id = cls._build_issue_id(
            cls._resolve_finding_file_path(finding, default_file_path),
            finding.cwe_id,
            finding.line_number,
        )
        return evidence_map.get(issue_id, {})

    @classmethod
    def _build_verification_context(
        cls,
        default_file_path: str,
        finding: Vulnerability,
        verification_map: dict,
    ) -> dict:
        issue_id = cls._build_issue_id(
            cls._resolve_finding_file_path(finding, default_file_path),
            finding.cwe_id,
            finding.line_number,
        )
        return verification_map.get(issue_id, {})

    def _build_verification_map(
        self,
        default_file_path: str,
        findings: List[Vulnerability],
    ) -> Dict[str, Dict]:
        verification_map: Dict[str, Dict] = {}

        for finding in findings:
            issue_id = self._build_issue_id(
                self._resolve_finding_file_path(finding, default_file_path),
                finding.cwe_id,
                finding.line_number,
            )

            registry_context = self._safe_verify(self.registry_verifier, finding, "registry")
            osv_context = self._safe_verify(self.osv_verifier, finding, "osv")
            verification_context = {
                **registry_context,
                **osv_context,
            }

            summary = self._compose_verification_summary(verification_context)
            if summary:
                verification_context["verification_summary"] = summary

            if verification_context:
                verification_map[issue_id] = verification_context

        return verification_map

    @staticmethod
    def _safe_verify(verifier, finding: Vulnerability, prefix: str) -> Dict[str, str | None]:
        try:
            return verifier.verify(finding)
        except Exception as exc:
            return {
                f"{prefix}_status": "ERROR",
                f"{prefix}_summary": str(exc),
            }

    @staticmethod
    def _compose_verification_summary(verification_context: Dict[str, str | None]) -> str | None:
        parts = []
        registry_status = verification_context.get("registry_status")
        registry_summary = verification_context.get("registry_summary")
        osv_status = verification_context.get("osv_status")
        osv_summary = verification_context.get("osv_summary")

        if registry_status:
            parts.append(f"Registry[{registry_status}] {registry_summary or ''}".strip())
        if osv_status:
            parts.append(f"OSV[{osv_status}] {osv_summary or ''}".strip())

        return " | ".join(parts) if parts else None

    @staticmethod
    def _build_processing_trace(
        evidence_context: Dict,
        verification_context: Dict,
        patch_context: Dict,
        analysis_failed: bool,
    ) -> List[str]:
        trace = ["scan:detected"]

        if evidence_context:
            trace.append("retrieval:enriched")
        else:
            trace.append("retrieval:skipped")

        registry_status = verification_context.get("registry_status")
        if registry_status:
            trace.append(f"verification:registry:{registry_status}")

        osv_status = verification_context.get("osv_status")
        if osv_status:
            trace.append(f"verification:osv:{osv_status}")

        if analysis_failed:
            trace.append("analysis:failed")
        else:
            trace.append("analysis:confirmed")

        patch_status = patch_context.get("patch_status")
        if patch_status:
            trace.append(f"patch:{patch_status}")
        elif not analysis_failed:
            trace.append("patch:skipped")

        return trace

    @staticmethod
    def _summarize_trace(trace: List[str]) -> str | None:
        return " -> ".join(trace) if trace else None

    @staticmethod
    def _build_run_summary(findings: List[Vulnerability], fix_suggestions: List[FixSuggestion]) -> Dict[str, int]:
        return {
            "findings_total": len(findings),
            "fix_suggestions_total": len(fix_suggestions),
            "code_findings_total": sum(1 for finding in findings if finding.cwe_id != "CWE-829"),
            "supply_chain_findings_total": sum(1 for finding in findings if finding.cwe_id == "CWE-829"),
            "code_fix_suggestions_total": sum(
                1 for suggestion in fix_suggestions if suggestion.category == "code"
            ),
            "supply_chain_fix_suggestions_total": sum(
                1 for suggestion in fix_suggestions if suggestion.category == "supply_chain"
            ),
            "verified_total": sum(
                1
                for suggestion in fix_suggestions
                if suggestion.registry_status is not None or suggestion.osv_status is not None
            ),
            "patch_generated_total": sum(
                1 for suggestion in fix_suggestions if suggestion.patch_status == "GENERATED"
            ),
        }

    @staticmethod
    def _classify_category(cwe_id: str) -> str:
        return "supply_chain" if cwe_id == "CWE-829" else "code"

    @staticmethod
    def _build_remediation_kind(category: str, patch_context: Dict) -> str | None:
        patch_status = patch_context.get("patch_status")
        if category == "supply_chain":
            if patch_status == "GENERATED":
                return "version_bump_patch"
            return "dependency_recommendation"
        if patch_status == "GENERATED":
            return "code_patch"
        return "code_recommendation"

    @classmethod
    def _build_target_ref(cls, file_path: str, finding: Vulnerability, category: str) -> str:
        if category == "supply_chain":
            dependency_name = cls._parse_dependency_name(finding.code_snippet)
            if dependency_name:
                return f"dependency:{dependency_name}"
        return f"{file_path}:{finding.line_number}"

    @staticmethod
    def _parse_dependency_name(requirement_line: str) -> str | None:
        match = re.match(r"^([a-zA-Z0-9_\-]+)", requirement_line.strip())
        if not match:
            return None
        return match.group(1).lower()
