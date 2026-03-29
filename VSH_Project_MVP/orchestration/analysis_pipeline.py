import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from .base_pipeline import BasePipeline
from shared.contracts import BaseScanner, BaseAnalyzer
from shared.finding_dedup import deduplicate_findings
from layer2.common.schema_mapper import build_l2_vuln_records
from layer2.patch_builder import PatchBuilder
from layer2.retriever.evidence_retriever import EvidenceRetriever
from layer2.verifier.registry_verifier import RegistryVerifier
from layer2.verifier.osv_verifier import OsvVerifier
from layer2.analyzer.confidence_support import build_decision_metadata
from repository.base_repository import BaseReadRepository, BaseWriteRepository
from models.vulnerability import Vulnerability
from models.scan_result import ScanResult
from models.fix_suggestion import FixSuggestion
from models.common_schema import PackageRecord, VulnRecord
from shared.logging_utils import get_logger

LOGGER = get_logger(__name__)

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
        retriever_status = self._get_retriever_status()
        if not os.path.exists(file_path):
            empty_result = ScanResult(
                file_path=file_path,
                language=self._infer_language(file_path),
                findings=[],
            )
            return self._build_run_result(empty_result, [], [], True, retriever_status)

        integrated_scan_result = self._build_integrated_scan_result(file_path)
        if integrated_scan_result.is_clean():
            return self._build_run_result(
                integrated_scan_result,
                [],
                [],
                True,
                retriever_status,
            )

        knowledge_data, fix_data = self._load_analysis_sources()
        evidence_map, verification_map, analysis_context_map = self._build_analysis_inputs(
            file_path=file_path,
            scan_result=integrated_scan_result,
            knowledge_data=knowledge_data,
            fix_data=fix_data,
        )
        raw_fix_suggestions = self._run_analyzer(
            scan_result=integrated_scan_result,
            knowledge_data=knowledge_data,
            fix_data=fix_data,
            analysis_context_map=analysis_context_map,
        )
        analysis_error = getattr(self.analyzer, "last_error", None)

        if analysis_error:
            self._save_analysis_failure_logs(
                file_path=file_path,
                scan_result=integrated_scan_result,
                findings=integrated_scan_result.findings,
                evidence_map=evidence_map,
                verification_map=verification_map,
                analysis_error=analysis_error,
            )
            fix_suggestions: List[FixSuggestion] = []
        else:
            fix_suggestions = self._normalize_and_save_suggestions(
                file_path=file_path,
                scan_result=integrated_scan_result,
                raw_suggestions=raw_fix_suggestions,
                evidence_map=evidence_map,
                verification_map=verification_map,
            )

        return self._build_run_result(
            integrated_scan_result=integrated_scan_result,
            fix_suggestions=fix_suggestions,
            l2_vuln_records=build_l2_vuln_records(integrated_scan_result, fix_suggestions),
            is_clean=False,
            retriever_status=retriever_status,
        )

    def run_scan_only(self, file_path: str) -> dict:
        """
        hyeonexcel 수정: MCP `scan_only` 계약을 지키기 위해
        L2 analyzer/로그 저장 없이 L1 스캔 결과만 반환하는 전용 경로를 제공한다.
        """
        if not os.path.exists(file_path):
            return {
                "file_path": file_path,
                "scan_results": [],
                "vuln_records": [],
                "package_records": [],
                "annotated_files": {},
                "notes": [],
                "is_clean": True,
            }

        integrated_scan_result = self._build_integrated_scan_result(file_path)
        return {
            "file_path": file_path,
            "scan_results": [v.model_dump() for v in integrated_scan_result.findings],
            "vuln_records": [record.model_dump() for record in integrated_scan_result.vuln_records],
            "package_records": [record.model_dump() for record in integrated_scan_result.package_records],
            "annotated_files": integrated_scan_result.annotated_files,
            "notes": integrated_scan_result.notes,
            "is_clean": integrated_scan_result.is_clean(),
        }

    def _scan_all_results(self, file_path: str) -> List[ScanResult]:
        all_results: List[ScanResult] = []
        for scanner in self.scanners:
            try:
                result = scanner.scan(file_path)
                if result:
                    all_results.append(result)
            except ValueError as e:
                LOGGER.warning("Unsupported language", extra={"error": str(e)})
            except Exception as e:
                LOGGER.warning("Scanner execution failed", extra={"error": str(e)})
        return all_results

    def _build_integrated_scan_result(self, file_path: str) -> ScanResult:
        # hyeonexcel 수정: run()에 몰려 있던 스캔/중복 제거/통합 ScanResult 생성을 분리해
        # 이후 L3 handoff나 멀티 언어 확장 시 입력 단계만 독립적으로 다룰 수 있게 한다.
        scan_results = self._scan_all_results(file_path)
        unique_findings = deduplicate_findings(
            [
                finding
                for result in scan_results
                for finding in result.findings
            ]
        )
        integrated_result = ScanResult(
            file_path=file_path,
            language=self._infer_language(file_path),
            findings=unique_findings,
        )
        integrated_result.vuln_records = self._merge_vuln_records(scan_results)
        integrated_result.package_records = self._merge_package_records(scan_results)
        integrated_result.notes = self._merge_notes(scan_results)
        integrated_result.annotated_files = self._build_annotation_preview(integrated_result)
        return integrated_result

    @staticmethod
    def _infer_language(file_path: str) -> str:
        suffix = Path(file_path).suffix.lower()
        if suffix in {".js", ".jsx", ".mjs"}:
            return "javascript"
        if suffix in {".ts", ".tsx"}:
            return "typescript"
        return "python"

    def _load_analysis_sources(self) -> tuple[List[Dict], List[Dict]]:
        return self.knowledge_repo.find_all(), self.fix_repo.find_all()

    def _build_analysis_inputs(
        self,
        file_path: str,
        scan_result: ScanResult,
        knowledge_data: List[Dict],
        fix_data: List[Dict],
    ) -> tuple[Dict[str, Dict], Dict[str, Dict], Dict[str, Dict]]:
        evidence_map = self.evidence_retriever.retrieve(
            scan_result,
            knowledge_data,
            fix_data,
        )
        verification_map = self._build_verification_map(
            default_file_path=file_path,
            findings=scan_result.findings,
        )
        analysis_context_map = self._build_analysis_context_map(
            evidence_map=evidence_map,
            verification_map=verification_map,
        )
        return evidence_map, verification_map, analysis_context_map

    def _run_analyzer(
        self,
        scan_result: ScanResult,
        knowledge_data: List[Dict],
        fix_data: List[Dict],
        analysis_context_map: Dict[str, Dict],
    ) -> List[FixSuggestion]:
        return self.analyzer.analyze(
            scan_result,
            knowledge_data,
            fix_data,
            analysis_context_map,
        )

    def _save_analysis_failure_logs(
        self,
        file_path: str,
        scan_result: ScanResult,
        findings: List[Vulnerability],
        evidence_map: Dict[str, Dict],
        verification_map: Dict[str, Dict],
        analysis_error: str,
    ) -> None:
        for finding in findings:
            evidence_context = self._build_evidence_context(file_path, finding, evidence_map)
            verification_context = self._build_verification_context(file_path, finding, verification_map)
            self.log_repo.save(
                self._build_analysis_failure_log(
                    default_file_path=file_path,
                    scan_result=scan_result,
                    finding=finding,
                    evidence_context=evidence_context,
                    verification_context=verification_context,
                    error_message=analysis_error,
                )
            )

    def _normalize_and_save_suggestions(
        self,
        file_path: str,
        scan_result: ScanResult,
        raw_suggestions: List[FixSuggestion],
        evidence_map: Dict[str, Dict],
        verification_map: Dict[str, Dict],
    ) -> List[FixSuggestion]:
        normalized_suggestions: List[FixSuggestion] = []

        for suggestion in raw_suggestions:
            matching_vuln = self._find_matching_vulnerability(
                file_path=file_path,
                findings=scan_result.findings,
                suggestion=suggestion,
            )
            if not matching_vuln:
                normalized_suggestions.append(suggestion)
                continue

            normalized_suggestion = self._normalize_suggestion(
                default_file_path=file_path,
                finding=matching_vuln,
                suggestion=suggestion,
                evidence_map=evidence_map,
                verification_map=verification_map,
            )
            l2_vuln_record = next(
                iter(build_l2_vuln_records(scan_result, [normalized_suggestion])),
                None,
            )
            self.log_repo.save(
                self._build_log_data(
                    matching_vuln,
                    normalized_suggestion,
                    l2_vuln_record.model_dump() if l2_vuln_record else None,
                )
            )
            normalized_suggestions.append(normalized_suggestion)

        return normalized_suggestions

    def _normalize_suggestion(
        self,
        default_file_path: str,
        finding: Vulnerability,
        suggestion: FixSuggestion,
        evidence_map: Dict[str, Dict],
        verification_map: Dict[str, Dict],
    ) -> FixSuggestion:
        finding_file_path = self._resolve_finding_file_path(finding, default_file_path)
        evidence_context = self._build_evidence_context(default_file_path, finding, evidence_map)
        verification_context = self._build_verification_context(default_file_path, finding, verification_map)
        patch_context = self.patch_builder.build(finding, suggestion)
        category = self._classify_category(finding.cwe_id)
        remediation_kind = self._build_remediation_kind(category, patch_context)
        target_ref = self._build_target_ref(finding_file_path, finding, category)
        processing_trace = self._build_processing_trace(
            evidence_context=evidence_context,
            verification_context=verification_context,
            patch_context=patch_context,
            analysis_failed=False,
        )
        analysis_context = {
            **evidence_context,
            **verification_context,
        }
        # hyeonexcel 수정: analyzer가 필드를 비워도 pipeline 단계에서
        # 최종 decision/confidence 메타데이터를 일관되게 보정해서 남긴다.
        decision_status, confidence_score, confidence_reason = build_decision_metadata(
            finding.cwe_id,
            analysis_context,
            decision_status=suggestion.metadata.l2.decision_status,
            confidence_score=suggestion.metadata.l2.confidence_score,
            confidence_reason=suggestion.metadata.l2.confidence_reason,
        )
        canonical_issue_id = self._build_issue_id(
            finding_file_path,
            finding.cwe_id,
            finding.line_number,
        )
        existing_l2 = suggestion.metadata.l2.model_dump()
        existing_l2.update(
            {
                "evidence_refs": suggestion.evidence_refs or evidence_context.get("evidence_refs", []),
                "evidence_summary": suggestion.evidence_summary or evidence_context.get("evidence_summary"),
                "retrieval_backend": suggestion.retrieval_backend or evidence_context.get("retrieval_backend"),
                "chroma_status": suggestion.chroma_status or evidence_context.get("chroma_status"),
                "chroma_summary": suggestion.chroma_summary or evidence_context.get("chroma_summary"),
                "chroma_hits": max(suggestion.chroma_hits, evidence_context.get("chroma_hits", 0)),
                "registry_status": suggestion.registry_status or verification_context.get("registry_status"),
                "registry_summary": suggestion.registry_summary or verification_context.get("registry_summary"),
                "osv_status": suggestion.osv_status or verification_context.get("osv_status"),
                "osv_summary": suggestion.osv_summary or verification_context.get("osv_summary"),
                "verification_summary": (
                    suggestion.verification_summary
                    or verification_context.get("verification_summary")
                ),
                "decision_status": decision_status,
                "confidence_score": confidence_score,
                "confidence_reason": confidence_reason,
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

        normalized_payload = suggestion.model_dump()
        normalized_payload.update(
            {
                "vuln_id": canonical_issue_id,
                "file_path": finding_file_path,
                "cwe_id": finding.cwe_id,
                "line_number": finding.line_number,
                "kisa_ref": suggestion.kisa_ref or evidence_context.get("primary_reference"),
                "metadata": {
                    "l2": existing_l2,
                },
            }
        )
        return FixSuggestion(**normalized_payload)

    @staticmethod
    def _build_log_data(
        finding: Vulnerability,
        suggestion: FixSuggestion,
        l2_vuln_record: dict | None = None,
    ) -> dict:
        l2 = suggestion.metadata.l2
        return {
            "issue_id": suggestion.issue_id,
            "vuln_id": suggestion.vuln_id,
            "file_path": suggestion.file_path,
            "l2_vuln_record": l2_vuln_record,
            "metadata": suggestion.metadata.model_dump(),
            "rule_id": finding.rule_id,
            "cwe_id": finding.cwe_id,
            "severity": finding.severity,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "l1_reachability_status": finding.reachability_status,
            "l1_references": list(finding.references),
            "original_code": suggestion.original_code or finding.code_snippet,
            "fixed_code": suggestion.fixed_code,
            "description": suggestion.description,
            "reachability": suggestion.reachability,
            "kisa_reference": suggestion.kisa_ref,
            "evidence_refs": l2.evidence_refs,
            "evidence_summary": l2.evidence_summary,
            "retrieval_backend": l2.retrieval_backend,
            "chroma_status": l2.chroma_status,
            "chroma_summary": l2.chroma_summary,
            "chroma_hits": l2.chroma_hits,
            "registry_status": l2.registry_status,
            "registry_summary": l2.registry_summary,
            "osv_status": l2.osv_status,
            "osv_summary": l2.osv_summary,
            "verification_summary": l2.verification_summary,
            "decision_status": l2.decision_status,
            "confidence_score": l2.confidence_score,
            "confidence_reason": l2.confidence_reason,
            "patch_status": l2.patch_status,
            "patch_summary": l2.patch_summary,
            "patch_diff": l2.patch_diff,
            "processing_trace": l2.processing_trace,
            "processing_summary": l2.processing_summary,
            "category": l2.category,
            "remediation_kind": l2.remediation_kind,
            "target_ref": l2.target_ref,
            "status": "pending",
        }

    def _build_run_result(
        self,
        integrated_scan_result: ScanResult,
        fix_suggestions: List[FixSuggestion],
        l2_vuln_records: List | None,
        is_clean: bool,
        retriever_status: Dict[str, str],
    ) -> dict:
        serialized_l2_vuln_records = [
            record.model_dump() for record in (l2_vuln_records or [])
        ]
        return {
            "file_path": integrated_scan_result.file_path,
            "scan_results": [v.model_dump() for v in integrated_scan_result.findings],
            "vuln_records": [record.model_dump() for record in integrated_scan_result.vuln_records],
            "package_records": [record.model_dump() for record in integrated_scan_result.package_records],
            "l2_vuln_records": serialized_l2_vuln_records,
            "annotated_files": integrated_scan_result.annotated_files,
            "notes": integrated_scan_result.notes,
            "fix_suggestions": [f.model_dump() for f in fix_suggestions],
            "is_clean": is_clean,
            "summary": self._build_run_summary(
                integrated_scan_result,
                fix_suggestions,
                serialized_l2_vuln_records,
                retriever_status,
            ),
        }

    def _build_annotation_preview(self, integrated_scan_result: ScanResult) -> Dict[str, str]:
        for scanner in self.scanners:
            if not hasattr(scanner, "annotate"):
                continue
            try:
                annotated_result = scanner.annotate(integrated_scan_result.model_copy(deep=True))
                if annotated_result.annotated_files:
                    return annotated_result.annotated_files
            except Exception as exc:
                print(f"[WARN] Annotation preview failed: {exc}")
        return {}

    @staticmethod
    def _merge_notes(scan_results: List[ScanResult]) -> List[str]:
        merged: List[str] = []
        seen: set[str] = set()
        for result in scan_results:
            for note in result.notes:
                if note in seen:
                    continue
                seen.add(note)
                merged.append(note)
        return merged

    @staticmethod
    def _merge_vuln_records(scan_results: List[ScanResult]) -> List[VulnRecord]:
        merged: List[VulnRecord] = []
        seen: set[tuple[str | None, int | None, str | None]] = set()
        for result in scan_results:
            for record in result.vuln_records:
                key = (
                    record.file_path,
                    record.line_number,
                    record.cwe_id,
                )
                if key in seen:
                    continue
                seen.add(key)
                merged.append(record)
        return merged

    @staticmethod
    def _merge_package_records(scan_results: List[ScanResult]) -> List[PackageRecord]:
        merged: List[PackageRecord] = []
        seen: set[str] = set()
        for result in scan_results:
            for record in result.package_records:
                package_id = record.package_id
                if package_id in seen:
                    continue
                if package_id:
                    seen.add(package_id)
                merged.append(record)
        return merged

    def _get_retriever_status(self) -> Dict[str, str]:
        if hasattr(self.evidence_retriever, "runtime_status"):
            return self.evidence_retriever.runtime_status()
        return {}

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
        scan_result: ScanResult,
        finding: Vulnerability,
        evidence_context: dict,
        verification_context: dict,
        error_message: str,
    ) -> dict:
        finding_file_path = cls._resolve_finding_file_path(finding, default_file_path)
        placeholder_suggestion = FixSuggestion(
            issue_id=cls._build_issue_id(finding_file_path, finding.cwe_id, finding.line_number),
            file_path=finding_file_path,
            cwe_id=finding.cwe_id,
            line_number=finding.line_number,
            original_code=finding.code_snippet,
            fixed_code="",
            description="L2 분석 실패로 수정 제안을 생성하지 못했습니다.",
            kisa_ref=evidence_context.get("primary_reference"),
            metadata={
                "l2": {
                    "evidence_refs": evidence_context.get("evidence_refs", []),
                    "evidence_summary": evidence_context.get("evidence_summary"),
                    "retrieval_backend": evidence_context.get("retrieval_backend"),
                    "chroma_status": evidence_context.get("chroma_status"),
                    "chroma_summary": evidence_context.get("chroma_summary"),
                    "chroma_hits": evidence_context.get("chroma_hits", 0),
                    "registry_status": verification_context.get("registry_status"),
                    "registry_summary": verification_context.get("registry_summary"),
                    "osv_status": verification_context.get("osv_status"),
                    "osv_summary": verification_context.get("osv_summary"),
                    "verification_summary": verification_context.get("verification_summary"),
                    "decision_status": "analysis_failed",
                    "confidence_score": 0,
                    "confidence_reason": "L2 분석 실패로 신뢰도를 계산하지 못했습니다.",
                    "category": cls._classify_category(finding.cwe_id),
                    "target_ref": cls._build_target_ref(
                        finding_file_path,
                        finding,
                        cls._classify_category(finding.cwe_id),
                    ),
                }
            },
        )
        l2_vuln_record = next(
            iter(build_l2_vuln_records(scan_result, [placeholder_suggestion])),
            None,
        )
        return {
            "issue_id": cls._build_issue_id(finding_file_path, finding.cwe_id, finding.line_number),
            "vuln_id": placeholder_suggestion.vuln_id,
            "file_path": finding_file_path,
            "l2_vuln_record": l2_vuln_record.model_dump() if l2_vuln_record else None,
            "metadata": placeholder_suggestion.metadata.model_dump(),
            "rule_id": finding.rule_id,
            "cwe_id": finding.cwe_id,
            "severity": finding.severity,
            "line_number": finding.line_number,
            "code_snippet": finding.code_snippet,
            "l1_reachability_status": finding.reachability_status,
            "l1_references": list(finding.references),
            "original_code": finding.code_snippet,
            "fixed_code": "",
            "description": "L2 분석 실패로 수정 제안을 생성하지 못했습니다.",
            "reachability": None,
            "kisa_reference": evidence_context.get("primary_reference"),
            "evidence_refs": placeholder_suggestion.evidence_refs,
            "evidence_summary": placeholder_suggestion.evidence_summary,
            "retrieval_backend": placeholder_suggestion.retrieval_backend,
            "chroma_status": placeholder_suggestion.chroma_status,
            "chroma_summary": placeholder_suggestion.chroma_summary,
            "chroma_hits": placeholder_suggestion.chroma_hits,
            "registry_status": placeholder_suggestion.registry_status,
            "registry_summary": placeholder_suggestion.registry_summary,
            "osv_status": placeholder_suggestion.osv_status,
            "osv_summary": placeholder_suggestion.osv_summary,
            "verification_summary": placeholder_suggestion.verification_summary,
            "decision_status": placeholder_suggestion.decision_status,
            "confidence_score": placeholder_suggestion.confidence_score,
            "confidence_reason": placeholder_suggestion.confidence_reason,
            "patch_status": placeholder_suggestion.patch_status,
            "patch_summary": placeholder_suggestion.patch_summary,
            "patch_diff": placeholder_suggestion.patch_diff,
            "category": placeholder_suggestion.category,
            "remediation_kind": placeholder_suggestion.remediation_kind,
            "target_ref": placeholder_suggestion.target_ref,
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

    @staticmethod
    def _build_analysis_context_map(
        evidence_map: Dict[str, Dict],
        verification_map: Dict[str, Dict],
    ) -> Dict[str, Dict]:
        issue_ids = set(evidence_map.keys()) | set(verification_map.keys())
        return {
            issue_id: {
                **evidence_map.get(issue_id, {}),
                **verification_map.get(issue_id, {}),
            }
            for issue_id in issue_ids
        }

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

        retrieval_backend = evidence_context.get("retrieval_backend")
        if retrieval_backend:
            trace.append(f"retrieval:backend:{retrieval_backend}")

        chroma_status = evidence_context.get("chroma_status")
        if chroma_status:
            trace.append(f"retrieval:chroma:{chroma_status}")

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
    def _build_run_summary(
        integrated_scan_result: ScanResult,
        fix_suggestions: List[FixSuggestion],
        l2_vuln_records: List[Dict] | None = None,
        retriever_status: Dict[str, str] | None = None,
    ) -> Dict[str, int | str]:
        # hyeonexcel 수정: summary는 이미 정규화된 suggestion을 집계만 해야 한다.
        # 여기서 suggestion을 다시 수정하면 반환 payload와 summary 집계 시점이 달라질 수 있다.
        findings = integrated_scan_result.findings
        summary: Dict[str, int | str] = {
            "findings_total": len(findings),
            "fix_suggestions_total": len(fix_suggestions),
            "l1_vuln_records_total": len(integrated_scan_result.vuln_records),
            "l1_package_records_total": len(integrated_scan_result.package_records),
            "l2_vuln_records_total": len(l2_vuln_records or []),
            "annotation_preview_total": len(integrated_scan_result.annotated_files),
            "l1_notes_total": len(integrated_scan_result.notes),
            "rule_tagged_total": sum(1 for finding in findings if finding.rule_id),
            "reachable_findings_total": sum(
                1 for finding in findings if finding.reachability_status == "reachable"
            ),
            "typosquatting_findings_total": sum(
                1 for finding in findings if finding.cwe_id == "CWE-1104"
            ),
            "code_findings_total": sum(1 for finding in findings if finding.cwe_id != "CWE-829"),
            "supply_chain_findings_total": sum(1 for finding in findings if finding.cwe_id == "CWE-829"),
            "code_fix_suggestions_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.category == "code"
            ),
            "supply_chain_fix_suggestions_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.category == "supply_chain"
            ),
            "verified_total": sum(
                1
                for suggestion in fix_suggestions
                if suggestion.metadata.l2.registry_status is not None
                or suggestion.metadata.l2.osv_status is not None
            ),
            "patch_generated_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.patch_status == "GENERATED"
            ),
            "chroma_enriched_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.chroma_hits > 0
            ),
            "retrieval_hybrid_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.retrieval_backend == "hybrid"
            ),
            "retrieval_static_only_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.retrieval_backend == "static_only"
            ),
            "decision_confirmed_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.decision_status == "confirmed"
            ),
            "confidence_high_total": sum(
                1 for suggestion in fix_suggestions if suggestion.metadata.l2.confidence_score >= 85
            ),
        }
        if retriever_status:
            summary["chroma_status"] = retriever_status.get("status", "UNKNOWN")
            summary["chroma_summary"] = retriever_status.get("summary", "")
        return summary

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
