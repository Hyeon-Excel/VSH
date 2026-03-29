from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from models.common_schema import VulnRecord
from models.fix_suggestion import FixSuggestion
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability


def build_l2_vuln_records(
    scan_result: ScanResult,
    fix_suggestions: Iterable[FixSuggestion],
) -> list[VulnRecord]:
    l1_index = {
        _record_key(record.file_path, record.cwe_id, record.line_number): record
        for record in scan_result.vuln_records
    }
    finding_index = {
        _record_key(finding.file_path or scan_result.file_path, finding.cwe_id, finding.line_number): finding
        for finding in scan_result.findings
    }

    records: list[VulnRecord] = []
    for suggestion in fix_suggestions:
        if suggestion.file_path is None or suggestion.cwe_id is None or suggestion.line_number is None:
            continue

        key = _record_key(suggestion.file_path, suggestion.cwe_id, suggestion.line_number)
        l1_record = l1_index.get(key)
        finding = finding_index.get(key)

        records.append(
            VulnRecord(
                vuln_id=l1_record.vuln_id if l1_record else _build_vuln_id(suggestion.vuln_id),
                rule_id=_resolve_rule_id(finding, l1_record),
                source="L2",
                detected_at=l1_record.detected_at if l1_record else _now_iso(),
                file_path=suggestion.file_path,
                line_number=suggestion.line_number,
                end_line_number=l1_record.end_line_number if l1_record else suggestion.line_number,
                column_number=l1_record.column_number if l1_record else 1,
                end_column_number=l1_record.end_column_number if l1_record else _build_end_column(suggestion),
                language=l1_record.language if l1_record else _guess_language(suggestion.file_path),
                vuln_type=l1_record.vuln_type if l1_record else _guess_vuln_type(suggestion.cwe_id),
                cwe_id=suggestion.cwe_id,
                cve_id=l1_record.cve_id if l1_record else _extract_cve(suggestion.evidence_refs),
                severity=(l1_record.severity if l1_record else _severity_from_finding(finding)),
                cvss_score=l1_record.cvss_score if l1_record else _extract_cvss(suggestion.evidence_refs),
                reachability_status=_normalize_reachability(finding),
                reachability_confidence=(
                    _normalize_reachability_confidence(finding)
                    if l1_record is None
                    else (l1_record.reachability_confidence or _normalize_reachability_confidence(finding))
                ),
                kisa_ref=suggestion.kisa_ref or (l1_record.kisa_ref if l1_record else "미매핑-추후보강"),
                fss_ref=l1_record.fss_ref if l1_record else None,
                owasp_ref=l1_record.owasp_ref if l1_record else None,
                evidence=suggestion.original_code or (finding.code_snippet if finding else ""),
                fix_suggestion=suggestion.description or suggestion.fixed_code,
                status="pending",
                action_at=None,
            )
        )

    return records


def _record_key(file_path: str, cwe_id: str, line_number: int) -> tuple[str, str, int]:
    return file_path, cwe_id, line_number


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_vuln_id(vuln_id: str | None) -> str:
    if vuln_id:
        return vuln_id
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"VSH-{date_str}-L2"


def _resolve_rule_id(finding: Vulnerability | None, l1_record: VulnRecord | None) -> str:
    if finding and finding.rule_id:
        return finding.rule_id
    if l1_record:
        return l1_record.rule_id
    return "VSH-L2-GENERIC"


def _build_end_column(suggestion: FixSuggestion) -> int:
    code = suggestion.original_code or suggestion.fixed_code or ""
    return max(1, len(code.strip()) or len(code) or 1)


def _guess_language(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    if suffix in {".js", ".jsx", ".mjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    return "python"


def _guess_vuln_type(cwe_id: str) -> str:
    mapping = {
        "CWE-79": "XSS",
        "CWE-89": "SQLI",
        "CWE-22": "PATH_TRAVERSAL",
        "CWE-78": "CMDI",
        "CWE-611": "XXE",
        "CWE-327": "WEAK_CRYPTO",
        "CWE-330": "INSECURE_RANDOM",
        "CWE-502": "DESERIALIZATION",
        "CWE-798": "HARDCODED_SECRET",
        "CWE-829": "SUPPLY_CHAIN",
        "CWE-1104": "PACKAGE_RISK",
    }
    return mapping.get(cwe_id, "GENERIC")


def _severity_from_finding(finding: Vulnerability | None) -> str:
    if finding:
        return finding.severity
    return "MEDIUM"


def _normalize_reachability(finding: Vulnerability | None) -> str:
    if finding is None:
        return "unknown"
    status = (finding.reachability_status or "").lower()
    if status in {"yes", "reachable", "high"}:
        return "reachable"
    if status in {"no", "unreachable", "low"}:
        return "unreachable"
    return "unknown"


def _normalize_reachability_confidence(finding: Vulnerability | None) -> str:
    if finding is None:
        return "low"
    confidence = finding.metadata.get("reachability_confidence") or "unknown"
    if isinstance(confidence, str):
        confidence = confidence.lower()
        if confidence in {"high", "medium", "low"}:
            return confidence
    return "low"


def _confidence_band(score: int) -> str:
    if score >= 85:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def _extract_cve(evidence_refs: list[str]) -> str | None:
    for ref in evidence_refs:
        if "CVE-" in ref:
            if ref.startswith("NVD: "):
                return ref.replace("NVD: ", "", 1)
            return ref
    return None


def _extract_cvss(evidence_refs: list[str]) -> float | None:
    for ref in evidence_refs:
        if ref.startswith("CVSS: "):
            try:
                return float(ref.replace("CVSS: ", "", 1))
            except ValueError:
                return None
    return None
