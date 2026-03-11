from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from layer2.common.requirement_parser import parse_requirement_line
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability

KISA_MAPPING = {
    "CWE-79": "입력데이터 검증 및 표현 3항",
    "CWE-89": "입력데이터 검증 및 표현 1항",
    "CWE-22": "입력데이터 검증 및 표현 5항",
    "CWE-78": "입력데이터 검증 및 표현 4항",
    "CWE-611": "입력데이터 검증 및 표현 6항",
    "CWE-327": "암호화 관리 2항",
    "CWE-330": "난수 생성 및 관리",
    "CWE-502": "직렬화된 객체 처리",
    "CWE-798": "보안기능 (키 관리) 2항",
    "CWE-829": "외부 라이브러리 사용 및 관리",
    "CWE-1104": "외부 라이브러리 사용 및 관리",
}

OWASP_MAPPING = {
    "CWE-89": "A03:2021",
    "CWE-79": "A03:2021",
    "CWE-22": "A01:2021",
    "CWE-78": "A03:2021",
    "CWE-798": "A02:2021",
    "CWE-327": "A02:2021",
    "CWE-611": "A03:2021",
    "CWE-1104": "A08:2021",
    "CWE-829": "A06:2021",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _gen_vuln_id(index: int) -> str:
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"VSH-{date_str}-{index:03d}"


def _build_package_id(source: str, ecosystem: str, name: str, version: str) -> str:
    eco = (ecosystem or "unknown").upper().replace(" ", "")
    nm = (name or "unknown").replace("/", "-").replace("@", "")
    ver = (version or "unknown").replace("/", "-")
    return f"PKG-{source}-{eco}-{nm}-{ver}"


def _vuln_type_from_finding(finding: Vulnerability) -> str:
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
    return mapping.get(finding.cwe_id, "GENERIC")


def _normalize_vuln_record(finding: Vulnerability, index: int) -> dict[str, Any]:
    return {
        "vuln_id": _gen_vuln_id(index),
        "rule_id": finding.rule_id,
        "source": "L1",
        "detected_at": _now_iso(),
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "language": _guess_language(finding.file_path or ""),
        "vuln_type": _vuln_type_from_finding(finding),
        "cwe_id": finding.cwe_id,
        "severity": finding.severity,
        "reachability_status": _normalize_reachability(finding.reachability_status),
        "kisa_ref": KISA_MAPPING.get(finding.cwe_id, "미매핑-추후보강"),
        "owasp_ref": OWASP_MAPPING.get(finding.cwe_id),
        "evidence": finding.code_snippet,
        "references": list(finding.references),
        "status": "pending",
        "metadata": dict(finding.metadata),
    }


def _normalize_reachability(status: str | None) -> str:
    if status == "YES":
        return "reachable"
    if status == "NO":
        return "unreachable"
    return "unknown"


def _guess_language(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    if suffix in {".js", ".jsx", ".mjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    return "python"


def _normalize_package_records(findings: list[Vulnerability]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()

    for finding in findings:
        if finding.cwe_id not in {"CWE-829", "CWE-1104"}:
            continue

        if finding.cwe_id == "CWE-829":
            package_name, package_version = parse_requirement_line(finding.code_snippet)
            if not package_name:
                continue
            package_id = _build_package_id("L1", "PyPI", package_name, package_version or "unknown")
            if package_id in seen:
                continue
            seen.add(package_id)
            records.append(
                {
                    "package_id": package_id,
                    "source": "L1",
                    "detected_at": _now_iso(),
                    "name": package_name,
                    "version": package_version or "unknown",
                    "ecosystem": "PyPI",
                    "severity": finding.severity,
                    "status": "upgrade_required",
                    "evidence": finding.code_snippet,
                    "references": list(finding.references),
                    "metadata": dict(finding.metadata),
                }
            )
            continue

        package_name = finding.metadata.get("package")
        ecosystem = finding.metadata.get("ecosystem", "PyPI")
        if not package_name:
            continue
        package_id = _build_package_id("L1", ecosystem, package_name, "unknown")
        if package_id in seen:
            continue
        seen.add(package_id)
        records.append(
            {
                "package_id": package_id,
                "source": "L1",
                "detected_at": _now_iso(),
                "name": package_name,
                "version": "unknown",
                "ecosystem": ecosystem,
                "severity": finding.severity,
                "status": "investigate",
                "evidence": finding.code_snippet,
                "references": list(finding.references),
                "metadata": dict(finding.metadata),
            }
        )

    return records


def normalize_scan_result(result: ScanResult) -> ScanResult:
    result.vuln_records = [
        _normalize_vuln_record(finding, index + 1)
        for index, finding in enumerate(result.findings)
    ]
    result.package_records = _normalize_package_records(result.findings)
    result.notes = [
        f"layer=L1",
        f"language={result.language}",
        f"findings={len(result.findings)}",
        f"package_records={len(result.package_records)}",
    ]
    return result
