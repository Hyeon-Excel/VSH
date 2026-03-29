from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from layer2.common.requirement_parser import parse_requirement_line
from models.common_schema import PackageRecord, VulnRecord
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


def _build_rule_id(finding: Vulnerability) -> str:
    if finding.rule_id:
        return finding.rule_id
    compact_cwe = finding.cwe_id.replace("-", "")
    return f"VSH-{compact_cwe}-GENERIC"


def _build_fix_suggestion(finding: Vulnerability) -> str:
    suggestions = {
        "CWE-79": "innerHTML 대신 textContent 또는 안전한 escaping 적용",
        "CWE-89": "사용자 입력을 문자열 포매팅하지 말고 parameterized query 사용",
        "CWE-22": "상대 경로 입력을 정규화하고 허용 경로만 접근",
        "CWE-78": "쉘 명령 조합 대신 안전한 인자 전달 방식 사용",
        "CWE-798": "하드코딩된 비밀값을 제거하고 환경변수/비밀 저장소 사용",
        "CWE-829": "안전한 버전 기준으로 의존성 업그레이드",
        "CWE-1104": "오타 또는 비정상 패키지명을 검토하고 정식 패키지로 교체",
    }
    return suggestions.get(finding.cwe_id, "L2 분석 결과를 바탕으로 안전한 구현으로 수정")


def _build_end_column(code_snippet: str) -> int:
    return max(1, len(code_snippet.strip()) or len(code_snippet) or 1)


def _normalize_vuln_record(finding: Vulnerability, index: int) -> VulnRecord:
    return VulnRecord(
        vuln_id=_gen_vuln_id(index),
        rule_id=_build_rule_id(finding),
        source="L1",
        detected_at=_now_iso(),
        file_path=finding.file_path or "<unknown>",
        line_number=finding.line_number,
        end_line_number=finding.line_number,
        column_number=1,
        end_column_number=_build_end_column(finding.code_snippet),
        language=_guess_language(finding.file_path or ""),
        vuln_type=_vuln_type_from_finding(finding),
        cwe_id=finding.cwe_id,
        cve_id=finding.metadata.get("cve_id"),
        severity=finding.severity,
        # 공통 스키마 규칙에 따라 L1 정규화 결과는 reachability를 항상 unknown으로 기록한다.
        reachability_status="unknown",
        reachability_confidence="low",
        kisa_ref=KISA_MAPPING.get(finding.cwe_id, "미매핑-추후보강"),
        fss_ref=finding.metadata.get("fss_ref"),
        owasp_ref=OWASP_MAPPING.get(finding.cwe_id),
        evidence=finding.code_snippet,
        fix_suggestion=_build_fix_suggestion(finding),
        status="pending",
        action_at=None,
    )


def _guess_language(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    if suffix in {".js", ".jsx", ".mjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    return "python"


def _normalize_package_records(findings: list[Vulnerability]) -> list[PackageRecord]:
    records: list[PackageRecord] = []
    seen: set[str] = set()

    for finding in findings:
        if finding.cwe_id != "CWE-829":
            continue

        package_name, package_version = parse_requirement_line(finding.code_snippet)
        if not package_name:
            continue
        package_id = _build_package_id("L1", "PyPI", package_name, package_version or "unknown")
        if package_id in seen:
            continue
        seen.add(package_id)
        records.append(
            PackageRecord(
                package_id=package_id,
                source="L1",
                detected_at=_now_iso(),
                name=package_name,
                version=package_version or "unknown",
                ecosystem="PyPI",
                cve_id=finding.metadata.get("cve_id"),
                severity=finding.severity,
                cvss_score=finding.metadata.get("cvss_score"),
                license=finding.metadata.get("license"),
                license_risk=bool(finding.metadata.get("license_risk", False)),
                status="upgrade_required",
                fix_suggestion=_build_fix_suggestion(finding),
                evidence=f"{finding.file_path}: {finding.code_snippet}" if finding.file_path else finding.code_snippet,
            )
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
