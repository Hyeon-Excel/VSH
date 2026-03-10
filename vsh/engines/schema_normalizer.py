"""
Schema normalization layer for L1 scanner.

Converts L1 detection results (Finding, DependencyVuln) into standardized
VulnRecord and PackageRecord formats used across L1/L2/L3 layers.
"""

from datetime import datetime, timezone

from vsh.core.models import DependencyVuln, Finding, PackageRecord, ScanResult, VulnRecord


KISA_MAPPING = {
    "XSS": "입력데이터 검증 및 표현 3항",
    "SQLI": "입력데이터 검증 및 표현 1항",
    "RPATH": "입력데이터 검증 및 표현 5항",
    "CMDI": "입력데이터 검증 및 표현 4항",
    "XXE": "입력데이터 검증 및 표현 6항",
    "SSRF": "입력데이터 검증 및 표현 2항",
    "CRLS": "암호화 관리 1항",
    "HARDCODED_SECRET": "보안기능 (키 관리) 2항",
    "WEAK_CRYPTO": "암호화 관리 2항",
    "INSECURE_RANDOM": "난수 생성 및 관리",
    "DESERIALIZATION": "직렬화된 객체 처리",
    "PATH_TRAVERSAL": "입력데이터 검증 및 표현 5항",
}

CWE_TO_KISA = {
    "CWE-79": "XSS",
    "CWE-89": "SQLI",
    "CWE-22": "RPATH",
    "CWE-78": "CMDI",
    "CWE-611": "XXE",
    "CWE-327": "WEAK_CRYPTO",
    "CWE-330": "INSECURE_RANDOM",
    "CWE-502": "DESERIALIZATION",
}

OWASP_MAPPING = {
    "CWE-89": "A03:2021",
    "CWE-79": "A03:2021",
    "CWE-22": "A01:2021",
    "CWE-94": "A03:2021",
    "CWE-95": "A03:2021",
    "CWE-78": "A03:2021",
    "CWE-798": "A02:2021",
    "CWE-327": "A02:2021",
    "CWE-328": "A02:2021",
    "CWE-330": "A02:2021",
    "CWE-434": "A04:2021",
    "CWE-611": "A03:2021",
    "CWE-287": "A07:2021",
    "CWE-352": "A01:2021",
    "CWE-1104": "A08:2021",
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


def _split_advisory_id(vuln_id: str | None) -> tuple[str | None, str | None]:
    if not vuln_id:
        return None, None
    if vuln_id.startswith("CVE-"):
        return vuln_id, "CVE"
    if vuln_id.startswith("GHSA-"):
        return None, "GHSA"
    if vuln_id.startswith("PYSEC-"):
        return None, "PYSEC"
    return None, "OSV"


def _get_vuln_type(finding: Finding) -> str:
    title_upper = finding.title.upper()
    if "XSS" in title_upper or finding.cwe == "CWE-79":
        return "XSS"
    if "SQL" in title_upper or finding.cwe == "CWE-89":
        return "SQLI"
    if "PATH" in title_upper or finding.cwe == "CWE-22":
        return "RPATH"
    if "COMMAND" in title_upper or finding.cwe == "CWE-78":
        return "CMDI"
    if "XXE" in title_upper or finding.cwe == "CWE-611":
        return "XXE"
    if "SECRET" in title_upper or finding.cwe == "CWE-798":
        return "HARDCODED_SECRET"
    if "CRYPTO" in title_upper or finding.cwe == "CWE-327":
        return "WEAK_CRYPTO"
    if "RANDOM" in title_upper or finding.cwe == "CWE-330":
        return "INSECURE_RANDOM"
    if "DESERIAL" in title_upper or finding.cwe == "CWE-502":
        return "DESERIALIZATION"
    return "GENERIC"


def _get_kisa_ref(cwe: str, vuln_type: str) -> str:
    mapped = CWE_TO_KISA.get(cwe)
    if mapped:
        return KISA_MAPPING.get(mapped, "입력데이터 검증 및 표현")
    return KISA_MAPPING.get(vuln_type, "입력데이터 검증 및 표현")


def _get_owasp_ref(cwe: str) -> str | None:
    return OWASP_MAPPING.get(cwe)


def normalize_finding(finding: Finding, index: int) -> VulnRecord:
    vuln_type = _get_vuln_type(finding)
    cwe = finding.cwe or "CWE-200"

    function_risk = finding.meta.get("function_risk") if finding.meta else None
    safe_alternatives = finding.meta.get("safe_alternatives") if finding.meta else None

    base_fix = finding.recommendation or ""
    if function_risk and safe_alternatives:
        enhanced_fix = f"{function_risk}\n안전한 대안: {safe_alternatives}"
        if base_fix:
            enhanced_fix += f"\n{base_fix}"
    else:
        enhanced_fix = base_fix

    return VulnRecord(
        vuln_id=_gen_vuln_id(index),
        source="L1",
        detected_at=_now_iso(),
        file_path=finding.file,
        line_number=finding.line,
        vuln_type=vuln_type,
        cwe_id=cwe,
        cve_id=finding.cve,
        severity=finding.severity,
        cvss_score=finding.cvss,
        reachability=(finding.reachability == "YES"),
        kisa_ref=_get_kisa_ref(cwe, vuln_type),
        fss_ref=None,
        owasp_ref=_get_owasp_ref(cwe),
        fix_suggestion=enhanced_fix,
        status="pending",
        action_at=None,
    )


def normalize_dep_vuln(dep_vuln: DependencyVuln, index: int = 1) -> PackageRecord:
    cve_id, advisory_source = _split_advisory_id(dep_vuln.vuln_id)
    return PackageRecord(
        package_id=_build_package_id("OSV", dep_vuln.ecosystem, dep_vuln.name, dep_vuln.version or "unknown"),
        source="L1_OSV",
        detected_at=_now_iso(),
        name=dep_vuln.name,
        version=dep_vuln.version or "unknown",
        ecosystem=dep_vuln.ecosystem,
        vuln_id=dep_vuln.vuln_id,
        cve_id=cve_id,
        advisory_source=advisory_source,
        severity=dep_vuln.severity,
        cvss_score=None,
        license=None,
        license_risk=False,
        status="upgrade_required" if dep_vuln.severity in ("CRITICAL", "HIGH") else "ok",
        fix_suggestion=None,
    )


def normalize_sbom_packages(sbom: dict, index_offset: int) -> list[PackageRecord]:
    records: list[PackageRecord] = []
    for pkg in sbom.get("packages", []):
        eco = pkg.get("ecosystem", "unknown")
        name = pkg.get("name", "unknown")
        version = pkg.get("version", "unknown")
        records.append(
            PackageRecord(
                package_id=_build_package_id("SBOM", eco, name, version),
                source="L1_SBOM",
                detected_at=_now_iso(),
                name=name,
                version=version,
                ecosystem=eco,
                vuln_id=None,
                cve_id=None,
                advisory_source=None,
                severity=None,
                cvss_score=None,
                license=pkg.get("license"),
                license_risk=_is_risky_license(pkg.get("license")),
                status="ok",
                fix_suggestion=None,
            )
        )
    return records


def _is_risky_license(license_name: str | None) -> bool:
    if not license_name:
        return False
    risky = {"GPL", "AGPL", "SSPL"}
    return any(r in license_name.upper() for r in risky)


def _ensure_unique_package_ids(records: list[PackageRecord]) -> list[PackageRecord]:
    counts: dict[str, int] = {}
    for record in records:
        base = record.package_id
        counts[base] = counts.get(base, 0) + 1
        if counts[base] > 1:
            record.package_id = f"{base}-{counts[base]}"
    return records


def normalize_scan_result(result: ScanResult, sbom: dict | None = None) -> ScanResult:
    result.vuln_records = [normalize_finding(finding, i + 1) for i, finding in enumerate(result.findings)]

    package_records: list[PackageRecord] = []
    for i, dep_vuln in enumerate(result.dep_vulns, 1):
        package_records.append(normalize_dep_vuln(dep_vuln, i))

    if sbom:
        package_records.extend(normalize_sbom_packages(sbom, len(package_records) + 1))

    result.package_records = _ensure_unique_package_ids(package_records)
    return result
