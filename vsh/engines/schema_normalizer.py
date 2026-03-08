"""
Schema normalization layer for L1 scanner.

Converts L1 detection results (Finding, DependencyVuln) into standardized
VulnRecord and PackageRecord formats used across L1/L2/L3 layers.
"""

from datetime import datetime
from pathlib import Path
from vsh.core.models import Finding, DependencyVuln, VulnRecord, PackageRecord, ScanResult


# Map Finding types to KISA references (KISA 보안기능별 가이드)
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

# Map CWE to OWASP Top 10 2021
OWASP_MAPPING = {
    "CWE-89": "A03:2021",   # SQL Injection
    "CWE-79": "A03:2021",   # Cross-site Scripting (XSS)
    "CWE-22": "A01:2021",   # Path Traversal
    "CWE-94": "A03:2021",   # Code Injection
    "CWE-95": "A03:2021",   # Improper Neutralization
    "CWE-78": "A03:2021",   # OS Command Injection
    "CWE-798": "A02:2021",  # Hardcoded Credentials
    "CWE-327": "A02:2021",  # Weak Cryptography
    "CWE-328": "A02:2021",  # Weak Hash
    "CWE-330": "A02:2021",  # Weak Random
    "CWE-434": "A04:2021",  # Unrestricted Upload
    "CWE-611": "A03:2021",  # XXE
    "CWE-287": "A07:2021",  # Authentication Bypass
    "CWE-352": "A01:2021",  # CSRF
    "CWE-1104": "A08:2021", # Dependency Vulnerability
}


def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.utcnow().isoformat() + "Z"


def _gen_vuln_id(index: int) -> str:
    """Generate unique vulnerability ID."""
    dt = datetime.utcnow()
    date_str = dt.strftime("%Y%m%d")
    return f"VSH-{date_str}-{index:03d}"


def _get_vuln_type(finding: Finding) -> str:
    """Infer vulnerability type from Finding title or CWE."""
    title_upper = finding.title.upper()
    
    if "XSS" in title_upper or finding.cwe == "CWE-79":
        return "XSS"
    elif "SQL" in title_upper or finding.cwe == "CWE-89":
        return "SQLI"
    elif "PATH" in title_upper or finding.cwe == "CWE-22":
        return "RPATH"
    elif "COMMAND" in title_upper or finding.cwe == "CWE-78":
        return "CMDI"
    elif "XXE" in title_upper or finding.cwe == "CWE-611":
        return "XXE"
    elif "SECRET" in title_upper or finding.cwe == "CWE-798":
        return "HARDCODED_SECRET"
    elif "CRYPTO" in title_upper or finding.cwe == "CWE-327":
        return "WEAK_CRYPTO"
    elif "RANDOM" in title_upper or finding.cwe == "CWE-330":
        return "INSECURE_RANDOM"
    elif "DESERIAL" in title_upper or finding.cwe == "CWE-502":
        return "DESERIALIZATION"
    else:
        return "GENERIC"


def _get_kisa_ref(cwe: str, vuln_type: str) -> str:
    """Get KISA reference from CWE or vuln type."""
    if cwe and cwe in KISA_MAPPING:
        return KISA_MAPPING.get(cwe, "입력데이터 검증 및 표현")
    return KISA_MAPPING.get(vuln_type, "입력데이터 검증 및 표현")


def _get_owasp_ref(cwe: str) -> str | None:
    """Get OWASP Top 10 2021 reference from CWE."""
    return OWASP_MAPPING.get(cwe)


def normalize_finding(finding: Finding, index: int) -> VulnRecord:
    """Convert Finding to VulnRecord with enhanced function-level risk analysis."""
    vuln_type = _get_vuln_type(finding)
    cwe = finding.cwe or "CWE-200"  # Default to info disclosure
    
    # Extract function-level risk information from metadata
    function_risk = None
    safe_alternatives = None
    if hasattr(finding, 'meta') and finding.meta:
        function_risk = finding.meta.get('function_risk')
        safe_alternatives = finding.meta.get('safe_alternatives')
    
    # Enhanced fix suggestion that includes function-level guidance
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


def normalize_dep_vuln(dep_vuln: DependencyVuln, index: int) -> PackageRecord:
    """Convert DependencyVuln to PackageRecord."""
    return PackageRecord(
        package_id=f"PKG-{index:03d}",
        source="L1_OSV",
        detected_at=_now_iso(),
        name=dep_vuln.name,
        version=dep_vuln.version or "unknown",
        ecosystem=dep_vuln.ecosystem,
        cve_id=dep_vuln.vuln_id,
        severity=dep_vuln.severity,
        cvss_score=None,  # OSV doesn't provide CVSS directly
        license=None,
        license_risk=False,
        status="upgrade_required" if dep_vuln.severity in ("CRITICAL", "HIGH") else "ok",
        fix_suggestion=None,
    )


def normalize_sbom_packages(sbom: dict, index_offset: int) -> list[PackageRecord]:
    """Convert SBOM packages to PackageRecords."""
    records: list[PackageRecord] = []
    
    for pkg in sbom.get("packages", []):
        eco = pkg.get("ecosystem", "unknown")
        records.append(PackageRecord(
            package_id=f"PKG-{index_offset + len(records):03d}",
            source="L1_SBOM",
            detected_at=_now_iso(),
            name=pkg.get("name", "unknown"),
            version=pkg.get("version", "unknown"),
            ecosystem=eco,
            cve_id=None,
            severity=None,
            cvss_score=None,
            license=pkg.get("license"),
            license_risk=_is_risky_license(pkg.get("license")),
            status="ok",
            fix_suggestion=None,
        ))
    
    return records


def _is_risky_license(license_name: str | None) -> bool:
    """Check if license poses risk."""
    if not license_name:
        return False
    
    risky = {"GPL", "AGPL", "SSPL"}
    return any(r in license_name.upper() for r in risky)


def normalize_scan_result(result: ScanResult, annotate: bool = False) -> ScanResult:
    """
    Normalize entire ScanResult to include VulnRecord and PackageRecord.
    
    Args:
        result: Raw ScanResult from L1 scanner
        annotate: Whether to include code annotations (requires code_annotator)
    
    Returns:
        Enriched ScanResult with normalized records
    """
    # Normalize findings
    vuln_records: list[VulnRecord] = []
    for i, finding in enumerate(result.findings):
        vuln_records.append(normalize_finding(finding, i + 1))
    
    # Normalize dependency vulnerabilities
    next_pkg_idx = len(vuln_records) + 1
    package_records: list[PackageRecord] = []
    
    for i, dep_vuln in enumerate(result.dep_vulns):
        package_records.append(normalize_dep_vuln(dep_vuln, next_pkg_idx + i))
    
    # Parse SBOM packages (if available)
    next_pkg_idx += len(result.dep_vulns)
    # Note: SBOM data isn't directly in ScanResult, would be added by scanner
    
    result.vuln_records = vuln_records
    result.package_records = package_records
    
    return result
