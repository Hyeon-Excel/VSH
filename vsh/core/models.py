from pydantic import BaseModel, Field
from typing import Literal, Optional, Any
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    cve: Optional[str] = None
    file: str
    line: int
    column: int = 1
    message: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    reachability: Optional[Literal["YES","NO","UNKNOWN"]] = "UNKNOWN"
    references: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)

# Normalized schema for L1+ layers
class VulnRecord(BaseModel):
    """Normalized vulnerability record used across L1/L2/L3 layers."""
    vuln_id: str  # VSH-YYYYMMDD-XXX format
    source: Literal["L1", "L2", "L3"] = "L1"
    detected_at: str  # ISO 8601 datetime
    file_path: str
    line_number: int
    vuln_type: str  # "XSS", "SQLI", "RPATH", etc.
    cwe_id: str  # Must not be null
    cve_id: Optional[str] = None
    severity: Severity
    cvss_score: Optional[float] = None
    reachability: bool = False  # true if path is reachable
    kisa_ref: str  # Must not be null; e.g., "입력데이터 검증 및 표현 3항"
    fss_ref: Optional[str] = None  # nullable
    owasp_ref: Optional[str] = None  # e.g., "A03:2021"
    fix_suggestion: Optional[str] = None
    status: Literal["pending", "investigating", "confirmed", "false_positive", "fixed"] = "pending"
    action_at: Optional[str] = None  # ISO 8601 datetime when action was taken

class PackageRecord(BaseModel):
    """Normalized package/dependency record used across L1/L2/L3 layers."""
    package_id: str  # stable package identifier (e.g. PKG-PYPI-requests-2.31.0)
    source: str  # "L1_SBOM", "L1_OSV", "L3_SBOM", etc.
    detected_at: str  # ISO 8601 datetime
    name: str
    version: str
    ecosystem: str  # "PyPI", "npm", etc.
    vuln_id: Optional[str] = None
    cve_id: Optional[str] = None
    advisory_source: Optional[str] = None
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = None
    license: Optional[str] = None
    license_risk: bool = False
    status: Literal["ok", "upgrade_available", "upgrade_required", "end_of_life"] = "ok"
    fix_suggestion: Optional[str] = None

class DependencyVuln(BaseModel):
    ecosystem: str  # PyPI, npm
    name: str
    version: str | None = None
    vuln_id: str | None = None
    summary: str | None = None
    severity: Severity = "MEDIUM"
    references: list[str] = Field(default_factory=list)

class ScanResult(BaseModel):
    project: str
    findings: list[Finding] = Field(default_factory=list)
    dep_vulns: list[DependencyVuln] = Field(default_factory=list)
    hallucinated_packages: list[str] = Field(default_factory=list)
    vuln_records: list[VulnRecord] = Field(default_factory=list)  # L1+ normalized schema
    package_records: list[PackageRecord] = Field(default_factory=list)  # L1+ normalized schema
    annotated_files: dict[str, str] = Field(default_factory=dict)  # file_path -> annotated_content
    typosquatting_packages: list[str] = Field(default_factory=list)  # L1 typosquatting detection
    score: int = 100
    notes: list[str] = Field(default_factory=list)
