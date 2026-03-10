from __future__ import annotations

from typing import Any, Literal, Optional, get_args, get_origin

try:
    from pydantic import BaseModel, Field  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for offline/minimal env
    class _FieldDefault:
        def __init__(self, default: Any = None, default_factory: Any = None):
            self.default = default
            self.default_factory = default_factory

    def Field(default: Any = None, default_factory: Any = None):
        return _FieldDefault(default=default, default_factory=default_factory)

    class BaseModel:
        def __init__(self, **kwargs: Any):
            anns = getattr(self.__class__, "__annotations__", {})
            for key in anns:
                if key in kwargs:
                    value = kwargs[key]
                else:
                    value = getattr(self.__class__, key, None)
                    if isinstance(value, _FieldDefault):
                        value = value.default_factory() if value.default_factory else value.default
                setattr(self, key, value)

            # store extra keys as attributes for compatibility
            for key, value in kwargs.items():
                if key not in anns:
                    setattr(self, key, value)

        def model_dump(self) -> dict[str, Any]:
            anns = getattr(self.__class__, "__annotations__", {})
            return {k: getattr(self, k) for k in anns}


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
    reachability: Optional[Literal["YES", "NO", "UNKNOWN"]] = "UNKNOWN"
    references: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class VulnRecord(BaseModel):
    """Normalized vulnerability record used across L1/L2/L3 layers."""

    vuln_id: str
    source: Literal["L1", "L2", "L3"] = "L1"
    detected_at: str
    file_path: str
    line_number: int
    vuln_type: str
    cwe_id: str
    cve_id: Optional[str] = None
    severity: Severity
    cvss_score: Optional[float] = None
    risk_score: Optional[float] = None
    confidence: Literal["low", "medium", "high"] = "medium"
    reachability: bool = False
    kisa_ref: str
    fss_ref: Optional[str] = None
    owasp_ref: Optional[str] = None
    fix_suggestion: Optional[str] = None
    status: Literal["pending", "investigating", "confirmed", "false_positive", "fixed"] = "pending"
    action_at: Optional[str] = None


class PackageRecord(BaseModel):
    """Normalized package/dependency record used across L1/L2/L3 layers."""

    package_id: str
    source: str
    detected_at: str
    name: str
    version: str
    ecosystem: str
    vuln_id: Optional[str] = None
    cve_id: Optional[str] = None
    advisory_source: Optional[str] = None
    severity: Optional[Severity] = None
    risk_score: Optional[float] = None
    confidence: Literal["low", "medium", "high"] = "medium"
    cvss_score: Optional[float] = None
    license: Optional[str] = None
    license_risk: bool = False
    status: Literal["ok", "upgrade_available", "upgrade_required", "end_of_life"] = "ok"
    fix_suggestion: Optional[str] = None


class DependencyVuln(BaseModel):
    ecosystem: str
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
    vuln_records: list[VulnRecord] = Field(default_factory=list)
    package_records: list[PackageRecord] = Field(default_factory=list)
    annotated_files: dict[str, str] = Field(default_factory=dict)
    typosquatting_packages: list[str] = Field(default_factory=list)
    score: int = 100
    notes: list[str] = Field(default_factory=list)
