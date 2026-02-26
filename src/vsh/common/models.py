"""Shared data models for L1/L2/L3 tools."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(str, Enum):
    CODE = "CODE"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"


class ReachabilityHint(str, Enum):
    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"


class ScanMode(str, Enum):
    SNIPPET = "snippet"
    FILE = "file"


class VerificationState(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class ActionType(str, Enum):
    ACCEPT = "ACCEPT"
    DISMISS = "DISMISS"


class BaseStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(BaseStrictModel):
    file_path: str
    start_line: int = Field(ge=1)
    start_col: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_col: int = Field(ge=1)


class Finding(BaseStrictModel):
    id: str
    rule_id: str
    severity: Severity
    category: Category
    location: Location
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    kisa_key: str | None = None
    fsec_key: str | None = None
    message: str
    reachability_hint: ReachabilityHint = ReachabilityHint.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)
    rationale: str | None = None
    recommendation: str | None = None


class VerificationRecord(BaseStrictModel):
    subject: str
    state: VerificationState
    details: str | None = None


class VerificationSummary(BaseStrictModel):
    registry: list[VerificationRecord] = Field(default_factory=list)
    osv: list[VerificationRecord] = Field(default_factory=list)


class ActionLog(BaseStrictModel):
    actor: str
    action: ActionType
    finding_id: str
    timestamp: str
    notes: str | None = None


class SupplyChainCandidate(BaseStrictModel):
    package_name: str
    line: int | None = Field(default=None, ge=1)
    source_type: str = "import"
    extraction_method: str = "tree-sitter"


class L1ScanAnnotateRequest(BaseStrictModel):
    code: str
    language: str
    file_path: str
    mode: ScanMode = ScanMode.SNIPPET


class L1ScanAnnotateResponse(BaseStrictModel):
    findings: list[Finding] = Field(default_factory=list)
    import_candidates: list[SupplyChainCandidate] = Field(default_factory=list)
    annotation_patch: str = ""
    timing_ms: int = 0
    errors: list[str] = Field(default_factory=list)


class L2EnrichFixRequest(BaseStrictModel):
    code: str
    findings: list[Finding] = Field(default_factory=list)
    project_context: dict[str, Any] | None = None


class L2EnrichFixResponse(BaseStrictModel):
    enriched_findings: list[Finding] = Field(default_factory=list)
    fix_patch: str = ""
    verification: VerificationSummary = Field(default_factory=VerificationSummary)
    errors: list[str] = Field(default_factory=list)


class L3FullReportRequest(BaseStrictModel):
    repo_path: str
    baseline_findings: list[Finding] = Field(default_factory=list)
    actions_log: list[ActionLog] = Field(default_factory=list)


class L3FullReportResponse(BaseStrictModel):
    report_md_path: str
    report_json_path: str
    sbom_path: str | None = None
    summary: str = ""
    errors: list[str] = Field(default_factory=list)
