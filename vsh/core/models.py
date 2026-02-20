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
    score: int = 100
    notes: list[str] = Field(default_factory=list)
