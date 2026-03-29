from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class VulnRecord(BaseModel):
    """
    팀 공통 VulnRecord 스키마.

    L1/L2/L3가 공통 필드명으로 취약점 데이터를 교환할 때 사용하는 기준 모델이다.
    """

    vuln_id: str
    rule_id: str
    source: Literal["L1", "L2", "L3_SONARQUBE", "L3_POC"]
    detected_at: str
    file_path: str
    line_number: int = Field(ge=1)
    end_line_number: int = Field(ge=1)
    column_number: int = Field(ge=1)
    end_column_number: int = Field(ge=1)
    language: str
    vuln_type: str
    cwe_id: str
    cve_id: str | None = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cvss_score: float | None = None
    reachability_status: Literal["reachable", "unreachable", "unknown"]
    reachability_confidence: Literal["high", "medium", "low"]
    kisa_ref: str
    fss_ref: str | None = None
    owasp_ref: str | None = None
    evidence: str
    fix_suggestion: str
    detection_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None
    reasoning_verdict: Literal["likely_vulnerable", "suspicious", "not_vulnerable", "needs_review"] | None = None
    risk_score: float | None = None
    final_priority: Literal["P1", "P2", "P3", "P4", "INFO"] | None = None
    status: Literal[
        "pending",
        "accepted",
        "dismissed",
        "poc_verified",
        "poc_failed",
        "poc_skipped",
        "scan_error",
    ] = "pending"
    action_at: str | None = None

    @field_validator("fss_ref", mode="before")
    @classmethod
    def normalize_fss_ref(cls, value: str | None) -> str | None:
        if value == "":
            return None
        return value


class PackageRecord(BaseModel):
    """
    팀 공통 PackageRecord 스키마.

    원본 스키마는 L3 SBOM 중심이지만, 현재 L1-L2 통합 단계에서는 L1 생성값도
    동일 구조로 실험적으로 맞추기 위해 source에 L1을 허용한다.
    """

    package_id: str
    source: Literal["L1", "L3_SBOM"]
    detected_at: str
    name: str
    version: str
    ecosystem: str
    cve_id: str | None = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cvss_score: float | None = None
    license: str | None = None
    license_risk: bool = False
    status: Literal["safe", "upgrade_required", "license_violation"]
    fix_suggestion: str
    evidence: str
    advisory_id: str | None = None
    advisory_source: str | None = None
    affected_module: str | None = None
    affected_symbol: str | None = None
    affected_api_patterns: list[str] = Field(default_factory=list)
    exploitability_hint: str | None = None
    usage_status: Literal["package_present", "package_imported", "vulnerable_api_referenced", "reachable_package_risk", "needs_manual_review"] | None = None
    risk_score: float | None = None
    final_priority: Literal["P1", "P2", "P3", "P4", "INFO"] | None = None
