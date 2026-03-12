from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class VulnRecord:
    # 식별 정보
    vuln_id: str
    rule_id: str
    source: str
    detected_at: str

    # 취약점 위치
    file_path: str
    line_number: int
    end_line_number: int
    column_number: int
    end_column_number: int
    language: str
    code_snippet: str

    # 취약점 분류
    vuln_type: str
    cwe_id: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    severity: str

    # 리치어빌리티
    reachability_status: str
    reachability_confidence: str

    # 컴플라이언스
    kisa_ref: str
    fss_ref: Optional[str]
    owasp_ref: Optional[str]

    # 분석 결과
    fix_suggestion: str

    # 액션
    status: str = field(default="pending")
    action_at: Optional[str] = field(default=None)

    def __post_init__(self):
        # 1순위 - source 검증
        allowed_sources = {"L1", "L2", "L3_SONARQUBE", "L3_POC"}
        if self.source not in allowed_sources:
            raise ValueError(f"Invalid source: {self.source}")

        # 2순위 - severity 검증
        allowed_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if self.severity not in allowed_severities:
            raise ValueError(f"Invalid severity: {self.severity}")

        # 3순위 - reachability_status 검증
        allowed_reachability_status = {"reachable", "unreachable", "unknown"}
        if self.reachability_status not in allowed_reachability_status:
            raise ValueError(f"Invalid reachability_status: {self.reachability_status}")

        # 4순위 - reachability_confidence 검증
        allowed_reachability_confidence = {"high", "medium", "low"}
        if self.reachability_confidence not in allowed_reachability_confidence:
            raise ValueError(f"Invalid reachability_confidence: {self.reachability_confidence}")

        # 5순위 - kisa_ref None 방어
        if self.kisa_ref is None:
            raise ValueError("kisa_ref must not be None")

        # 6순위 - fss_ref 빈 문자열 정규화
        if self.fss_ref == "":
            self.fss_ref = None

        # 7순위 - status 검증
        allowed_statuses = {
            "pending", "accepted", "dismissed",
            "poc_verified", "poc_failed", "poc_skipped", "scan_error"
        }
        if self.status not in allowed_statuses:
            raise ValueError(f"Invalid status: {self.status}")
