from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class PackageRecord:
    # 식별 정보
    package_id: str
    detected_at: str

    # 패키지 정보
    name: str
    version: str
    ecosystem: str

    # 취약점 정보
    cve_id: Optional[str]
    severity: str
    cvss_score: Optional[float]

    # 라이선스
    license: Optional[str]
    license_risk: bool

    # 조치
    status: str
    code_snippet: str
    fix_suggestion: str

    # 기본값 있는 필드는 반드시 맨 마지막에 위치
    source: str = field(default="L3_SBOM")

    def __post_init__(self):
        # 1순위 - source 검증
        allowed_sources = {"L3_SBOM"}
        if self.source not in allowed_sources:
            raise ValueError(f"Invalid source: {self.source}")

        # 2순위 - severity 검증
        allowed_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if self.severity not in allowed_severities:
            raise ValueError(f"Invalid severity: {self.severity}")

        # 3순위 - status 검증
        allowed_statuses = {"safe", "upgrade_required", "license_violation"}
        if self.status not in allowed_statuses:
            raise ValueError(f"Invalid status: {self.status}")
