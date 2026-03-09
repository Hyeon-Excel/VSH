"""
공통 취약점 스키마 — L3 팀 공유 스키마 기반 (VulnRecord / PackageRecord)
L1/L2/L3 결과를 Shared Log DB에 저장할 때 사용하는 표준 데이터 형식입니다.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ================================================================== #
# 공통 상수
# ================================================================== #

STATUS_ALLOWED = [
    "pending",        # 개발자 확인 전 (저장 시 기본값)
    "accepted",       # 개발자 수락
    "dismissed",      # 오탐으로 처리
    "poc_verified",   # PoC로 실제 취약점 확인
    "poc_failed",     # PoC 실행 실패
    "poc_skipped",    # 해당 CWE 템플릿 없음
    "scan_error",     # 스캔 자체 실패
]

SEVERITY_ALLOWED = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SOURCE_ALLOWED = ["L1", "L2", "L3_SONARQUBE", "L3_POC", "L3_SBOM"]


def _new_vuln_id() -> str:
    """VSH-YYYYMMDD-XXXXXX 형식의 고유 식별자를 생성합니다."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    return f"VSH-{date_str}-{suffix}"


def _new_pkg_id() -> str:
    """PKG-XXXXXX 형식의 고유 식별자를 생성합니다."""
    return f"PKG-{uuid.uuid4().hex[:6].upper()}"


def _now_iso() -> str:
    """현재 시각을 ISO 8601 형식으로 반환합니다."""
    return datetime.now(timezone.utc).isoformat()


# ================================================================== #
# VulnRecord — 코드 취약점 기록 (L1/L2/L3 공통)
# ================================================================== #

@dataclass
class VulnRecord:
    """
    L1/L2/L3 공통 취약점 기록 스키마.
    Shared Log DB에 저장되는 표준 형식입니다.
    """
    file_path: str
    line_number: int
    vuln_type: str
    cwe_id: str
    severity: str                    # "CRITICAL"/"HIGH"/"MEDIUM"/"LOW" 만 허용
    cvss_score: float                # 참고용 수치, severity 판단에 사용 금지
    reachability: bool
    kisa_ref: str                    # null 비허용, 항상 값 있어야 함
    fix_suggestion: str

    source: str = "L2"              # "L1"/"L2"/"L3_SONARQUBE"/"L3_POC"
    vuln_id: str = field(default_factory=_new_vuln_id)   # VSH-YYYYMMDD-XXXXXX
    detected_at: str = field(default_factory=_now_iso)   # ISO 8601
    status: str = "pending"
    cve_id: Optional[str] = None    # 없으면 null
    fss_ref: Optional[str] = None   # null 허용, 빈 문자열("") 사용 금지
    owasp_ref: Optional[str] = None
    action_at: Optional[str] = None  # Accept/Dismiss 시점, 그 전까지 null

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ALLOWED:
            raise ValueError(
                f"severity '{self.severity}'는 허용되지 않습니다. "
                f"허용값: {SEVERITY_ALLOWED}"
            )
        if self.status not in STATUS_ALLOWED:
            raise ValueError(
                f"status '{self.status}'는 허용되지 않습니다. "
                f"허용값: {STATUS_ALLOWED}"
            )
        if self.source not in SOURCE_ALLOWED:
            raise ValueError(
                f"source '{self.source}'는 허용되지 않습니다. "
                f"허용값: {SOURCE_ALLOWED}"
            )
        # fss_ref 빈 문자열 금지
        if self.fss_ref is not None and self.fss_ref == "":
            raise ValueError("fss_ref에 빈 문자열은 허용되지 않습니다. null을 사용하세요.")
        if self.owasp_ref is not None and self.owasp_ref == "":
            raise ValueError("owasp_ref에 빈 문자열은 허용되지 않습니다. null을 사용하세요.")

    def to_dict(self) -> dict:
        return {
            "vuln_id":       self.vuln_id,
            "source":        self.source,
            "detected_at":   self.detected_at,
            "file_path":     self.file_path,
            "line_number":   self.line_number,
            "vuln_type":     self.vuln_type,
            "cwe_id":        self.cwe_id,
            "cve_id":        self.cve_id,
            "severity":      self.severity,
            "cvss_score":    self.cvss_score,
            "reachability":  self.reachability,
            "kisa_ref":      self.kisa_ref,
            "fss_ref":       self.fss_ref,
            "owasp_ref":     self.owasp_ref,
            "fix_suggestion": self.fix_suggestion,
            "status":        self.status,
            "action_at":     self.action_at,
        }


# ================================================================== #
# PackageRecord — SBOM 라이브러리 기록 (L3_SBOM 전용)
# ================================================================== #

@dataclass
class PackageRecord:
    """
    L3_SBOM 전용 패키지 기록 스키마.
    """
    name: str
    version: str
    ecosystem: str                   # "PyPI" / "npm" 등
    license: str
    license_risk: bool

    source: str = "L3_SBOM"         # 고정
    package_id: str = field(default_factory=_new_pkg_id)  # PKG-XXXXXX
    detected_at: str = field(default_factory=_now_iso)
    status: str = "safe"            # "safe"/"upgrade_required"/"license_violation"
    cve_id: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    fix_suggestion: Optional[str] = None

    _PACKAGE_STATUS_ALLOWED = ["safe", "upgrade_required", "license_violation"]

    def __post_init__(self) -> None:
        if self.status not in self._PACKAGE_STATUS_ALLOWED:
            raise ValueError(
                f"status '{self.status}'는 허용되지 않습니다. "
                f"허용값: {self._PACKAGE_STATUS_ALLOWED}"
            )
        if self.severity is not None and self.severity not in SEVERITY_ALLOWED:
            raise ValueError(
                f"severity '{self.severity}'는 허용되지 않습니다. "
                f"허용값: {SEVERITY_ALLOWED}"
            )

    def to_dict(self) -> dict:
        return {
            "package_id":    self.package_id,
            "source":        self.source,
            "detected_at":   self.detected_at,
            "name":          self.name,
            "version":       self.version,
            "ecosystem":     self.ecosystem,
            "cve_id":        self.cve_id,
            "severity":      self.severity,
            "cvss_score":    self.cvss_score,
            "license":       self.license,
            "license_risk":  self.license_risk,
            "status":        self.status,
            "fix_suggestion": self.fix_suggestion,
        }
