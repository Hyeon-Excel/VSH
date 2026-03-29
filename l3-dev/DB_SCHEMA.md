# VSH L3 — DB 스키마
# 기반: 원본 JSON 예시 (정본) + PRD v3.1 참조
# 최종 확정: 2026-03-09

---

## VulnRecord (코드 취약점)
```python
@dataclass
class VulnRecord:
    # 식별 정보
    vuln_id: str                  # (예: "VSH-20260303-001")
    source: str                   # "L1"|"L2"|"L3_SONARQUBE"|"L3_POC"
    detected_at: str              # ISO 8601 (예: "2026-03-03T14:21:00")

    # 취약점 위치
    file_path: str                # (예: "static/js/main.js")
    line_number: int
    code_snippet: str             # 취약 코드 원문

    # 취약점 분류
    vuln_type: str                # (예: "XSS", "SQLi")
    cwe_id: str                   # (예: "CWE-79")
    cve_id: Optional[str]         # (예: "CVE-2022-25858"), 없으면 None
    cvss_score: float             # 0.0~10.0, 참고용만 — severity 산출 금지
    severity: str                 # "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"

    # 컴플라이언스
    kisa_ref: str                 # 필수, null 불허 (예: "입력데이터 검증 및 표현 3항")
    fss_ref: Optional[str]        # null 허용, ""(빈 문자열) 불허 → None 자동 변환
    owasp_ref: Optional[str]      # (예: "A03:2021")

    # 분석 결과
    reachability: Optional[bool]  # True: 도달 가능 / False: 불가 / None: 미확인
    fix_suggestion: Optional[str] # 권장 수정 방법

    # 액션
    status: str                   # 아래 7개 허용값 (기본값: "pending")
    action_at: Optional[str]      # Accept/Dismiss 전까지 None, 이후 ISO 8601

    def __post_init__(self):
        # 1순위: severity 검증
        allowed_severity = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if self.severity not in allowed_severity:
            raise ValueError(f"severity는 {allowed_severity} 중 하나여야 합니다.")
        # 2순위: fss_ref 빈 문자열 방어
        if self.fss_ref == "":
            self.fss_ref = None
        # 3순위: status 검증
        allowed_status = {
            "pending",      # 탐지 초기 상태 (기본값)
            "accepted",     # 개발자가 취약점 확인 후 수락
            "dismissed",    # 개발자가 Dismiss 선택
            "poc_verified", # PoC 실행 성공 — 실제 공격 가능 확인
            "poc_failed",   # PoC 실행했으나 공격 불가
            "poc_skipped",  # Docker 미설치 등으로 PoC 건너뜀
            "scan_error"    # 스캔 자체 실패
        }
        if self.status not in allowed_status:
            raise ValueError(f"status는 {allowed_status} 중 하나여야 합니다.")
```

### severity 규칙
- 허용값: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- **cvss_score에서 절대 파생 금지**
- 호출자가 명시적으로 지정

### reachability 상태표

| 값 | 의미 | 발생 시점 |
|----|------|-----------|
| `True` | 도달 가능 확인 | L2 분석 또는 L3 SonarQube taint flow 확인 |
| `False` | 도달 불가 확인 | L2 또는 L3 분석 결과 |
| `None` | 미확인 | L2 미구현 또는 L3 스캔 전/실패 |

리포트 출력: `None`이면 "❓ 미확인" 표시

### status 허용값 (7개)

| 값 | 의미 | action_at |
|----|------|-----------|
| `pending` | 탐지 초기 상태 — **저장 시 기본값** | None |
| `accepted` | 개발자가 취약점 확인 후 수락 | 수락 시점 ISO 8601 |
| `dismissed` | 개발자가 Dismiss 선택 | Dismiss 시점 ISO 8601 |
| `poc_verified` | PoC 성공 — 실제 공격 가능 확인 | None |
| `poc_failed` | PoC 실행했으나 공격 불가 | None |
| `poc_skipped` | Docker 미설치 등으로 PoC 건너뜀 | None |
| `scan_error` | 스캔 자체 실패 | None |

### __post_init__ 검증 순서
1. severity enum 검증 (가장 치명적)
2. fss_ref 빈 문자열 → None 변환
3. status enum 검증

---

## PackageRecord (SBOM 전용)
```python
@dataclass
class PackageRecord:
    # 식별 정보
    package_id: str               # (예: "PKG-001")
    source: str = "L3_SBOM"      # 고정값, 절대 변경 불가
    detected_at: str              # ISO 8601

    # 패키지 정보
    name: str                     # (예: "PyYAML")
    version: str                  # (예: "5.3.1")
    ecosystem: str                # "PyPI"|"npm"|"Maven" 등

    # 취약점 정보
    cve_id: Optional[str]         # (예: "CVE-2022-1471"), 없으면 None
    severity: str                 # VulnRecord와 동일 enum 규칙
    cvss_score: Optional[float]   # 참고용만

    # 라이선스
    license: Optional[str]        # (예: "MIT", "GPL-3.0")
    license_risk: bool            # 라이선스 위험 여부

    # 조치
    status: str                   # 아래 3개 허용값만
    fix_suggestion: Optional[str] # (예: "6.0.1 이상으로 업그레이드")

    def __post_init__(self):
        allowed_severity = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if self.severity not in allowed_severity:
            raise ValueError(f"severity는 {allowed_severity} 중 하나여야 합니다.")
        allowed_status = {
            "safe",              # 취약점 없음
            "upgrade_required",  # 업그레이드 필요
            "license_violation"  # 라이선스 정책 위반
        }
        if self.status not in allowed_status:
            raise ValueError(f"status는 {allowed_status} 중 하나여야 합니다.")
```

### 핵심 규칙
- `source`는 `"L3_SBOM"` 고정. 변경 불가.
- LLM 우회. `pipeline.py → M4 → Shared DB` 직접 저장.
- `severity`는 VulnRecord와 동일한 enum 규칙.

### status 허용값 (3개)

| 값 | 의미 |
|----|------|
| `safe` | 취약점 없음 |
| `upgrade_required` | 취약 버전 — 업그레이드 필요 |
| `license_violation` | 라이선스 정책 위반 |

---

## AbstractSharedDB 인터페이스
```python
class AbstractSharedDB(ABC):
    @abstractmethod
    async def write(self, record: VulnRecord | PackageRecord) -> None:
        pass

    @abstractmethod
    async def read_all_vuln(self) -> list[VulnRecord]:
        pass

    @abstractmethod
    async def read_all_package(self) -> list[PackageRecord]:
        pass
```

### Week별 구현체

| 주차 | 구현체 | 위치 |
|------|--------|------|
| Week 1~3 | `MockSharedDB` | `mock_shared_db.py` |
| Week 4 통합 | `RealSharedDB` | `vsh/shared_db.py` |