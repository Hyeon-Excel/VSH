# VSH L3 — 코드 작성 규칙
# 이 파일은 Gemini CLI가 코드 생성 시 항상 참조한다

---

## R1. 추상화 강제 (ABC)

모든 provider는 반드시 `AbstractXxxProvider`를 상속한다.
추상 메서드 미구현 시 `TypeError` 발생이 보장되어야 한다.
```python
# ✅ 올바른 구조
from abc import ABC, abstractmethod

class AbstractSonarQubeProvider(ABC):
    @abstractmethod
    async def scan(self, project_path: str) -> list[VulnRecord]:
        pass
```

---

## R2. DI 패턴 — pipeline.py에서 구체 클래스 직접 import 금지
```python
# ❌ 금지
from l3.providers.sonarqube.mock import MockSonarQubeProvider

# ✅ 허용 — 추상 타입으로만 받음
class L3Pipeline:
    def __init__(
        self,
        sonarqube: AbstractSonarQubeProvider,
        sbom: AbstractSBOMProvider,
        poc: AbstractPoCProvider,
        normalizer: L3Normalizer
    ):
```

구체 클래스 주입은 `mcp_server.py`에서만 한다.

---

## R3. severity enum — cvss_score 파생 절대 금지

허용값: `"CRITICAL"` | `"HIGH"` | `"MEDIUM"` | `"LOW"`
```python
# ❌ 금지 — cvss_score로 자동 계산
if cvss_score >= 9.0:
    severity = "CRITICAL"

# ✅ 호출자가 명시적으로 지정
VulnRecord(..., cvss_score=9.8, severity="CRITICAL", ...)
```

`cvss_score`는 참고용 필드일 뿐, severity와 독립적이다.

---

## R4. fss_ref 빈 문자열 금지

`fss_ref`: null 허용 / 빈 문자열(`""`) 불허
`__post_init__`에서 자동 변환한다.
```python
def __post_init__(self):
    if self.fss_ref == "":
        self.fss_ref = None
```

---

## R5. status 허용값

### VulnRecord status (7개 외 사용 금지)
```python
allowed_status = {
    "pending",      # 탐지 초기 상태 — 저장 시 기본값
    "accepted",     # 개발자가 취약점 확인 후 수락
    "dismissed",    # 개발자가 Dismiss 선택
    "poc_verified", # PoC 성공 — 실제 공격 가능 확인
    "poc_failed",   # PoC 실행했으나 공격 불가
    "poc_skipped",  # Docker 미설치 등으로 PoC 건너뜀
    "scan_error"    # 스캔 자체 실패
}
```

### PackageRecord status (3개 외 사용 금지)
```python
allowed_status = {
    "safe",             # 취약점 없음
    "upgrade_required", # 업그레이드 필요
    "license_violation" # 라이선스 정책 위반
}
```

### 공통 규칙
- VulnRecord 저장 시 기본값은 항상 `"pending"`
- `action_at`은 `accepted` / `dismissed` 전까지 `None`

---

## R6. PackageRecord → LLM 우회

저장 경로: `M2 SBOM → pipeline.py → M4 Normalizer → Shared DB`
LLM 호출 없음. M2에서 직접 M4로.
```python
# pipeline.py 내
package_records = await self.sbom.scan(file_path)
for pkg in package_records:
    await self.normalizer.save(pkg)  # LLM 거치지 않음
```

---

## R7. PoC — exploit 코드 DB 저장 금지

저장 대상: 실행 결과(성공/실패) + 해석 텍스트만
저장 금지: `get_exploit_code()`가 반환하는 코드 문자열 자체

---

## R8. M4 Normalizer — 예외 처리 원칙

단일 레코드 실패가 파이프라인 전체를 중단시키지 않는다.
```python
async def save(self, record) -> None:
    try:
        await self.db.write(record)
    except Exception:
        if hasattr(record, "status"):
            record.status = "scan_error"
        try:
            await self.db.write(record)
        except Exception as e:
            print(f"[L3 Normalizer] 저장 최종 실패: {e}")
            # 파이프라인 중단 없이 계속 진행
```

---

## R9. Mock/Real 인터페이스 일치

Mock과 Real은 동일한 메서드 시그니처를 유지한다.
ABC 상속이 이를 강제한다.
```python
# Mock과 Real 모두 동일한 시그니처
async def scan(self, project_path: str) -> list[VulnRecord]: ...
```

---

## R10. source 고정값 규칙

| 클래스 | source 값 |
|--------|-----------|
| SonarQube provider | `"L3_SONARQUBE"` |
| PoC provider | `"L3_POC"` |
| SBOM provider | `"L3_SBOM"` (고정, 변경 불가) |

---

## R11. Reachability 판정 기준

SonarQube flows.locations가 2개 이상일 때만 `True`.
flows 없으면 `None` (미확인). `False`로 내리지 않는다.
```python
def _parse_reachability(self, issue: dict) -> Optional[bool]:
    flows = issue.get("flows", [])
    if not flows:
        return None
    return True if any(
        len(flow.get("locations", [])) >= 2 for flow in flows
    ) else None
```

---

## R12. Gemini API 사용 제한

- PoC 템플릿 생성에 사용 금지
- 허용: ①CWE ID 기반 템플릿 선택, ②실행 결과 해석
- PoC 템플릿은 `poc_templates/` 폴더 사전 작성 파일로만 관리