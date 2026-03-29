# VSH L3 Cold Path — GEMINI.md
# 기반 문서: PRD v3.1 / 개발 계획서 v1.1
# 개발 도구: Gemini CLI

---

## 프로젝트 개요

VSH(Vibe Coding Secure Helper)의 L3 Cold Path 레이어.
목적: 속도가 아닌 증명. 조직이 보안 심사에 제출하는 법적 증거 문서 생성.

- 트리거: Ctrl+S → FastMCP `trigger_l3_scan()` → 백그라운드 실행
- 출력: MD + JSON 리포트 (KISA / 금융보안원 / OWASP 컴플라이언스 매핑)
- L3는 L1/L2 결과를 직접 받지 않음 → Shared Log RAG DB에서 읽음
- 결과 병합은 M5 리포트 생성 시점에만 발생

---

## 필수 참조 파일

작업 전 반드시 아래 파일을 확인할 것:

| 파일 | 언제 읽는가 |
|------|------------|
| `RULES.md` | 코드 작성 전 항상 |
| `TASK.md` | 세션 시작 시 — 오늘 할 일 확인 |
| `ARCHITECTURE.md` | 새 파일 위치 판단 시 |
| `DB_SCHEMA.md` | VulnRecord/PackageRecord 작성 시 |
| `TROUBLESHOOTING.md` | 에러 발생 시 |

---

## 개발 환경

- Python: 3.13.7
- pytest + pytest-asyncio 설치 완료
- Docker: 설치됨 (Week 3~4 전에 동작 확인 필요)
- syft: Week 2 시작 전 설치 필요
- sonar-scanner: Week 3 시작 전 설치 필요

## 경로 규칙

- 리포트 출력 경로: `l3-dev/reports/`
- 폴더 자동 생성: `os.makedirs("reports", exist_ok=True)`
- vuln_id 포맷: `"VSH-{YYYYMMDD}-{uuid[:8].upper()}"`
  예시: `"VSH-20260309-A1B2C3D4"`
- package_id 포맷: `"PKG-{uuid[:8].upper()}"`
  예시: `"PKG-A1B2C3D4"`

## 로깅 규칙

- print() 방식으로 통일. logging 모듈 사용 금지.
- 형식: `print(f"[L3 모듈명] 메시지")`
- 예시:
  - `print(f"[L3 Normalizer] 저장 실패: {e}")`
  - `print(f"[L3 Pipeline] M1 스캔 완료: {len(results)}건")`
  - `print(f"[L3 PoC] poc_skipped: Docker 미설치")`

--------
## 개발 전략

### Mock-First + DI 패턴
- 모든 provider는 Mock으로 시작 → E2E 먼저 완성
- Mock → Real 교체는 `mcp_server.py` DI 주입부 한 줄만 변경
- 나머지 코드 변경 없음

### 4주 일정
| 주차 | 목표 | Provider 상태 |
|------|------|--------------|
| Week 1 | ABC + Mock E2E | 전부 Mock |
| Week 2 | 실제 SBOM (syft + OSV API) | SBOM Real |
| Week 3 | 실제 SonarQube + Reachability | SBOM + SonarQube Real |
| Week 4 | PoC Docker + FastMCP 통합 | 전부 Real |

---

## 현재 단계

**Week 1 — 추상화 + Mock 파이프라인 E2E**

작업 순서 (TASK.md 참조):
1. `l3/schema.py`
2. `l3/providers/base.py`
3. Mock Provider 3개 + `mock_shared_db.py`
4. `l3/normalizer.py`
5. `l3/pipeline.py`
6. `l3/report_generator.py`
7. `mcp_server.py`
8. `tests/test_schema.py` + `tests/test_week1_e2e.py`

---

## 절대 금지 (RULES.md 상세 참조)
```
❌ severity를 cvss_score에서 자동 계산
❌ fss_ref에 빈 문자열("") 허용
❌ PackageRecord를 LLM에 통과
❌ exploit 코드를 DB에 저장
❌ pipeline.py에서 구체 클래스 직접 import
❌ Mock/Real 메서드 시그니처 불일치
❌ status 허용값(7개) 외 사용
❌ Gemini API로 악성 페이로드 생성
```

---

## Gemini CLI 사용 패턴
```bash
# 세션 시작 시 컨텍스트 확인
/memory show

# 파일 단위 작업 예시
gemini "l3/schema.py의 VulnRecord를 작성해줘.
RULES.md와 DB_SCHEMA.md를 반드시 따를 것."

# 코드 리뷰
gemini "이 코드가 RULES.md를 위반하는지 확인해줘" < l3/normalizer.py

# 컨텍스트 갱신
/memory reload


## 스키마 요약

### VulnRecord 주요 필드

| 필드 | 타입 | 규칙 |
|------|------|------|
| `vuln_id` | str | (예: "VSH-20260303-001") |
| `source` | str | `"L1"` \| `"L2"` \| `"L3_SONARQUBE"` \| `"L3_POC"` |
| `detected_at` | str | ISO 8601 |
| `vuln_type` | str | (예: "XSS", "SQLi") |
| `cve_id` | Optional[str] | 없으면 None |
| `severity` | str | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` |
| `cvss_score` | float | 참고용만 — severity 산출 절대 금지 |
| `kisa_ref` | str | 필수, null 불허 |
| `fss_ref` | Optional[str] | null 허용, `""` 불허 |
| `reachability` | Optional[bool] | `True` / `False` / `None`(미확인) |
| `status` | str | 7개 허용값, 기본값 `"pending"` |
| `action_at` | Optional[str] | accepted/dismissed 시점, 그 전엔 None |

### PackageRecord 주요 필드

| 필드 | 타입 | 규칙 |
|------|------|------|
| `package_id` | str | (예: "PKG-001") |
| `source` | str | 고정값 `"L3_SBOM"` |
| `name` | str | 패키지명 |
| `version` | str | 패키지 버전 |
| `license_risk` | bool | 라이선스 위험 여부 |
| `status` | str | `"safe"` \| `"upgrade_required"` \| `"license_violation"` |
| `fix_suggestion` | Optional[str] | (예: "6.0.1 이상으로 업그레이드") |


