# VSH L3 — Sprint 태스크
# 업데이트: 2026-03-09

---

## 현재 Sprint: Week 1 — 추상화 + Mock E2E

### 완료 기준
모든 Mock provider로 `pipeline.run()` → M1→M2→M3→M4→M5 전체 흐름 동작 확인.
`test_schema.py` + `test_week1_e2e.py` 전부 통과.

---

### 태스크 목록

#### 1단계: 스키마
- [x] `l3/schema.py` — VulnRecord 작성
- [x] `l3/schema.py` — PackageRecord 작성
- [x] `l3/schema.py` — __post_init__ 검증 로직 (severity / fss_ref / status)

#### 2단계: 추상화
- [x] `l3/providers/base.py` — AbstractSonarQubeProvider
- [x] `l3/providers/base.py` — AbstractSBOMProvider
- [x] `l3/providers/base.py` — AbstractPoCProvider
- [x] `l3/providers/base.py` — AbstractSharedDB

#### 3단계: Mock 구현
- [x] `l3/providers/sonarqube/mock.py` — MockSonarQubeProvider
- [x] `l3/providers/sbom/mock.py` — MockSBOMProvider
- [x] `l3/providers/poc/mock.py` — MockPoCProvider
- [x] `mock_shared_db.py` — MockSharedDB

#### 4단계: 핵심 모듈
- [x] `l3/normalizer.py` — L3Normalizer (M4)
- [x] `l3/pipeline.py` — L3Pipeline (DI 패턴, Orchestrator)
- [x] `l3/report_generator.py` — ReportGenerator (M5, MD+JSON)

#### 5단계: 조립
- [x] `mcp_server.py` — DI 주입 + Tool 1개 (scan_project)

#### 6단계: 테스트
- [x] `tests/test_schema.py` — severity/fss_ref/status 검증
- [x] `tests/test_week1_e2e.py` — Mock E2E 전체 흐름

---

### Week 1 완료 체크리스트 (PRD v3.1 기준)

- [x] schema.py __post_init__ 검증 전부 통과
- [x] ABC 미구현 시 TypeError 발생 확인
- [x] DI 패턴: pipeline.py에 구체 클래스 import 없음
- [x] Mock E2E: M1→M2→M3→M4 순서 실행 확인
- [x] PackageRecord LLM 우회 경로 확인
- [x] MD / JSON 리포트 동시 생성 확인
- [x] reachability 필드 리포트 출력 확인
- [x] normalizer 실패 시 scan_error + 파이프라인 계속 진행 확인
- [x] test_schema.py 전체 통과
- [x] test_week1_e2e.py 전체 통과

---

## 다음 Sprint: Week 2 — 실제 SBOM 연동
(Week 1 완료 후 이 섹션을 채울 것)

## Week 3: 실제 SonarQube + Reachability
(대기)

## Week 4: PoC Docker Sandbox + FastMCP 통합
(대기)
