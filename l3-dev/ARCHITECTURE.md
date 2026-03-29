# VSH L3 — 아키텍처 + 데이터 흐름
# 기반: PRD v3.1

---

## 전체 시스템에서 L3의 위치
```
L1 → Shared Log RAG DB ← L3 (읽기: M5 리포트 생성 시)
L2 → Shared Log RAG DB
L3 → Shared Log RAG DB (쓰기: M4 Normalizer)
                ↓
         M5 Report Generator
```

L3는 L1/L2와 병렬 동작. L1/L2 출력을 직접 받지 않는다.

---

## FastMCP Tool 구조
```
Cursor / Claude (클라이언트)
        ↓ MCP 프로토콜
   mcp_server.py (FastMCP 서버)
        ├── validate_code()     ← L1/L2 담당 (기존, 변경 없음)
        ├── trigger_l3_scan()   ← L3 스캔 트리거 (신규)
        └── generate_report()  ← L3 리포트 생성 (신규)
```

| Tool | 처리 방식 | 이유 |
|------|-----------|------|
| `validate_code` | await 직접 반환 | 즉시 피드백 필요 |
| `trigger_l3_scan` | asyncio.create_task 후 즉시 반환 | 수십 초 소요, 블로킹 불가 |
| `generate_report` | await 직접 반환 | 집계+포맷팅만이라 빠름 |

---

## l3-dev/ 파일 구조
```
l3-dev/
├── GEMINI.md               ← Gemini CLI 컨텍스트 (자동 로드)
├── RULES.md                ← 코드 작성 규칙
├── TASK.md                 ← Sprint 태스크
├── ARCHITECTURE.md         ← 이 파일
├── DB_SCHEMA.md            ← 스키마 상세
├── TROUBLESHOOTING.md      ← 에러 기록
├── CHANGELOG.md            ← 완료 기록
│
├── mcp_server.py           ← FastMCP 진입점 (Week 4에 MVP로 이동)
│
├── l3/
│   ├── __init__.py
│   ├── mock_shared_db.py   ← 개발/테스트 전용 Mock DB
│   ├── schema.py           ← VulnRecord / PackageRecord
│   ├── pipeline.py         ← Orchestrator (M1→M2→M3→M4)
│   ├── normalizer.py       ← M4: 스키마 검증 + DB 저장
│   ├── report_generator.py ← M5: MD/JSON 리포트 생성
│   └── providers/
│       ├── base.py         ← 추상 클래스 4개
│       ├── sonarqube/
│       │   ├── mock.py     ← Week 1
│       │   └── real.py     ← Week 3 교체
│       ├── sbom/
│       │   ├── mock.py     ← Week 1
│       │   └── real.py     ← Week 2 교체
│       └── poc/
│           ├── mock.py     ← Week 1
│           └── real.py     ← Week 4 교체
│
├── poc_templates/
│   ├── registry.py         ← CWE ID → 템플릿 클래스 매핑
│   └── cwe_89_sqli.py      ← SQLi 템플릿 (MVP 유일)
│
└── tests/
    ├── test_schema.py
    ├── test_week1_e2e.py
    ├── test_week2_sbom.py
    ├── test_week3_sonarqube.py
    └── test_week4_poc.py
```

---

## L3 모듈 역할 분담

| 모듈 | 역할 | 핵심 제약 |
|------|------|-----------|
| M1 SonarQube | 전체 프로젝트 SAST + Reachability | taint flow 2개 이상 = True |
| M2 SBOM | 공급망 취약점 + 라이선스 | LLM 우회, M4 직접 |
| M3 PoC | Docker 격리 환경에서 공격 가능성 증명 | SQLi 한정, exploit 코드 DB 저장 금지 |
| M4 Normalizer | 스키마 검증 + Shared DB 저장 | 실패해도 파이프라인 계속 |
| M5 Report | L1/L2/L3 집계 + MD/JSON 출력 | 새 분석/LLM 재판단 금지 |

---

## 데이터 흐름

### M3 PoC 처리 흐름
```
pipeline.py가 Shared DB에서 VulnRecord 읽기
        ↓
[Gemini API 1회] CWE ID → TEMPLATE_REGISTRY에서 템플릿 선택
        ↓
Docker 컨테이너 격리 실행
  --network none / --read-only / --no-new-privileges
  --memory 256m / timeout=30s
        ↓
실행 결과 수신 (EXPLOIT_SUCCESS / EXPLOIT_FAILED / timeout)
        ↓
[Gemini API 2회] 실행 결과 해석 → 자연어 설명
        ↓
VulnRecord status 업데이트 → M4
```

### Mock → Real 교체 방식
```python
# mcp_server.py — 이 한 줄만 변경
# Week 1
sonarqube=MockSonarQubeProvider()
# Week 3
sonarqube=RealSonarQubeProvider()
```

---

## Week 4 통합 시 MVP 복사 대상
```
l3-dev/l3/          → vsh/l3/
l3-dev/mcp_server.py → vsh/mcp_server.py (Tool 2개 추가만)
poc_templates/       → vsh/poc_templates/
shared_db.py (신규)  → vsh/shared_db.py