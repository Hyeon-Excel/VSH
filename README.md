
# VSH L3 Cold Path 구현 완료 보고서

## 1. 개요

| 항목        | 내용                       |
| --------- | ------------------------ |
| 담당자       | Lucas                    |
| 브랜치       | `L3-dev`                 |
|           |                          |
| 개발 기간     | 2026년 2월 ~ 3월 (Week 1~4) |
| 최종 pytest | 91/91 PASSED, Warning 0개 |

**L3 Cold Path란?** VSH 시스템에서 Lucas가 전담하는 레이어입니다. L1(실시간 패턴 탐지), L2(LLM 판단)와 완전히 독립적으로 백그라운드에서 실행되며, 더 깊고 정밀한 보안 분석을 담당합니다. 개발자가 파일을 저장하는 순간 자동으로 실행되고 결과를 Shared Log DB에 저장합니다. 최종 보안 리포트 생성 시점에 L1/L2 결과와 합쳐집니다.

---

## 2. L3 아키텍처

```
[트리거] Ctrl+S 파일 저장 이벤트
         ↓
[진입점] mcp_server.py → scan_project(project_path)
         ↓
[L3 파이프라인] pipeline.py
    │
    ├── M1: SonarQube Cloud SAST 스캔
    │       전체 프로젝트를 정적 분석하여 취약점 탐지
    │       결과: VulnRecord 목록 생성
    │
    ├── M2: SBOM 스캔 (syft + OSV API)
    │       프로젝트 의존 패키지 전체를 분석
    │       CVE 데이터베이스와 대조하여 취약 패키지 탐지
    │       결과: PackageRecord 즉시 DB 저장 (LLM 우회)
    │
    ├── M3: PoC Docker 샌드박스 검증
    │       M1이 탐지한 취약점이 실제 공격 가능한지 검증
    │       격리된 Docker 컨테이너에서 페이로드 실행
    │       결과: VulnRecord status 업데이트
    │         - poc_verified: 실제 공격 성공 (진짜 취약점)
    │         - poc_failed: 공격 실패 (오탐 가능성)
    │         - poc_skipped: 해당 CWE 템플릿 없음
    │         - scan_error: 실행 중 오류
    │
    └── M4: Normalizer → MockSharedDB 저장
            모든 결과를 Shared Log DB에 저장
            L1/L2 결과와 리포트 생성 시점에 합쳐짐
         ↓
[리포트] L3ReportGenerator → reports/vsh_report_*.md 생성
```

**L1/L2와의 관계**

```
L1 Hot Path  ─────────────────────────────┐
L2 Warm Path ─────────────────────────────┤→ 리포트 생성 시 합산
L3 Cold Path ─ 독립 실행 (병렬) ──────────┘
```

L3는 L1/L2로부터 직접 데이터를 전달받지 않습니다. L3는 저장된 파일을 직접 스캔하고 결과를 Shared Log DB에 독립적으로 저장합니다. 단, 리포트 생성 시점에 L1/L2가 Shared DB에 저장한 결과를 LLM이 함께 참고하여 최종 보안 리포트를 생성합니다.

---

## 3. 주차별 구현 내역

### Week 1 — 파이프라인 골격 + 스키마 v2.0

**핵심 결정: Mock-First 전략**

모든 컴포넌트를 Mock으로 먼저 구현하고 Real로 교체하는 방식을 채택했습니다. `mcp_server.py`에서 import 한 줄만 바꾸면 Mock → Real 전환이 가능합니다. `pipeline.py`는 Mock/Real 여부를 모르고 항상 동일하게 동작합니다.

**구현 내용**

- VulnRecord, PackageRecord 스키마 설계 (`__post_init__` 검증 포함)
- L3Pipeline, L3Normalizer, L3ReportGenerator 골격
- AbstractSonarQubeProvider, AbstractSBOMProvider, AbstractPoCProvider ABC 설계
- 모든 Provider Mock 구현
- pytest 40개 PASSED

**스키마 핵심 규칙** (반드시 숙지)

- `severity`는 `cvss_score`로 자동 계산 금지 — 상위 레이어가 판단한 값을 그대로 사용
- `kisa_ref`는 `None` 불가 — 항상 값이 있어야 함
- `fss_ref`는 빈 문자열 입력 시 자동으로 `None`으로 변환
- `status` 저장 시 기본값은 항상 `"pending"`

---

### Week 2 — SBOM 실제 구현

**구현 내용**

- syft 1.42.1 CLI로 프로젝트 패키지 스캔
- OSV querybatch API로 취약 패키지 1차 필터링
- OSV vulns/{id} API로 취약점 상세 조회
- PackageRecord 생성 및 반환
- pytest 53개 PASSED (누적)

**핵심 결정사항**

- `cvss_score`는 `None` 고정 — OSV API의 score 필드가 숫자가 아닌 벡터 문자열이라 사용 불가
- `severity`는 OSV의 `database_specific.severity` 텍스트 기반으로 결정

---

### Week 3 — SonarQube Cloud 연동 + LLM 어댑터

**핵심 결정: 로컬 Docker SonarQube → SonarCloud로 전환**

처음에는 로컬 Docker로 SonarQube를 실행하려 했으나 두 가지 문제로 포기했습니다.

- WSL2가 8834~10147 포트 구간을 대량 예약해서 9000, 9100 포트 사용 불가
- SonarQube 컨테이너가 메모리 70~90% 점유 → 다른 작업 불가

SonarCloud(sonarcloud.io) API로 전환하여 해결했습니다.

**LLM 어댑터 모듈 (l3/llm/)**

SonarQube는 규칙 ID(`python:S3649`)만 반환하고 CWE ID는 별도로 조회해야 합니다. LLM이 규칙 ID와 이슈 메시지를 보고 CWE ID를 분류합니다.

```python
# ClaudeAdapter 또는 GeminiAdapter로 교체 가능
# mcp_server.py에서 import 한 줄만 변경
from l3.llm.gemini_adapter import GeminiAdapter  # 현재 사용
sonarqube = RealSonarQubeProvider(llm=GeminiAdapter())
```

**LLM 역할 제한** — CWE 분류와 PoC 템플릿 선택만 담당. exploit 코드 생성 절대 금지.

**SonarQube 인증 주의사항**

```python
# Bearer 토큰 아님 — HTTPBasicAuth 사용
auth = HTTPBasicAuth(sonar_token, "")
```

- pytest 86개 PASSED (누적)

---

### Week 4 — PoC Docker 샌드박스

**PoC가 왜 필요한가?**

SonarQube가 취약점을 탐지했더라도 실제로 공격 가능한지는 별도 검증이 필요합니다. False positive(오탐)를 걸러내는 역할입니다.

**Docker 샌드박스를 쓰는 이유**

악성 페이로드를 실행하므로 호스트 시스템을 보호해야 합니다. `--network none`으로 네트워크를 완전 차단하고 `--cap-drop ALL`로 커널 권한을 제거합니다.

**통신 방식**

HTTP 대신 stdin/stdout으로 통신합니다. `--network none`이라 HTTP 포트 바인딩이 불가능하기 때문입니다.

```
호스트 → stdin으로 페이로드 전송
컨테이너 → stdout으로 결과 반환 ("VULNERABLE" 또는 "SAFE")
```

**현재 MVP 범위**

- SQLi(CWE-89)만 지원
- 페이로드: `' OR '1'='1`
- 타깃 앱: Flask + SQLite 인메모리

**확장 포인트** (나중에 이 메서드 내부만 교체)

```python
def _select_template(self, cwe_id):
    # 나중에 LLM 호출로 교체 예정
    return TEMPLATE_MAP.get(cwe_id)

def _load_payloads(self, template_name):
    # 나중에 template_registry.load()로 교체 예정
    return PAYLOAD_MAP.get(template_name, [])
```

- pytest 91개 PASSED (누적)

---

## 4. 파일 구조 상세

```
l3-dev/
├── mcp_server.py
│   FastMCP 진입점. Mock → Real 교체가 일어나는 유일한 파일.
│   Provider 인스턴스를 생성하고 pipeline에 주입(DI)함.
│   이 파일에서만 import를 변경하면 됨.
│
├── e2e/
│   pytest가 아닌 직접 실행하는 E2E 테스트 스크립트 모음.
│   ├── test_l3_e2e.py        Phase 1-A: Mock SonarQube로 빠른 동작 확인
│   ├── test_l3_e2e_real.py   Phase 1-B: Real SonarQube 전체 파이프라인
│   ├── test_poc_verified.py  poc_verified 단독 확인용
│   └── test_vuln.py          SonarQube 스캔용 취약 코드 샘플
│
├── l3/
│   ├── models/
│   │   ├── vuln_record.py
│   │   │   코드 취약점 레코드. __post_init__에서 7가지 검증 수행.
│   │   │   source 허용값: L1, L2, L3_SONARQUBE, L3_POC
│   │   │   status 허용값: pending, accepted, dismissed,
│   │   │                  poc_verified, poc_failed, poc_skipped, scan_error
│   │   └── package_record.py
│   │       패키지 취약점 레코드.
│   │       source: L3_SBOM 고정
│   │       status 허용값: safe, upgrade_required, license_violation
│   │
│   ├── schema.py
│   │   VulnRecord, PackageRecord를 외부로 재export하는 편의 모듈.
│   │
│   ├── providers/
│   │   ├── base.py
│   │   │   모든 Provider의 Abstract 클래스 정의.
│   │   │   이 파일을 기반으로 mock.py와 real.py가 동일한 인터페이스를 구현.
│   │   │
│   │   ├── sonarqube/
│   │   │   ├── mock.py  CWE-89 VulnRecord 1건을 하드코딩으로 반환
│   │   │   └── real.py  SonarQube Cloud API 실제 연동 ✅
│   │   │       - _health_check(): API 상태 확인
│   │   │       - _ensure_project(): 프로젝트 등록 (이미 있으면 skip)
│   │   │       - _run_scanner(): Docker로 sonar-scanner-cli 실행
│   │   │       - _wait_for_analysis(): 분석 완료 polling
│   │   │       - _fetch_issues(): 이슈 목록 조회
│   │   │       - _build_vuln_record(): 이슈 → VulnRecord 변환
│   │   │
│   │   ├── sbom/
│   │   │   ├── mock.py  PyYAML 5.3.1 PackageRecord 1건을 하드코딩으로 반환
│   │   │   └── real.py  syft + OSV API 실제 연동 ✅
│   │   │       현재 mcp_server.py에서는 Mock 사용 중
│   │   │       Real로 교체 시: MockSBOMProvider → RealSBOMProvider
│   │   │
│   │   └── poc/
│   │       ├── mock.py  항상 poc_verified를 반환하는 Mock
│   │       ├── real.py  Docker 샌드박스 실제 구현 ✅
│   │       │   - _select_template(): CWE ID → 템플릿명 선택
│   │       │   - _load_payloads(): 템플릿명 → 페이로드 목록 반환
│   │       │   - _run_poc(): Docker 실행 + stdin/stdout 통신
│   │       │   - verify(): 전체 흐름 조립
│   │       └── docker/
│   │           Flask SQLi 타깃 앱. --network none 환경에서 동작.
│   │           ├── Dockerfile
│   │           ├── app.py      READY 신호 → 페이로드 수신 → 결과 출력
│   │           └── routes/
│   │               └── sqli.py SQLi 취약 쿼리 실행 로직
│   │
│   ├── llm/
│   │   ├── base.py            LLMAdapter ABC (classify_cwe 추상 메서드)
│   │   ├── claude_adapter.py  Claude API 사용 (anthropic 패키지)
│   │   └── gemini_adapter.py  Gemini API 사용 (google.genai 패키지) ✅ 현재 사용
│   │
│   ├── pipeline.py
│   │   ⚠️ 절대 수정 금지.
│   │   M1→M2→M3→M4 흐름을 조립하는 파일.
│   │   Provider 구현체를 모르고 Abstract 인터페이스에만 의존.
│   │   수정하면 DI 패턴이 무너지고 Mock/Real 교체가 불가능해짐.
│   │
│   ├── normalizer.py
│   │   M4: VulnRecord, PackageRecord를 Shared DB에 저장.
│   │
│   ├── report_generator.py
│   │   DB에서 결과를 읽어 VSH 보안 진단 리포트(MD)를 생성.
│   │   reports/ 폴더에 vsh_report_YYYYMMDD_HHMMSS.md로 저장.
│   │   (reports/ 폴더는 .gitignore에 포함됨)
│   │
│   └── mock_shared_db.py
│       인메모리 DB. 현재 L3 단독 실행 시 사용.
│       팀 통합 시 RealSharedDB로 교체 예정.
│       mcp_server.py에서 import 한 줄만 바꾸면 됨.
│
└── tests/
    pytest로 실행하는 단위 테스트 모음. 91개 전부 PASSED.
    ├── test_models.py            14개 — 스키마 검증 테스트
    ├── test_schema.py            23개 — 허용값 검증 테스트
    ├── test_week1_e2e.py          3개 — 파이프라인 통합 테스트
    ├── test_week2_sbom.py        13개 — SBOM real.py 테스트
    ├── test_week3_llm_adapter.py  8개 — LLM 어댑터 테스트
    ├── test_week3_sonarqube.py   25개 — SonarQube real.py 테스트
    └── test_week4_poc.py          5개 — PoC real.py 테스트
```

---

## 5. 현재 mcp_server.py 설정 상태

```python
from l3.providers.sonarqube.real import RealSonarQubeProvider  # Real ✅
from l3.providers.sbom.mock import MockSBOMProvider             # Mock (syft 미설치 환경 대비)
from l3.providers.poc.real import RealPoCProvider               # Real ✅
from l3.llm.gemini_adapter import GeminiAdapter                 # Gemini ✅
from l3.mock_shared_db import MockSharedDB                      # Mock (팀 통합 전)

sonarqube = RealSonarQubeProvider(llm=GeminiAdapter())
sbom      = MockSBOMProvider()
poc       = RealPoCProvider(llm=GeminiAdapter())
db        = MockSharedDB()
```

**SBOM이 아직 Mock인 이유** syft CLI가 설치되어 있어야 Real SBOM이 동작합니다. 팀원 환경에 syft가 없을 수 있어서 안전하게 Mock으로 유지했습니다. Real로 교체하려면 syft를 설치하고 import만 변경하면 됩니다.

**MockSharedDB인 이유** L1/L2 팀원 코드와 통합 전까지는 인메모리 DB를 사용합니다. 통합 시 RealSharedDB로 교체합니다.

---

## 6. 실행 방법

### 사전 준비

**[1] `.env` 파일 생성 (루트에)**

```
SONAR_TOKEN=<SonarCloud Project Analysis Token>
SONAR_URL=https://sonarcloud.io
SONAR_ORG=vsh-project
SONAR_PROJECT_KEY=vsh-project
GEMINI_API_KEY=<Gemini API Key>
```

**SONAR_TOKEN 발급 주의사항** 일반 User Token이 아닌 **Project Analysis Token**이 필요합니다.

- SonarCloud → `vsh-project` → Administration → Analysis Method → Manually → 토큰 발급
- User Token으로는 JRE 다운로드 API(403)와 프로젝트 생성 API(401) 권한이 부족합니다.

**[2] Docker PoC 이미지 빌드**

```powershell
docker build -t vsh-poc-target l3/providers/poc/docker/
```

PoC 검증 시 Docker가 실행 중이어야 합니다. Docker Desktop이 꺼져있으면 `scan_error`가 발생합니다.

**[3] 의존성 설치**

```powershell
pip install -r requirements.txt
```

---

### E2E 테스트 실행

**Phase 1-A — Mock SonarQube (빠른 확인, 30초 이내)**

Real SonarQube 없이도 전체 파이프라인 동작을 확인할 수 있습니다. MockSonarQubeProvider가 CWE-89 VulnRecord를 반환하고 Docker PoC가 실제로 실행됩니다.

```powershell
cd C:\Users\LG\Desktop\VSH_Project\l3-dev
python e2e/test_l3_e2e.py
```

기대 결과:

```
✅ VSH-20260309-TEST0001 | cwe=CWE-89 | poc_verified
📦 PyYAML 5.3.1 | upgrade_required
리포트 생성 완료
```

**Phase 1-B — Real SonarQube (실제 스캔, 3~5분 소요)**

실제 SonarCloud가 프로젝트를 스캔합니다. `.env` 설정이 완료되어 있어야 합니다.

```powershell
python e2e/test_l3_e2e_real.py
```

기대 결과:

```
SonarQube 이슈 탐지 → Gemini CWE 분류 → VulnRecord DB 저장 → 리포트 생성
```

**poc_verified 단독 확인**

```powershell
python e2e/test_poc_verified.py
```

---

### pytest 단위 테스트 실행

```powershell
pytest tests/ -v
```

기대 결과: 91/91 PASSED, Warning 0개

---

## 7. E2E 테스트 결과 상세

### Phase 1-A 결과 (Mock SonarQube + Real PoC)

```
M1 MockSonarQube → CWE-89 VulnRecord 1건 생성
M2 MockSBOM      → PyYAML 5.3.1 PackageRecord 1건 생성
M3 Real PoC      → Docker 컨테이너 실행
                   ' OR '1'='1 페이로드 전송
                   VULNERABLE 감지 → poc_verified
M4 Normalizer    → DB 저장

✅ VSH-20260309-TEST0001 | cwe=CWE-89 | poc_verified
```

### Phase 1-B 결과 (Real SonarQube + Real PoC)

```
M1 RealSonarQube → 프로젝트 스캔 (약 3분)
                   이슈 12건 탐지
                   Gemini가 규칙 ID → CWE ID 변환
                   (CWE-400, CWE-662, CWE-407 등)
M2 MockSBOM      → PyYAML 5.3.1 PackageRecord 1건 생성
M3 Real PoC      → CWE-89 없으므로 전부 poc_skipped
                   (현재 TEMPLATE_MAP에 CWE-89만 있음)
M4 Normalizer    → VulnRecord 12건 DB 저장

⚠️ 12건 전부 poc_skipped인 이유:
   탐지된 이슈들이 "async 함수에서 동기 호출 사용" 관련 이슈라서
   CWE-89(SQLi)가 없음. TEMPLATE_MAP에 CWE-89만 있어서
   나머지 CWE는 템플릿이 없어 poc_skipped 처리됨.
   이건 정상 동작임.
```

---

## 8. 리포트 형식 (실제 출력 예시)

```
🛡️ VSH 보안 진단 리포트
======================================================
진단일시 : 2026-03-18 19:34
진단엔진 : VSH v1.0 (SonarQube + SBOM + PoC Docker)
적용기준 : KISA 시큐어코딩 가이드 | 금융보안원 체크리스트 | OWASP Top 10

📊 종합 보안 점수 : 40 / 100
======================================================
항목                              결과
──────────────────────────────────────────────────────
KISA 시큐어코딩 준수율            14 / 26 항목 (54%)
금융보안원 체크리스트 준수율      8 / 20 항목 (40%)
탐지된 취약점                     12건 (CRITICAL 0, HIGH 0, MEDIUM 12, LOW 0)
Reachability 확인 (실제 위협)     0건
오탐 처리                         0건
사용 라이브러리 총                1개
위험 라이브러리                   1개
라이선스 위반                     없음

🚨 취약점 상세
======================================================
[MEDIUM] Use — l3/providers/sonarqube/real.py 54번 라인
  * CWE          : CWE-400
  * CVSS         : N/A
  * CVE          : N/A
  * Reachability : ❓ 분석 중 (도달 가능성 미확인)
  * 영향 범위    : 추가 분석 필요
  * KISA 근거    : KISA 시큐어코딩 가이드 참조
  * 금융보안원   : N/A
  * OWASP        : N/A
  * 조치         : SonarQube 규칙 python:S7499 참조
  * PoC 검증     : poc_skipped

📦 SBOM 요약 (라이브러리 성분표)
======================================================
라이브러리     버전       CVE                라이선스    상태
──────────────────────────────────────────────────────
PyYAML         5.3.1      CVE-2022-1471      MIT         ❌ 업그레이드 필요

권장 조치 : 위험 라이브러리를 최신 버전으로 업그레이드하세요.

✅ 개발자 조치 내역 (Human-in-the-Loop)
======================================================
개발자 조치 내역이 없습니다.

======================================================
본 리포트는 보조 도구(VSH)에 의해 자동 생성되었으며,
최종 보안 책임은 개발자에게 있습니다.
======================================================
```

---

## 9. 팀 통합 계획

L3는 독립 레이어이므로 팀 코드와 연결할 지점이 명확합니다.

**Step 1 — 인터페이스 합의 (팀 전체)**

- L3 트리거 방식: 파일 저장 시 누가 `scan_project()`를 호출하는가
- Shared Log DB 구조: L1/L2 결과와 L3 결과를 어떻게 합칠 것인가

**Step 2 — MockSharedDB → RealSharedDB 교체**

```python
# mcp_server.py에서 import 한 줄만 변경
from l3.mock_shared_db import MockSharedDB      # 현재
from l3.real_shared_db import RealSharedDB       # 통합 후
```

**Step 3 — MockSBOMProvider → RealSBOMProvider 교체**

```python
from l3.providers.sbom.mock import MockSBOMProvider  # 현재
from l3.providers.sbom.real import RealSBOMProvider  # 교체 시
```

syft 설치 필요: [github.com/anchore/syft](https://github.com/anchore/syft)

---

## 10. 향후 계획

|항목|설명|시점|
|---|---|---|
|Real SBOM 연동|syft 설치 후 MockSBOMProvider → RealSBOMProvider 교체. import 한 줄 변경으로 가능|발표 전|
|CWE-89 실제 탐지|SonarQube `python:S3649` 규칙에 걸리는 SQLi 코드 추가 → Real PoC poc_verified 확인|발표 전|
|MVP 통합|Shared DB 연결, 파일 저장 트리거 연결, 대시보드 연동|팀 전체 작업|
|template_registry 도입|PayloadsAllTheThings/SecLists 페이로드 라이브러리 연동. `_load_payloads()` 내부만 교체|발표 후|

---

## 11. 코드 작성 시 주의사항

아래 규칙을 위반하면 `__post_init__`에서 `ValueError`가 발생합니다.

**절대 금지 사항**

```
pipeline.py 수정 금지
  → DI 패턴의 핵심 파일. 수정하면 Mock/Real 교체가 불가능해짐.

severity를 cvss_score로 계산 금지
  → severity는 상위 레이어가 판단한 값. 재계산하면 리포트 무결성 훼손.

kisa_ref = None 금지
  → 필수 필드. None이면 __post_init__에서 ValueError 발생.

fss_ref = "" (빈 문자열) 금지
  → 빈 문자열은 자동으로 None으로 변환됨. 직접 입력 금지.

verify() 내부에서 예외 raise 금지
  → pipeline.py가 예외를 잡아 poc_skipped로 처리해서
    scan_error와 구분이 불가능해짐.
    내부에서 반드시 처리하고 record 반환.

asyncio.to_thread 없이 subprocess/requests 직접 호출 금지
  → 이벤트 루프가 블로킹되어 다른 비동기 작업이 멈춤.
```

---

팀원분들이 보시기에 궁금한 부분이 있으면 추가 보완하겠습니다.
