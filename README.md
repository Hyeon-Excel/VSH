# L3 Cold Path — VSH (Vibe Coding Secure Helper)

> 팀: 분위기 지켜 | 담당: Lucas | 브랜치: `L3-dev`

## 업데이트 사항
## PoC 검증 엔진 (M3)

### 지원 CWE 목록

| CWE | 취약점 유형 | 검증 결과 | 페이로드 출처 |
|-----|-----------|---------|-------------|
| CWE-89 | SQL Injection | poc_verified ✅ | PayloadsAllTheThings/SQL Injection |
| CWE-78 | OS Command Injection | poc_verified ✅ | PayloadsAllTheThings/Command Injection |
| CWE-79 | XSS | poc_verified ✅ | PayloadsAllTheThings/XSS Injection |

---

### 구조 개요

페이로드 공급과 검증이 분리된 구조입니다.

```
template_registry.py     페이로드 공급
  FILE_MAP: CWE ID → PayloadsAllTheThings 파일 경로
  자동 필터링: 빈 줄, 주석(#) 제거
  기본값: 앞 50개 사용

Docker PoC (vsh-poc-target)     검증 실행
  app.py: CWE ID 기반 Dispatcher
  routes/sqli.py: CWE-89 SQLi 검증
  routes/cmdi.py: CWE-78 Command Injection 검증
  routes/xss.py:  CWE-79 XSS 패턴 매칭 검증
```

통신 프로토콜: `stdin → "CWE-ID|페이로드"` 한 줄 전송

---

### Docker 이미지 빌드

최초 1회 또는 routes 파일 변경 시 재빌드가 필요합니다.

```powershell
docker build -t vsh-poc-target l3\providers\poc\docker\
```

---

### 새 CWE 추가 방법

CWE 하나를 추가할 때 수정하는 파일은 총 3개입니다.
`pipeline.py`, `mcp_server.py`, `real.py`는 수정하지 않습니다.

**Step 1 — 페이로드 파일 추가**

PayloadsAllTheThings 레포에서 해당 CWE의 페이로드 파일을 확인하고
아래 경로에 넣습니다.

```
l3/providers/poc/payloads/
└── 폴더명/
    └── Intruder/
        └── 파일명.txt
```

**Step 2 — template_registry.py FILE_MAP 한 줄 추가**

```python
# l3/providers/poc/template_registry.py

FILE_MAP = {
    "CWE-89": "SQL Injection/Intruder/Auth_Bypass.txt",
    "CWE-78": "Command Injection/Intruder/command_exec.txt",
    "CWE-79": "XSS Injection/Intruders/IntrudersXSS.txt",
    "CWE-22": "Path Traversal/Intruder/path_traversal.txt",  # 추가
}
```

**Step 3 — docker/routes/새파일.py 작성**

검증 함수 하나만 구현합니다.
반환값은 `bool`입니다. `True`면 VULNERABLE, `False`면 SAFE.
모든 예외는 내부에서 처리하고 `False`를 반환합니다.

```python
# l3/providers/poc/docker/routes/ptrav.py 예시

import os

def check_ptrav(payload: str) -> bool:
    try:
        base_dir = "/tmp/safe"
        target = os.path.normpath(os.path.join(base_dir, payload))
        if not target.startswith(base_dir):
            return True
        return False
    except Exception:
        return False
```

**Step 4 — docker/app.py DISPATCHER 등록**

```python
# l3/providers/poc/docker/app.py

from routes.ptrav import check_ptrav  # import 추가

DISPATCHER = {
    "CWE-89": ...,
    "CWE-78": ...,
    "CWE-79": ...,
    "CWE-22": check_ptrav,            # 한 줄 추가
}
```

**Step 5 — Docker 이미지 재빌드**

```powershell
docker build -t vsh-poc-target l3\providers\poc\docker\
```

**Step 6 — 검증**

```powershell
python -m e2e.test_l3_e2e_real
```

CWE ID가 탐지되면 자동으로 template_registry에서 페이로드를 로딩하고
Docker Dispatcher가 해당 검증 함수를 실행합니다.

---

### 페이로드 필터링 규칙

`template_registry.py`의 `load()` 메서드는 아래 순서로 필터링합니다.

```
1. 빈 줄 제거
2. #으로 시작하는 주석 줄 제거
3. 앞 50개만 사용 (max_payloads=50)
```

`max_payloads` 값은 `load()` 호출 시 변경 가능합니다.

```python
TemplateRegistry.load("CWE-89", max_payloads=30)
```

---

### 주의사항

```
Docker 이미지 재빌드를 빠뜨리면
새로 추가한 routes 파일이 컨테이너 안에 없어서
DISPATCHER 분기가 동작하지 않습니다.

routes 파일을 수정하거나 추가한 경우
반드시 재빌드 후 테스트하십시오.
```
## 개요

CWE-89(SQLi)만 poc_verified 가능하던 구조를
CWE-78(CmdI), CWE-79(XSS)까지 확장했습니다.
페이로드 공급과 검증 로직이 분리된 반자동화 구조입니다.

---

## 변경 배경

기존 문제:
- `PAYLOAD_MAP`에 페이로드를 직접 하드코딩 (3~5개)
- CWE 추가 시 페이로드 조사 + 코드 작성 1~2시간 소요
- Docker가 CWE ID를 모르고 무조건 SQLi 검증만 실행
- CWE-78/79 페이로드가 들어와도 항상 SAFE 반환

---

## 변경 내용

### template_registry.py — 페이로드 공급 반자동화

| 항목 | 변경 전 | 변경 후 |
|------|--------|--------|
| 페이로드 출처 | 코드에 하드코딩 | PayloadsAllTheThings 파일 |
| 지원 CWE | CWE-89 | CWE-89 / CWE-78 / CWE-79 |
| 페이로드 수 | 3~5개 | 최대 50개 |
| 네트워크 의존 | 런타임 GitHub 다운로드 | 완전 로컬 오프라인 |
| 새 CWE 추가 | 직접 작성 | FILE_MAP 한 줄 |

### Docker Dispatcher — CWE별 검증 분기

| 항목 | 변경 전 | 변경 후 |
|------|--------|--------|
| 통신 프로토콜 | `payload` | `CWE-ID\|payload` |
| 검증 분기 | 무조건 sqli.py | CWE ID 기반 Dispatcher |
| 신규 파일 | 없음 | routes/cmdi.py, routes/xss.py |

---

## 테스트 결과

```
단독 검증:
  CWE-89: poc_verified ✅
  CWE-78: poc_verified ✅
  CWE-79: poc_verified ✅

pytest:
  106/106 PASSED (회귀 없음)
```

---

## 수정된 파일 목록

```
수정:
  l3/providers/poc/template_registry.py
  l3/providers/poc/docker/app.py
  l3/providers/poc/real.py
  tests/test_week4_poc.py

신규:
  l3/providers/poc/docker/routes/cmdi.py
  l3/providers/poc/docker/routes/xss.py
  l3/providers/poc/payloads/XSS Injection/Intruders/IntrudersXSS.txt
  l3/providers/poc/payloads/Command Injection/Intruder/command_exec.txt
  tests/test_template_registry.py
  vuln_sample.py
  e2e/test_vuln.py
```

---

## 팀 통합 시 참고사항

L3는 독립 레이어로 동작합니다.
팀 통합 시 `mcp_server.py`에서 아래 한 줄만 교체하면 됩니다.

```python
# 변경 전
from l3.mock_shared_db import MockSharedDB

# 변경 후
from l3.real_shared_db import RealSharedDB
```


# L3 전체 내용


## 한 줄 요약

개발자가 코딩하는 동안 백그라운드에서 SonarQube + SBOM + PoC 를 실행하고,
감사(Audit) 및 컴플라이언스 제출에 사용할 수 있는 증거 기반 보안 리포트를 생성하는 레이어.

---

## 전체 시스템에서 L3 의 위치
```
개발자  →  Ctrl+S 저장
              │
         FastMCP 진입점
              │
    ┌─────────┴──────────────────┐
    │ 직렬                        │ 병렬 (완전 독립)
    ↓                             ↓
L1 Hot Path                  L3 Cold Path  ← 이 레포
Semgrep + Tree-sitter         SonarQube + SBOM + PoC
    │
L2 Warm Path
Claude API + RAG
    │                             │
    └──────────┬──────────────────┘
               ↓
         Shared Log DB
               ↓  (리포트 생성 시)
          최종 보안 리포트
```

- L1 → L2 는 직렬 연결
- L3 는 L1/L2 와 **완전 독립 병렬 실행**
- 세 레이어 결과는 **리포트 생성 시점에만 합산**

---

## 현재 완성도 (2026.03)

| 컴포넌트 | 상태 | 비고 |
|---------|------|------|
| SonarQube Provider | ✅ 완료 | Real 연동 |
| SBOM Provider | ✅ 완료 | syft + OSV API |
| PoC Provider | ✅ 완료 | Docker 샌드박스 |
| 리포트 생성 | ✅ 완료 | poc_verified 상세 블록 포함 |
| 단위 테스트 | ✅ 완료 | 88/88 통과 |
| SharedDB | ⏳ Mock | MVP 통합 시 Real 교체 예정 |

---

## 디렉토리 구조
```
l3-dev/
├── mcp_server.py              # 진입점. Provider 등록. 여기만 수정.
├── pipeline.py                # 파이프라인 제어. 절대 수정 금지.
│
├── l3/
│   ├── providers/
│   │   ├── sonarqube/
│   │   │   ├── base.py        # Abstract 클래스
│   │   │   ├── mock.py        # Mock 구현체
│   │   │   └── real.py        # Real 구현체 (SonarQube Cloud)
│   │   ├── sbom/              # 동일 구조
│   │   ├── poc/               # 동일 구조
│   │   └── shared_db/         # 동일 구조
│   │
│   ├── models/
│   │   └── schema.py          # VulnRecord, PackageRecord
│   │
│   └── report/
│       └── generator.py       # 리포트 생성
│
└── tests/
    └── *.py                   # 88개 단위 테스트
```

---

## 실행 방법

### 환경 세팅
```bash
pip install -r requirements.txt
```

`.env` 파일 생성:
```
SONARQUBE_TOKEN=...
SONARQUBE_ORG=...
SONARQUBE_PROJECT_KEY=...
GEMINI_API_KEY=...
```

Docker Desktop 실행 확인 (PoC 에 필요)

syft 설치 확인 (SBOM 에 필요):
```bash
winget install anchore.syft
```

### 실행
```bash
python mcp_server.py --file <스캔할_파일_절대경로>
```

### 테스트
```bash
# 1단계: 스키마 검증 (의존성 없음)
pytest tests/test_schema.py -v

# 2단계: Mock 단위 테스트 (외부 도구 불필요)
pytest -k "mock" -v

# 3단계: Real 단위 테스트 (Docker, syft, SonarQube 필요)
pytest -k "real" -v

# 전체
pytest
```

> **주의**: `test_week1_e2e.py` 실패는 버그가 아님.
> Mock 환경 기준으로 작성된 파일이 Real Provider 와 불일치하는 의도된 상태.
> MVP 통합 시 재작성 예정.

---

## 현재 Provider 구성
```python
# mcp_server.py
sonarqube = RealSonarQubeProvider(llm=GeminiAdapter())  # ✅ Real
sbom      = RealSBOMProvider()                          # ✅ Real
poc       = RealPoCProvider(llm=GeminiAdapter())        # ✅ Real
shared_db = MockSharedDB()                              # ⏳ MVP 통합 후 교체
```

**Mock ↔ Real 전환은 `mcp_server.py` import 한 줄만 바꾸면 된다.**
`pipeline.py` 는 절대 건드리지 않는다.

---

## MVP 통합 방법 (팀원용)

### 팀 공용 mcp_server.py 에 추가할 내용
```python
# 1. import 추가
from l3.providers.sonarqube.real import RealSonarQubeProvider
from l3.providers.sbom.real import RealSBOMProvider
from l3.providers.poc.real import RealPoCProvider
from l3.llm.gemini_adapter import GeminiAdapter
from l3.pipeline import L3Pipeline

# 2. L3 파이프라인 생성 (팀 공용 shared_db 인스턴스 주입)
l3_pipeline = L3Pipeline(
    sonarqube=RealSonarQubeProvider(llm=GeminiAdapter()),
    sbom=RealSBOMProvider(),
    poc=RealPoCProvider(llm=GeminiAdapter()),
    shared_db=shared_db    # ← L1/L2 와 동일한 인스턴스
)

# 3. 기존 validate_code 툴에 L3 백그라운드 실행 추가
@mcp.tool()
async def validate_code(file_path: str) -> dict:
    # L1/L2 기존 로직 (수정 없음)
    l1_result = await l1_pipeline.run(file_path)
    if l1_result:
        l2_result = await l2_pipeline.run(l1_result)

    # L3 백그라운드 실행 (기다리지 않음 — 분 단위 작업)
    asyncio.create_task(l3_pipeline.run(file_path))

    return l2_result
```

### L3 가 팀에 요구하는 것 (계약)

SharedDB 가 아래 세 메서드만 구현하면 L3 내부는 수정할 필요 없다.
```python
async def save_vuln(self, record: VulnRecord) -> None: ...
async def save_package(self, record: PackageRecord) -> None: ...
async def get_all(self) -> dict: ...
```

---

## 스키마 핵심 규칙

위반 시 `__post_init__` 에서 `ValueError` 발생.

| 규칙 | 내용 |
|------|------|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` 만 허용 |
| `severity` 계산 | `cvss_score` 로 자동 계산 **절대 금지** |
| `kisa_ref` | null 불허. 항상 값 있어야 함 |
| `fss_ref` | null 허용. 빈 문자열 `""` 입력 시 자동으로 null 변환 |
| `cvss_score` | MVP 에서는 None 고정 |
| `status` 초기값 | 저장 시점은 항상 `"pending"` |
| `source` (VulnRecord) | `L1` / `L2` / `L3_SONARQUBE` / `L3_POC` 만 허용 |

---

## 절대 건드리면 안 되는 것들

| 금지 | 이유 |
|------|------|
| `pipeline.py` 수정 | 인터페이스 계약. 건드리면 88개 테스트 전부 영향 |
| `scan()` 시그니처 변경 | Mock/Real 양쪽 모두 깨짐 |
| `severity` 를 `cvss_score` 로 계산 | 스키마 위반 |
| LLM 에게 exploit 코드 생성 요청 | 보안 원칙 위반. LLM 은 CWE 분류 + PoC 템플릿 선택만 |

---

## 알려진 사항

- **SonarQube `_wait_for_analysis()`**: 이전 스캔 결과를 현재 결과로 잘못 인식하는 버그 수정 완료
- **SonarQube `_fetch_issues()`**: deprecated `statuses` 파라미터로 인해 VULNERABILITY 타입이 필터링되던 버그 수정 완료
- **PoC Docker 통신**: `--network none` 으로 HTTP 불가. stdin/stdout 으로만 통신
- **Windows 경로**: `_to_docker_path()` 로 자동 변환 (`C:\Users\...` → `/c/Users/...`)
- **SonarQube 인증**: Bearer 아님. `HTTPBasicAuth(token, "")` 사용
