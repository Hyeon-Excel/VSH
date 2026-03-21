# L3 Cold Path — VSH (Vibe Coding Secure Helper)

> 팀: 분위기 지켜 | 담당: Lucas | 브랜치: `L3-dev`

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
