# VSH — Vibe Secure Helper

**AI 기반 보안 취약점 자동 탐지 및 수정 제안 도구**

VSH는 개발자가 코드를 작성하는 동안 보안 취약점을 실시간으로 탐지하고, LLM(Google Gemini / Anthropic Claude)을 통해 수정 코드를 자동 생성하는 MCP(Model Context Protocol) 서버입니다. Claude IDE / Cursor와 통합하여 사용할 수 있습니다.

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **L1 스캔** | 패턴 매칭(CWE), AST 파싱(Tree-sitter), 의존성 취약점(SBOM) |
| **L2 분석** | Gemini / Claude API를 이용한 취약점 검증 및 수정 코드 생성 |
| **MCP 도구** | Claude IDE에서 `validate_code`, `scan_only`, `apply_fix` 등 직접 호출 |
| **대시보드** | 웹 UI(`localhost:3000`)에서 탐지 결과 확인 및 수락/기각 처리 |
| **KISA 연동** | 국내 KISA 보안 가이드라인 기반 패턴 및 수정 지침 적용 |

---

## 아키텍처

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Interface (MCP / Claude IDE)               │
│  tools/server.py — validate_code, scan_only, ...     │
├─────────────────────────────────────────────────────┤
│  Layer 2: Orchestration (Pipeline)                   │
│  pipeline/analysis_pipeline.py                       │
├─────────────────────────────────────────────────────┤
│  Layer 3: Execution                                  │
│  modules/scanner/   — MockSemgrep, TreeSitter, SBOM │
│  modules/analyzer/  — GeminiAnalyzer, ClaudeAnalyzer │
├─────────────────────────────────────────────────────┤
│  Layer 4: Data (Repository Pattern)                  │
│  repository/ — knowledge_repo, fix_repo, log_repo    │
├─────────────────────────────────────────────────────┤
│  Layer 5: Domain Models                              │
│  models/ — ScanResult, Vulnerability, FixSuggestion  │
└─────────────────────────────────────────────────────┘
```

**분석 흐름:**
```
코드 파일
  → [L1] 스캐너 3종 병렬 실행 (패턴 / AST / 의존성)
  → 취약점 중복 제거 (CWE-ID + 라인번호 기준)
  → [L2] LLM 검증 & 수정 코드 생성
  → log.json 저장 (status: pending)
  → 대시보드 또는 MCP 도구로 결과 반환
```

---

## 디렉토리 구조

```
VSH_Final/
├── models/              # 도메인 모델 (ScanResult, Vulnerability, FixSuggestion)
├── modules/
│   ├── scanner/         # 스캐너 3종 (패턴, AST, SBOM)
│   └── analyzer/        # LLM 분석기 (Gemini, Claude)
├── pipeline/            # 파이프라인 오케스트레이터
├── repository/          # 데이터 접근 레이어
├── mock_db/
│   ├── knowledge.json   # CWE 패턴 DB
│   ├── kisa_fix.json    # KISA 수정 지침
│   └── log.json         # 분석 결과 로그
├── dashboard/           # FastAPI 웹 대시보드
├── tools/server.py      # MCP 도구 등록
├── mcp_server_unified.py  # 통합 MCP 서버 엔트리포인트
├── config.py            # 설정 상수
└── .env                 # 환경 변수 (API 키 등)
```

---

## 설치 방법

### 1. 가상환경 설정

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 2. 의존성 설치

```bash
pip install -r requirements.txt
```

### 3. 환경 변수 설정

`.env` 파일을 생성하고 아래 내용을 입력하세요.

```env
# LLM 설정 (gemini 또는 claude)
LLM_PROVIDER=gemini

# API 키 (하나 이상 필수)
GEMINI_API_KEY=your_gemini_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key

# 경로 설정
LOG_PATH=mock_db/log.json
KNOWLEDGE_PATH=mock_db/knowledge.json
FIX_PATH=mock_db/kisa_fix.json

# 대시보드 포트
DASHBOARD_PORT=3000
```

---

## 실행 방법

### MCP 서버 (Claude IDE / Cursor 연동)

```bash
python mcp_server_unified.py
```

Claude IDE 설정에서 이 서버를 MCP 서버로 등록하면, 다음 도구를 직접 호출할 수 있습니다.

| MCP 도구 | 기능 |
|----------|------|
| `validate_code` | 파일 스캔 + LLM 분석 전체 실행 |
| `scan_only` | L1 스캔만 실행 |
| `get_results` | 저장된 분석 결과 조회 |
| `apply_fix` | 수정 코드 파일에 적용 |
| `dismiss_issue` | 이슈 기각 처리 |
| `get_log` | 분석 로그 확인 |

### 대시보드 (웹 UI)

```bash
cd dashboard
uvicorn app:app --host 0.0.0.0 --port 3000
```

브라우저에서 `http://localhost:3000` 접속 후 탐지된 취약점 목록 확인 및 수락/기각 처리 가능.

---

## 탐지 가능한 취약점 유형

| CWE ID | 취약점 유형 |
|--------|------------|
| CWE-78 | OS 명령어 인젝션 |
| CWE-89 | SQL 인젝션 |
| CWE-22 | 경로 순회 (Path Traversal) |
| CWE-94 | 코드 인젝션 (`eval`, `exec`) |
| CWE-319 | 평문 전송 (HTTP 사용) |
| CWE-798 | 하드코딩된 자격증명 |
| CWE-502 | 안전하지 않은 역직렬화 (`pickle`) |
| SBOM | 의존성 패키지 알려진 취약점 (CVE) |

---

## 기술 스택

- **런타임**: Python 3.10+
- **LLM**: Google Gemini API, Anthropic Claude API
- **스캐닝**: Tree-sitter (AST), Regex 패턴 매칭, SBOM 분석
- **웹 서버**: FastAPI + Uvicorn
- **MCP**: fastmcp
- **데이터 모델**: Pydantic
- **테스트**: pytest



## 라이선스

본 프로젝트는 학술/연구 목적으로 개발되었습니다.
