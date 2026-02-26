# PROGRESS.md — 개발 진행 상태

## 현재 단계: Step 7 준비 중

---

## Step 진행 현황

| Step | 내용 | 상태 | 분기점 통과 |
|------|------|------|------------|
| 0 | 프로젝트 세팅 | 완료 | 260225 |
| 1 | Domain Model | 완료 | 260225 |
| 2 | Repository + Mock DB | 완료 | 260225 |
| 3 | Scanner (L1) | 완료 | 260225 |
| 4 | Analyzer (L2) | 완료 | 260225 |
| 5 | Pipeline | 완료 | 260225 |
| 6 | MCP 툴 등록 | 완료 | 260225 |
| 7 | Dashboard | 대기 | - |
| 8 | E2E 테스트 | 대기 | - |

---

## 각 Step 분기점 체크리스트

### Step 0 — 프로젝트 세팅
- [x] 폴더 구조 생성 완료
- [x] pip install 오류 없음 (Semgrep 제외)
- [x] python -c "import fastmcp, anthropic, fastapi" 오류 없음

### Step 1 — Domain Model
- [x] models/ import 오류 없음
- [x] 모델 간 의존성 방향 올바름
- [x] ScanResult, Vulnerability, FixSuggestion 인스턴스 생성 확인

### Step 2 — Repository + Mock DB
- [x] JSON 파일 정상 로드 확인
- [x] MockRepo 인스턴스 생성 오류 없음
- [x] find_by_id(), save() 호출 결과 확인

### Step 3 — Scanner (L1)
- [x] 테스트용 취약 파일로 SemgrepScanner 실행 결과 확인
- [x] TreeSitterScanner Python 파싱 확인
- [x] SBOMScanner requirements.txt 취약 패키지 탐지 확인
- [x] supported_languages() 반환값 확인

### Step 4 — Analyzer (L2)
- [x] L1 결과를 넘겼을 때 Gemini API 응답 확인
- [x] 취약점 판단 결과 파싱 확인 (있음/없음/오탐)
- [x] 수정 제안 코드 생성 확인

### Step 5 — Pipeline
- [x] 취약한 파일 → L1 → L2 흐름 정상 실행
- [x] 아무것도 없는 파일 → clean 반환 확인
- [x] PipelineFactory 인스턴스 생성 확인

### Step 6 — MCP 툴 등록
- [x] mcp_server.py 실행 오류 없음 (Fail Fast 적용)
- [x] scan_file 툴 호출 → 파이프라인 실행 확인
- [x] get_report 툴 호출 → log.json 반환 확인
- [x] update_status 툴 호출 → 상태 변경 및 검증 확인

### Step 7 — Dashboard
- [ ] localhost:3000 접속 확인
- [ ] 분석 결과 화면 표시 확인
- [ ] Accept 클릭 → 파일 수정 확인
- [ ] Dismiss 클릭 → 로그 기록 확인

### Step 8 — E2E 테스트
- [ ] 취약한 파일 → 대시보드 결과 → Accept → 파일 수정
- [ ] 수정된 파일 재스캔 → clean 처리
- [ ] log.json 전체 이력 기록 확인

---

## 이슈 및 결정 사항 로그

| 날짜 | 내용 |
|------|------|
| 250225 | 아키텍처 설계 확정 (기능+레이어 혼합, OOP 원칙 적용) |
| 250225 | MVP 지원 언어: Python (Tree-sitter) |
| 250225 | 대시보드 포트: 3000 |
| 250225 | 프로젝트 루트: VSH_Project_MVP |
| 260225 | Step 0 완료: 프로젝트 구조 세팅, 의존성 설치, 레이어별 __init__.py 및 클래스 스켈레톤 작성 |
| 260225 | Step 1 완료: Domain Model 구현 (Pydantic 채택 - 데이터 검증 및 직렬화 용이성), 다음: Repository + Mock DB |
| 260225 | Step 2 완료: Repository Layer 구현 및 Mock DB 연동 |
| 260225 | [결정] BaseRead/WriteRepository 분리: LSP 위반 방지 및 읽기 전용 데이터의 무결성 보장 |
| 260225 | [결정] find_by_id() 반환값: 항목 부재 시 None 반환 ({} 반환 시 존재 여부 확인 로직 모호성 제거) |
| 260225 | [결정] config.py 추가: 참조 데이터 경로는 상수로 관리하고 런타임 로그 경로만 .env로 관리 |
| 260225 | Step 3 완료: L1 Scanner 구현 완료 (Semgrep, Tree-sitter, SBOM) |
| 260225 | [결정] BaseReadRepository find_all() 추가: Scanner의 패턴 매칭을 위해 전체 보안 규칙 조회가 필수적임 |
| 260225 | [결정] SemgrepScanner Export: Pipeline이 Mock 여부를 몰라도 되도록 MockSemgrepScanner를 SemgrepScanner로 export |
| 260225 | [결정] 예외 처리 방식: 파일 부재/파싱 에러는 빈 ScanResult 반환, 지원하지 않는 언어 입력은 ValueError 발생 |
| 260225 | [결정] SBOMScanner 탐색 범위: requirements.txt는 항상 PROJECT_ROOT 기준으로 고정 탐색 |
| 260225 | Step 4 완료: Analyzer (L2) 구현 및 API 연동 |
| 260225 | [결정] Claude API 키 부재로 기본 Analyzer를 Gemini API로 교체 |
| 260225 | [결정] LLMAnalyzer를 ClaudeAnalyzer로 이름 변경 후 보존 |
| 260225 | [결정] GeminiAnalyzer 추가 및 AnalyzerFactory 구현 (.env LLM_PROVIDER 값으로 동적 선택) |
| 260225 | [결정] 현재 기본값: LLM_PROVIDER=gemini, 추후 claude로 값만 변경 시 교체 완료 |
| 260225 | [이슈] Gemini 모델: gemini-2.5-flash 사용 (gemini-1.5-pro 지정 시 라이브러리 자동 처리 문제) |
| 260225 | [이슈] google-generativeai 지원 종료 경고 발생 → 추후 google-genai 패키지로 마이그레이션 필요 |
| 260225 | Step 5 완료: Pipeline Layer 구현 (Orchestration 흐름 완성) |
| 260225 | [결정] 중복 탐지 문제 해결: `_deduplicate()`를 `@staticmethod`로 선언하여 `cwe_id` + `line_number` 기준으로 중복 제거 |
| 260225 | [결정] run() 반환 타입: 모든 값을 직렬화 가능한 dict 및 리스트 구조로 반환 (도메인 모델 객체 직접 반환 금지) |
| 260225 | [결정] PipelineFactory 의존성 조립: 파이프라인 생성 시 필요한 모든 의존성(Scanner, Analyzer, Repo)을 외부에서 생성 후 주입 (DI 패턴 적용) |
| 260225 | [결정] LogRepo 저장 형식: `issue_id`, `file_path`, `cwe_id`, `severity`, `line_number`, `code_snippet`, `status("pending")` 포함 확정 |
| 260225 | Step 6 완료: MCP 툴 등록 및 Interface Layer 구현 |
| 260225 | [결정] MCP 툴 3개 등록 확정 (`scan_file`, `get_report`, `update_status`) |
| 260225 | [결정] load_dotenv() 호출 순서 확정: `PipelineFactory.create()` 이전에 반드시 호출하여 환경변수 누락 방지 |
| 260225 | [결정] pipeline.log_repo 직접 참조 확정: 툴 호출 간 데이터 일관성 보장을 위해 동일한 인스턴스 공유 |
| 260225 | [결정] 툴 반환 형식 확정: LLM 가독성 및 한글 보존을 위해 `json.dumps(..., ensure_ascii=False, indent=2)` 적용 |
| 260225 | [결정] update_status 존재하지 않는 issue_id 처리: 예외를 던지지 않고 명확한 `error` JSON 응답 반환 |
| 260225 | [결정] L3 추가 확장성 고려: 기존 3개 툴 수정 없이 `generate_report` 툴만 새로 추가하도록 설계 |
| 260225 | [결정] Pipeline Fail Fast 원칙: 초기화 실패 시 예외를 던져 서버가 시작되지 않도록 처리 |
| 260225 | 다음 단계: Step 7 (Dashboard - FastAPI) |
