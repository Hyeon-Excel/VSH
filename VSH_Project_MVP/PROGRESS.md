# PROGRESS.md — 개발 진행 상태

## 현재 단계: 프로젝트 완료 (Post-MVP 준비)

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
| 7 | Dashboard | 완료 | 260225 |
| 8 | E2E 테스트 | 완료 | 260225 |

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
- [x] localhost:3000 접속 확인
- [x] 분석 결과 화면 표시 확인
- [x] Accept 클릭 → 상태 업데이트 및 코드 복사 확인
- [x] Dismiss 클릭 → 로그 기록 확인

### Step 8 — E2E 테스트
- [x] 취약한 파일 → 대시보드 결과 → Accept → 코드 복사 (수동 검증 완료)
- [x] 수정된 파일 재스캔 → 핵심 취약점 제거 확인 (CWE-89, CWE-798)
- [x] log.json 전체 이력 기록 및 자동화 스크립트 통과 확인

---

## 이슈 및 결정 사항 로그

| 날짜 | 내용 |
|------|------|
| 250225 | 아키텍처 설계 확정 (기능+레이어 혼합, OOP 원칙 적용) |
| 250225 | MVP 지원 언어: Python (Tree-sitter) |
| 250225 | 대시보드 포트: 3000 |
| 250225 | 프로젝트 루트: VSH_Project_MVP |
| 260225 | Step 0 완료: 프로젝트 구조 세팅, 의존성 설치, 레이어별 __init__.py 및 클래스 스켈레톤 작성 |
| 260225 | Step 1 완료: Domain Model 구현 (Pydantic 채택 - 데이터 검증 및 직렬화 용이성) |
| 260225 | Step 2 완료: Repository Layer 구현 및 Mock DB 연동 |
| 260225 | Step 3 완료: L1 Scanner 구현 완료 (Semgrep, Tree-sitter, SBOM) |
| 260225 | Step 4 완료: Analyzer (L2) 구현 및 API 연동 (Gemini API 채택) |
| 260225 | Step 5 완료: Pipeline Layer 구현 (Orchestration 흐름 완성) |
| 260225 | Step 6 완료: MCP 툴 등록 및 Interface Layer 구현 |
| 260225 | Step 7 완료: Dashboard Layer 구현 및 사전 작업 완료 |
| 260225 | Step 8 완료: 전체 시스템 E2E 테스트 및 자동화 검증 완료 |
| 260225 | [결정] E2E 테스트 격리: `tests/e2e_target.py`, `tests/e2e_target_fixed.py` 전용 파일 사용 |
| 260225 | [결정] 테스트 검증 방식: 수동 UI 확인(UX) + `pytest` 자동 스크립트(API/데이터) 병행 |
| 260225 | [이슈] CWE-89 패턴 오탐: `knowledge.json` 정규식이 안전한 바인딩 코드도 매칭. 코드 분리(SQL 분리)로 해결 |
| 260225 | [Post-MVP] google.generativeai → `google.genai` 마이그레이션 (현재 패키지 지원 종료 상태) |
| 260225 | [Post-MVP] SBOMScanner 결과 경로 개선, SQLiteLogRepo 도입, diff 뷰어 추가 예정 |
