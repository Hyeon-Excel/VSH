# GEMINI.md — Security MCP 프로젝트 컨텍스트

## 프로젝트 개요
Security MCP는 다양한 언어(MVP: Python)의 코드 보안 취약점을 자동 분석하고,
Claude AI가 수정 제안까지 해주는 도구다.
Tree-sitter 라이브러리를 활용한 AST 파싱과 Semgrep 정적 분석을 조합하여
언어에 관계없이 확장 가능한 구조로 설계되었다.

---

## 아키텍처 레이어 구조

Interface Layer     → tools/       (MCP 툴 등록, 위임만 담당)
Orchestration Layer → pipeline/    (L1→L2 흐름 제어)
Execution Layer     → modules/     (실제 스캔/분석 실행)
Data Layer          → repository/  (DB 접근 추상화)
Domain Model        → models/      (데이터 구조 정의)

---

## 폴더 구조

VSH_Project/
├── mcp_server.py
├── tools/
│   ├── analysis_tools.py
│   ├── dashboard_tools.py
│   └── status_tools.py
├── pipeline/
│   ├── base_pipeline.py
│   ├── analysis_pipeline.py
│   └── pipeline_factory.py
├── modules/
│   ├── base_module.py
│   ├── scanner/
│   │   ├── semgrep_scanner.py
│   │   ├── treesitter_scanner.py
│   │   └── sbom_scanner.py
│   └── analyzer/
│       └── llm_analyzer.py
├── repository/
│   ├── base_repository.py
│   ├── knowledge_repo.py
│   ├── fix_repo.py
│   └── log_repo.py
├── models/
│   ├── scan_result.py
│   ├── vulnerability.py
│   └── fix_suggestion.py
├── mock_db/
│   ├── knowledge.json
│   ├── kisa_fix.json
│   └── log.json
└── dashboard/
    ├── app.py
    └── index.html

---

## 설계 원칙 (절대 위반 금지)

1. SRP — 각 클래스/모듈은 하나의 책임만 가진다
2. OCP — 새 기능 추가 시 기존 코드 수정 없이 구현체만 추가한다
3. DIP — 구체 구현이 아닌 추상 클래스에 의존한다
4. 의존성 방향은 항상 위에서 아래로만 흐른다 (역방향 금지)
5. tools/ 는 pipeline/ 에만 의존한다. modules/ 를 직접 호출하지 않는다
6. 모든 반환 타입은 models/ 의 도메인 모델을 사용한다

---

## 확정된 인터페이스 이름 (변경 금지)

### 추상 클래스 메서드
BaseScanner.scan(file_path: str) -> ScanResult
BaseScanner.supported_languages() -> list[str]
BaseRepository.find_by_id(id: str) -> dict
BaseRepository.save(data: dict) -> bool
BasePipeline.run(file_path: str) -> dict

### MCP 툴 이름
validate_code(file_path: str) -> dict
scan_only(file_path: str) -> dict
get_results() -> dict
apply_fix(issue_id: str) -> dict
dismiss_issue(issue_id: str) -> dict
get_log(file_path: str) -> dict

### Domain Model 핵심 필드
ScanResult.file_path
ScanResult.language
ScanResult.findings

Vulnerability.cwe_id
Vulnerability.severity
Vulnerability.line_number
Vulnerability.code_snippet

FixSuggestion.issue_id
FixSuggestion.original_code
FixSuggestion.fixed_code
FixSuggestion.description

---

## 코딩 컨벤션

- 타입 힌트 필수
- 추상 클래스는 ABC 사용
- 모든 public 메서드에 docstring 필수
- 예외는 반드시 try/except로 처리하고 로그 남기기
- 환경변수는 .env 파일에서만 읽기 (python-dotenv 사용)

---

## MVP 범위

포함: L1 (Semgrep + Tree-sitter + SBOM Mock) + L2 (Claude API) + Dashboard + FastMCP
제외: L3 (SonarQube, PoC, 리포트), 실제 Vector DB, VS Code Extension

---

## 현재 진행 상태

PROGRESS.md 참고