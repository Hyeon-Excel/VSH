# CONVENTIONS.md — 네이밍 및 코딩 규칙

## 파일 네이밍
- 모든 파일명: snake_case
- 추상 클래스 파일: base_*.py
- 스캐너 구현체: *_scanner.py
- 분석기 구현체: *_analyzer.py
- 레포지토리 구현체: *_repo.py

## 클래스 네이밍
- 추상 클래스: Base* (예: BaseScanner, BaseRepository)
- 구현체: 기능명 + 역할 (예: SemgrepScanner, MockKnowledgeRepo)
- Pipeline: *Pipeline (예: AnalysisPipeline)

## 메서드 네이밍 (확정, 변경 금지)

### BaseScanner
scan(file_path: str) -> ScanResult
supported_languages() -> list[str]

### BaseAnalyzer
analyze(scan_result: ScanResult, knowledge: list[dict], fix_hints: list[dict], evidence_map: dict[str, dict] | None = None) -> list[FixSuggestion]

### BaseReadRepository
find_by_id(id: str) -> dict | None
find_all() -> list[dict]

### BaseWriteRepository
save(data: dict) -> bool
update_status(id: str, status: str) -> bool

### BasePipeline
run(file_path: str) -> dict

### MCP 툴
validate_code(file_path: str) -> dict
scan_only(file_path: str) -> dict
get_results() -> dict
apply_fix(issue_id: str) -> dict
dismiss_issue(issue_id: str) -> dict
get_log(file_path: str) -> dict

## Domain Model 필드 (확정, 변경 금지)

### ScanResult
file_path: str
language: str
findings: list[Vulnerability]

### Vulnerability
cwe_id: str
severity: str        # HIGH / MEDIUM / LOW
line_number: int
code_snippet: str

### FixSuggestion
issue_id: str
original_code: str
fixed_code: str
description: str

L2 확장 필드:

- file_path
- cwe_id
- line_number
- reachability
- kisa_reference
- evidence_refs
- evidence_summary
- retrieval_backend
- chroma_status
- chroma_summary
- chroma_hits
- registry_status
- registry_summary
- osv_status
- osv_summary
- verification_summary
- decision_status
- confidence_score
- confidence_reason
- patch_status
- patch_summary
- patch_diff
- processing_trace
- processing_summary
- category
- remediation_kind
- target_ref

## 코딩 규칙

- 타입 힌트 필수 (모든 함수 인자 및 반환값)
- 추상 클래스는 반드시 ABC, abstractmethod 사용
- 모든 public 메서드에 docstring 필수
- 예외 처리는 반드시 try/except, 로그 남기기
- 환경변수는 .env에서만 읽기 (python-dotenv)
- 레이어 간 데이터 전달은 반드시 models/ 도메인 모델 사용
- 현재 L2 구현체 위치는 `VSH_Project_MVP/layer2/`를 기준으로 한다
- `modules/`는 공통 인터페이스와 scanner 중심으로 유지한다
- 내부 구현 변수명은 구현 후 이 파일에 추가할 것

## 내부 구현 변수명

### Analyzer
- `knowledge_map`
- `fix_map`
- `evidence_map`
- `finding_context`
- `last_error`

### Pipeline
- `scanners`
- `analyzer`
- `knowledge_repo`
- `fix_repo`
- `log_repo`
- `evidence_retriever`
- `registry_verifier`
- `osv_verifier`
- `patch_builder`
- `evidence_map`
- `verification_map`
- `analysis_context_map`

### MCP 도구
- 공개 계약 이름은 `validate_code`, `scan_only`, `get_results`, `apply_fix`, `dismiss_issue`, `get_log`
- `scan_file`, `get_report`, `update_status`는 레거시 호환 래퍼로만 유지 가능
