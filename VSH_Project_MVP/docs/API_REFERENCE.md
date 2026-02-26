# API Reference

## Domain Models (models/)
`models/` 패키지에 정의된 도메인 모델들은 시스템의 모든 레이어 간 데이터 교환의 기준이 됩니다.

### ScanResult
스캐너(L1)가 생성하는 전체 스캔 결과 모델.

| 필드명 | 타입 | 설명 |
|--------|------|------|
| `file_path` | `str` | 스캔 대상 파일 경로 |
| `language` | `str` | 파일의 언어 (예: python) |
| `findings` | `list[Vulnerability]` | 발견된 취약점 리스트 (기본값: 빈 리스트) |

**Methods:**
- `is_clean() -> bool`: 발견된 취약점이 하나도 없으면 `True`를 반환합니다.

---

### Vulnerability
단일 취약점 정보를 담는 모델.

| 필드명 | 타입 | 설명 |
|--------|------|------|
| `cwe_id` | `str` | CWE ID (예: CWE-78) |
| `severity` | `str` | 취약점 심각도 (**HIGH**, **MEDIUM**, **LOW** 중 하나) |
| `line_number` | `int` | 취약점이 발견된 라인 번호 |
| `code_snippet` | `str` | 취약점이 포함된 코드 조각 |

**Validation:**
- `severity` 필드는 반드시 "HIGH", "MEDIUM", "LOW" 중 하나의 값이어야 하며, 그 외 입력 시 `ValueError`가 발생합니다.

---

### FixSuggestion
분석기(L2)가 제안하는 취약점 수정 정보.

| 필드명 | 타입 | 설명 |
|--------|------|------|
| `issue_id` | `str` | 취약점 ID |
| `original_code` | `str` | 수정 전 원본 코드 |
| `fixed_code` | `str` | 수정 후 제안 코드 |
| `description` | `str` | 수정 내용에 대한 설명 |

---

## Repository Layer (repository/)

### BaseReadRepository (Abstract)
읽기 전용 저장소를 위한 인터페이스.

- `find_by_id(id: str) -> dict | None`: ID로 항목 조회. 없으면 `None` 반환.
- `find_all() -> list[dict]`: 저장소의 모든 항목을 리스트로 반환합니다. Scanner의 패턴 순회 매칭에 사용됩니다.

### BaseWriteRepository (Abstract)
읽기/쓰기가 가능한 저장소를 위한 인터페이스. `BaseReadRepository` 상속.

- `save(data: dict) -> bool`: 데이터 저장 및 업데이트. 성공 시 `True` 반환.
- `update_status(id: str, status: str) -> bool`: 항목의 처리 상태를 업데이트.

---

### MockKnowledgeRepo
보안 지식 베이스(`knowledge.json`) 조회 담당. `BaseReadRepository` 상속.

- `find_by_id(id: str) -> dict | None`: CWE ID로 보안 규칙 및 패턴 조회.

### MockFixRepo
KISA 수정 가이드(`kisa_fix.json`) 조회 담당. `BaseReadRepository` 상속.

- `find_by_id(id: str) -> dict | None`: CWE ID로 수정 코드 템플릿 및 설명 조회.

### MockLogRepo
분석 로그(`log.json`) 기록 및 상태 관리 담당. `BaseWriteRepository` 상속.

- `save(data: dict) -> bool`: 분석 결과를 로그에 기록. `issue_id` 중복 시 기존 항목 업데이트.
- `update_status(id: str, status: str) -> bool`: 특정 이슈의 진행 상태(`pending`, `accepted`, `dismissed`) 변경.
  - `ValueError`: 허용되지 않은 `status` 값 입력 시 발생.

---

## Scanner Layer (modules/scanner/)

### BaseScanner (Abstract)
모든 스캐너의 기본 인터페이스입니다.

- `scan(file_path: str) -> ScanResult`: 파일을 분석하여 취약점 목록을 반환합니다.
  - **Exception**: 지원하지 않는 언어 확장자일 경우 `ValueError` 발생.
  - **Error Handling**: 파일 부재나 파싱 에러 시 빈 `findings`를 가진 `ScanResult` 반환.
- `supported_languages() -> list[str]`: 스캐너가 지원하는 언어 목록을 반환합니다. (MVP: `["python"]`)

### SemgrepScanner
라인 단위 문자열 매칭 기반 스캐너입니다. (현재 MockSemgrepScanner로 구현되어 export됨)
- **Dependency**: `MockKnowledgeRepo`를 생성자 주입으로 받습니다.
- **Method**: `scan()` - `knowledge.json`의 정규식 패턴을 파일의 각 라인과 대조합니다.

### TreeSitterScanner
AST(Abstract Syntax Tree) 구문 분석 기반 스캐너입니다.
- **Dependency**: `MockKnowledgeRepo`를 생성자 주입으로 받습니다.
- **Method**: `scan()` - Python 코드를 AST로 파싱하여 함수 호출(Call Node)을 추출하고 보안 규칙과 매칭합니다.

### SBOMScanner
소프트웨어 빌드 재료(requirements.txt) 분석 스캐너입니다.
- **Method**: `scan()` - `PROJECT_ROOT/requirements.txt`를 읽어 취약한 버전의 패키지가 포함되었는지 검사합니다.
- **Version Logic**: `packaging.version` 모듈을 사용하여 의미론적 버전 비교를 수행합니다.

**참고**: `modules/__init__.py`에서 `MockSemgrepScanner`는 `SemgrepScanner`라는 이름으로 export됩니다. 이는 상위 레이어인 Pipeline이 구현 세부 사항(Mock 여부)에 의존하지 않도록 하기 위함입니다.

---

## Pipeline Layer (pipeline/)

### BasePipeline (Abstract)
파이프라인의 기본 동작을 정의하는 인터페이스.
- `run(file_path: str) -> dict`: 단일 파일에 대한 보안 분석 파이프라인 전체를 실행합니다.

### AnalysisPipeline
실제 분석 흐름을 오케스트레이션하는 클래스입니다. 생성자를 통해 스캐너, 분석기, 레포지토리를 주입받습니다.
- **Method**: `run(file_path: str) -> dict`
  - **인자**: 스캔 대상 파일 경로
  - **반환값**: `file_path`, `scan_results` (dict list), `fix_suggestions` (dict list), `is_clean` (bool) 키를 포함하는 직렬화 가능한 딕셔너리.
  - **전체 흐름**: Scanner 병렬 실행 -> 중복 제거 -> (취약점 발견 시) DB 조회 및 Analyzer 실행 -> (위협 판정 시) LogRepo에 저장 -> 최종 JSON 직렬화 포맷 반환.
- **Method**: `_deduplicate(findings: List[Vulnerability]) -> List[Vulnerability]`
  - `@staticmethod`로 선언.
  - `cwe_id`와 `line_number` 조합을 고유 키로 사용하여 여러 스캐너의 중복된 탐지 결과를 제거합니다.

### PipelineFactory
파이프라인의 모든 의존성을 생성하고 조립하는 역할을 합니다.
- **Method**: `create() -> BasePipeline`
  - 싱글톤 형태의 `Mock Repo`들(Knowledge, Fix, Log)을 생성.
  - 3종의 스캐너(`Semgrep`, `TreeSitter`, `SBOM`) 초기화.
  - `.env`의 `LLM_PROVIDER` 값을 읽어 적절한 `Analyzer` 인스턴스 생성 및 `api_key` 검증 (누락 시 `ValueError`).
  - 생성된 모든 의존성을 `AnalysisPipeline`에 주입하여 반환.

---

## Interface Layer (tools/server.py)

FastMCP를 통해 Claude/Cursor 등의 LLM 클라이언트가 호출할 수 있는 인터페이스입니다. 툴 내부에 비즈니스 로직을 포함하지 않고 Pipeline 및 Repository에 위임합니다.

### `scan_file(file_path: str) -> str`
지정한 파일을 보안 스캔하고 분석 결과를 반환합니다.
- **입력**: `file_path` (스캔 대상 경로)
- **반환 JSON 구조**: 파이프라인 실행 결과 (`file_path`, `scan_results`, `fix_suggestions`, `is_clean`)
- **예외 처리**: 예외 발생 시 `{"error": "에러 메시지"}` 형태의 JSON 반환.

### `get_report() -> str`
저장된 모든 보안 진단 로그를 조회합니다.
- **입력**: 없음
- **반환 JSON 구조**: `{"logs": [{로그 데이터...}], "total": N}`
- **예외 처리**: 예외 발생 시 `{"error": "에러 메시지"}` 반환.

### `update_status(issue_id: str, status: str) -> str`
특정 취약점의 상태를 '수정 승인' 또는 '무시'로 변경합니다.
- **입력**: 
  - `issue_id`: 대상 이슈 ID
  - `status`: 변경할 상태값 (`accepted` 또는 `dismissed`만 허용)
- **반환 JSON 구조**: 성공 시 `{"issue_id": "...", "status": "...", "message": "..."}`
- **예외 및 에러 처리**:
  - 존재하지 않는 `issue_id` 입력 시: `{"error": "Issue not found: ..."}`
  - 잘못된 `status` 입력 시: `{"error": "Invalid status..."}`
  - 기타 시스템 예외 발생 시: `{"error": "에러 메시지"}`
