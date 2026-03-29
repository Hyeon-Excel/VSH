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

---

## Pipeline Layer (pipeline/)

### BasePipeline (Abstract)
파이프라인의 기본 동작을 정의하는 인터페이스.
- `run(file_path: str) -> dict`: 단일 파일에 대한 보안 분석 파이프라인 전체를 실행합니다.

### AnalysisPipeline
실제 분석 흐름을 오케스트레이션하는 클래스입니다. 생성자를 통해 스캐너, 분석기, 레포지토리(Read/Write)를 주입받습니다.
- **Method**: `run(file_path: str) -> dict`
  - **전체 흐름**: 스캐너 실행 -> 중복 제거 -> Analyzer 실행 -> **결과를 `LogRepo`에 영구 저장(original/fixed code 포함)** -> 결과 반환.

---

## Dashboard API (dashboard/app.py)

FastAPI를 통해 개발자가 브라우저에서 분석 결과를 리뷰하고 조치할 수 있는 인터페이스를 제공합니다.

### `GET /`
- **설명**: 대시보드 메인 HTML 페이지(`index.html`)를 반환합니다.

### `GET /api/logs`
- **설명**: `log.json`에 저장된 모든 보안 진단 이력을 조회합니다.

### `POST /api/logs/{issue_id}/accept`
- **설명**: 사용자가 수정을 승인했음을 표시하고 AI 제안 코드를 반환합니다.

---

## E2E Testing (tests/test_e2e.py)

전체 시스템의 정합성을 검증하기 위한 자동화된 테스트 세트입니다.

### 테스트 실행 방법
Dashboard 서버가 실행 중이어야 합니다 (`uvicorn dashboard.app:app --port 3000`).
```bash
python -m pytest tests/test_e2e.py -v
```

### 테스트 시나리오
1. **취약 파일 스캔 (`test_e2e_scan_vulnerable_file`)**: `e2e_target.py` 스캔 시 CWE-89, CWE-798이 정확히 탐지되는지 검증.
2. **Dashboard API (`test_e2e_dashboard_api`)**: `/api/logs` 조회 및 `accept/dismiss` 호출 시 상태 변경 및 `fixed_code` 반환 여부 검증.
3. **수정 파일 재스캔 (`test_e2e_rescan_fixed_file`)**: `e2e_target_fixed.py` 스캔 시 핵심 취약점이 더 이상 탐지되지 않는지 검증.
4. **로그 이력 (`test_e2e_log_history`)**: `log.json`에 모든 필드(`original_code`, `fixed_code` 등)가 올바르게 저장되는지 검증.

### 주의사항
- **SBOMScanner 특성**: 프로젝트 루트의 `requirements.txt`를 항상 스캔하므로, 개별 파일이 깨끗해도 전체 `is_clean`은 `False`일 수 있습니다. 재스캔 검증 시 특정 CWE ID의 존재 여부로 판단해야 합니다.
- **Library 마이그레이션**: 현재 `google-generativeai`를 사용 중이나 이미 지원 종료되었습니다. `GeminiAnalyzer` 단일 파일만 `google-genai` 패키지로 교체하여 시스템 전체 수정을 방지할 수 있습니다.
