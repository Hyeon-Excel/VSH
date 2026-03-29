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
| `vuln_records` | `list[VulnRecord]` | 공통 스키마 기준 L1 취약점 레코드 |
| `package_records` | `list[PackageRecord]` | 공통 스키마 기준 패키지 레코드 |
| `annotated_files` | `dict[str, str]` | 코드 주석 preview 결과 |
| `notes` | `list[str]` | 스캐너 실행 메모 및 provenance |

**Methods:**
- `is_clean() -> bool`: 발견된 취약점이 하나도 없으면 `True`를 반환합니다.

---

### Vulnerability
단일 취약점 정보를 담는 모델.

| 필드명 | 타입 | 설명 |
|--------|------|------|
| `file_path` | `str \| None` | 취약점이 실제로 발견된 파일 경로 |
| `cwe_id` | `str` | CWE ID (예: CWE-78) |
| `severity` | `str` | 취약점 심각도 (**CRITICAL**, **HIGH**, **MEDIUM**, **LOW** 중 하나) |
| `line_number` | `int` | 취약점이 발견된 라인 번호 |
| `code_snippet` | `str` | 취약점이 포함된 코드 조각 |

**Validation:**
- `severity` 필드는 반드시 "CRITICAL", "HIGH", "MEDIUM", "LOW" 중 하나의 값이어야 하며, 그 외 입력 시 `ValueError`가 발생합니다.

---

### FixSuggestion
분석기(L2)가 제안하는 취약점 수정 정보.

| 필드명 | 타입 | 설명 |
|--------|------|------|
| `vuln_id` | `str` | 공통 스키마 기준 취약점 ID |
| `file_path` | `str \| None` | 수정 제안이 적용되어야 하는 실제 파일 경로 |
| `cwe_id` | `str \| None` | 연관된 CWE ID |
| `line_number` | `int \| None` | 연관된 라인 번호 |
| `reachability_status` | `str \| None` | 공통 스키마 기준 도달 가능성 상태 |
| `reachability_confidence` | `str \| None` | 공통 스키마 기준 도달 가능성 신뢰도 |
| `kisa_ref` | `str \| None` | 공통 스키마 기준 KISA 참조 |
| `evidence` | `str \| None` | 공통 스키마 기준 취약 코드 스니펫 |
| `fix_suggestion` | `str \| None` | 공통 스키마 기준 수정 요약 |
| `metadata` | `FixSuggestionMetadata` | L2 내부 운영 메타데이터 블록 (`metadata.l2`) |
| `original_code` | `str` | 수정 전 원본 코드 |
| `fixed_code` | `str` | 수정 후 제안 코드 |
| `description` | `str` | 수정 내용에 대한 설명 |

#### FixSuggestionMetadata.l2
`metadata.l2`는 공통 스키마 밖의 L2 전용 운영 필드를 담는다.

| 필드명 | 타입 | 설명 |
|--------|------|------|
| `reachability_note` | `str \| None` | L2가 생성한 reachability 설명 문장 |
| `evidence_refs` | `list[str]` | retrieval이 모은 근거 참조 목록 |
| `evidence_summary` | `str \| None` | retrieval이 정리한 근거 요약 |
| `retrieval_backend` | `str \| None` | retrieval 실행 경로 (`static_only`, `hybrid` 등) |
| `chroma_status` | `str \| None` | Chroma RAG 상태 |
| `chroma_summary` | `str \| None` | Chroma 상태 설명 |
| `chroma_hits` | `int` | Chroma 적중 수 |
| `registry_status` | `str \| None` | registry verifier 결과 상태 |
| `registry_summary` | `str \| None` | registry verifier 상세 설명 |
| `osv_status` | `str \| None` | OSV verifier 결과 상태 |
| `osv_summary` | `str \| None` | OSV verifier 상세 설명 |
| `verification_summary` | `str \| None` | verifier 결과를 합친 요약 |
| `decision_status` | `str \| None` | 최종 판단 상태 |
| `confidence_score` | `int` | 신뢰도 점수 |
| `confidence_reason` | `str \| None` | 신뢰도 산정 사유 |
| `patch_status` | `str \| None` | patch preview 생성 상태 |
| `patch_summary` | `str \| None` | patch preview 생성 요약 |
| `patch_diff` | `str \| None` | unified diff 형식 patch preview |
| `processing_trace` | `list[str]` | L2 처리 경로 단계 목록 |
| `processing_summary` | `str \| None` | 처리 경로를 요약한 문자열 |
| `category` | `str \| None` | finding 분류 (`code`, `supply_chain`) |
| `remediation_kind` | `str \| None` | 수정 방식 분류 |
| `target_ref` | `str \| None` | L3 handoff용 대상 식별자 |

---

### Common Schema
L1/L2/L3가 공통으로 교환하는 구조화 레코드는 `models/common_schema.py`에 정의되어 있습니다.

#### VulnRecord
공통 취약점 레코드. 현재 파이프라인은 다음 두 경로로 이 구조를 노출합니다.
- `vuln_records`: L1이 정규화한 원본 결과
- `l2_vuln_records`: L2가 판단/보강한 후 다시 공통 스키마로 매핑한 결과

#### PackageRecord
공통 패키지 레코드. 현재는 L1 통합 단계에서 `package_records`로 노출됩니다.

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
- `update_status(id: str, status: str) -> bool`: 특정 이슈의 진행 상태(`pending`, `accepted`, `dismissed`, `analysis_failed`) 변경.
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

## Verification Layer (layer2/verifier/)

### RegistryVerifier
공급망 finding에서 패키지 선언을 식별하고 registry 검증 대상 여부를 정규화합니다.
- **Method**: `verify(finding: Vulnerability) -> dict`
- **Status Values**: `FOUND`, `NOT_FOUND`, `UNKNOWN`, `ERROR`

### OsvVerifier
공급망 finding에 대해 advisory 기반 취약 버전 여부를 정규화합니다.
- **Method**: `verify(finding: Vulnerability) -> dict`
- **Current Data Source**: `config.VULNERABLE_PACKAGES` 기반 deterministic verifier
- **Status Values**: `FOUND`, `NOT_FOUND`, `UNKNOWN`, `ERROR`

---

## Pipeline Layer (pipeline/)

### BasePipeline (Abstract)
파이프라인의 기본 동작을 정의하는 인터페이스.
- `run(file_path: str) -> dict`: 단일 파일에 대한 보안 분석 파이프라인 전체를 실행합니다.

### AnalysisPipeline
실제 분석 흐름을 오케스트레이션하는 클래스입니다. 생성자를 통해 스캐너, 분석기, 레포지토리(Read/Write)를 주입받습니다.
- **Method**: `run(file_path: str) -> dict`
  - **전체 흐름**: 스캐너 실행 -> 중복 제거 -> Retrieval -> Analyzer 실행 -> Verification 정규화 -> **결과를 `LogRepo`에 영구 저장(original/fixed code 포함)** -> 결과 반환.
  - **주요 반환 필드**: `scan_results`, `vuln_records`, `package_records`, `l2_vuln_records`, `fix_suggestions`, `summary`

---

## Dashboard API (dashboard/app.py)

FastAPI를 통해 개발자가 브라우저에서 분석 결과를 리뷰하고 조치할 수 있는 인터페이스를 제공합니다.

### `GET /`
- **설명**: 대시보드 메인 HTML 페이지(`index.html`)를 반환합니다.

### `GET /api/logs`
- **설명**: `log.json`에 저장된 모든 보안 진단 이력을 조회합니다.
- **비고**: 각 로그 항목에는 L2 결과를 공통 스키마로 정리한 `l2_vuln_record`가 포함될 수 있습니다.

### `POST /api/logs/{issue_id}/accept`
- **설명**: 사용자가 수정을 승인했음을 표시하고 AI 제안 코드를 반환합니다.

---

## E2E Testing (tests/test_e2e.py)

전체 시스템의 정합성을 검증하기 위한 자동화된 테스트 세트입니다.

### 테스트 실행 방법
Dashboard 서버가 실행 중이어야 합니다 (`uvicorn dashboard.app:app --port 3000`).
```bash
LLM_PROVIDER=mock \
python -m pytest tests/test_e2e.py -v
```

### 테스트 시나리오
1. **취약 파일 스캔 (`test_e2e_scan_vulnerable_file`)**: `e2e_target.py` 스캔 시 CWE-89, CWE-798이 정확히 탐지되는지 검증.
2. **Dashboard API (`test_e2e_dashboard_api`)**: `/api/logs` 조회 및 `accept/dismiss` 호출 시 상태 변경 및 `fixed_code` 반환 여부 검증.
3. **수정 파일 재스캔 (`test_e2e_rescan_fixed_file`)**: `e2e_target_fixed.py` 스캔 시 핵심 취약점이 더 이상 탐지되지 않는지 검증.
4. **로그 이력 (`test_e2e_log_history`)**: `log.json`에 모든 필드(`original_code`, `fixed_code` 등)가 올바르게 저장되는지 검증.

### 주의사항
- **SBOMScanner 특성**: 프로젝트 루트의 `requirements.txt`를 항상 스캔하므로, 개별 파일이 깨끗해도 전체 `is_clean`은 `False`일 수 있습니다. 재스캔 검증 시 특정 CWE ID의 존재 여부로 판단해야 합니다.
- **Gemini SDK**: 현재 `GeminiAnalyzer`는 `google-genai` 패키지를 사용합니다. Gemini 관련 의존성 문제를 점검할 때는 `google-generativeai`가 아니라 `google-genai` 설치 여부를 확인해야 합니다.
