# Variables & Constants

## Severity

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`

`severity`는 정성 등급이고, `cvss_score`는 참고용 수치다. 둘을 혼합해 판정하지 않는다.

## Language

현재 스캐너/공통 스키마에서 주로 사용하는 값:

- `python`
- `javascript`
- `c`

파이프라인은 파일 확장자 기준으로 기본 언어를 추론하고, 스캐너별 `ScanResult.language`를 그대로 유지한다.

## Reachability

공통 스키마와 현재 L1/L2는 아래 값을 사용한다.

- `reachable`
- `unreachable`
- `unknown`

기존 `YES / NO / UNKNOWN`은 하위호환 입력으로만 처리한다.

## LLM Provider

환경변수 `LLM_PROVIDER` 허용값:

- `mock`
- `gemini`
- `claude`

실제 키:

- `GEMINI_API_KEY`
- `ANTHROPIC_API_KEY`

## 로그 구조

`mock_db/log.json`에 저장되는 로그는 UI/MCP 소비 편의를 위해 공통 스키마 키와 레거시 평탄화 키를 함께 가진다.

핵심 키:

- `issue_id`
- `vuln_id`
- `file_path`
- `cwe_id`
- `severity`
- `line_number`
- `code_snippet`
- `status`
- `description`
- `fixed_code`
- `l2_vuln_record`
- `metadata`

### `metadata.l2`

L2 운영 필드는 `metadata.l2` 안에 저장된다.

- `reachability_note`
- `evidence_refs`
- `evidence_summary`
- `retrieval_backend`
- `chroma_status`
- `chroma_summary`
- `chroma_hits`
- `registry_status`
- `registry_summary`
- `osv_status`
- `osv_summary`
- `verification_summary`
- `decision_status`
- `confidence_score`
- `confidence_reason`
- `patch_status`
- `patch_summary`
- `patch_diff`
- `processing_trace`
- `processing_summary`
- `category`
- `remediation_kind`
- `target_ref`

### 로그 호환 키

현재 로그는 기존 대시보드/도구 호환을 위해 아래 평탄화 키도 유지한다.

- `kisa_reference`
- `reachability`
- `evidence_refs`
- `retrieval_backend`
- `decision_status`
- `confidence_score`
- `patch_diff`
- `category`

공식 직렬화 기준은 `FixSuggestion.metadata.l2`와 `l2_vuln_record`다.

## Path / Config

`config.py` 기준 주요 상수:

- `PROJECT_ROOT`
- `KNOWLEDGE_PATH`
- `FIX_PATH`
- `LOG_PATH`
- `CHROMA_DB_PATH`
- `CHROMA_COLLECTION_NAME`

## MCP Tool Names

공개 계약:

- `validate_code`
- `scan_only`
- `get_results`
- `apply_fix`
- `dismiss_issue`
- `get_log`

레거시 호환 이름:

- `scan_file`
- `get_report`
- `update_status`
