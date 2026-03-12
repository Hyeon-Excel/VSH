# CONVENTIONS.md

## 파일 네이밍

- 모든 파일명은 `snake_case`를 사용한다.
- 추상 클래스 파일은 `base_*.py` 형식을 사용한다.
- 스캐너 구현체는 `*_scanner.py` 형식을 사용한다.
- 분석기 구현체는 `*_analyzer.py` 형식을 사용한다.
- 레포지토리 구현체는 `*_repo.py` 형식을 사용한다.

## 클래스 네이밍

- 추상 클래스는 `Base*` 형식을 사용한다.
- 구현체는 `기능명 + 역할` 형식을 사용한다.
- 파이프라인 클래스는 `*Pipeline` 형식을 사용한다.

## 현재 기준선

- 실제 구현 기준선은 `VSH_Project_MVP/`이다.
- 새 구현은 `layer1/`, `layer2/`, `orchestration/`, `interfaces/`를 직접 사용한다.
- `modules/`, `pipeline/`, `tools/`는 구 경로 호환 wrapper로만 유지한다.

## 추상 계약

### BaseScanner

```python
scan(file_path: str) -> ScanResult
supported_languages() -> list[str]
```

### BaseAnalyzer

```python
analyze(
    scan_result: ScanResult,
    knowledge: list[dict],
    fix_hints: list[dict],
    evidence_map: dict[str, dict] | None = None,
) -> list[FixSuggestion]
```

### BaseReadRepository

```python
find_by_id(id: str) -> dict | None
find_all() -> list[dict]
```

### BaseWriteRepository

```python
save(data: dict) -> bool
update_status(id: str, status: str) -> bool
```

### BasePipeline

```python
run(file_path: str) -> dict
run_scan_only(file_path: str) -> dict
```

## MCP 공개 계약

```python
validate_code(file_path: str) -> dict
scan_only(file_path: str) -> dict
get_results() -> dict
apply_fix(issue_id: str) -> dict
dismiss_issue(issue_id: str) -> dict
get_log(file_path: str) -> dict
```

- `scan_file`, `get_report`, `update_status`는 레거시 호환 wrapper로만 유지한다.

## 도메인 모델

### ScanResult

- `file_path: str`
- `language: str`
- `findings: list[Vulnerability]`
- `vuln_records: list[VulnRecord]`
- `package_records: list[PackageRecord]`
- `annotated_files: list[dict]`
- `notes: list[str]`

### Vulnerability

- `cwe_id: str`
- `severity: str`
- `line_number: int`
- `code_snippet: str`
- `file_path: str | None`
- `rule_id: str | None`
- `reachability_status: str | None`
- `references: list[str]`
- `metadata: dict[str, str]`

### 공통 스키마

- `models/common_schema.py`의 `VulnRecord`, `PackageRecord`를 레이어 간 공통 record 기준으로 사용한다.
- L1 normalized output과 L2 handoff output은 모두 이 스키마를 따른다.

### FixSuggestion

`FixSuggestion`은 L2 내부 운영 모델이면서, 공통 스키마 대응 필드와 `metadata.l2`를 함께 가진다.

공통 필드:

- `vuln_id`
- `file_path`
- `cwe_id`
- `line_number`
- `reachability_status`
- `reachability_confidence`
- `kisa_ref`
- `evidence`
- `status`
- `action_at`
- `original_code`
- `fixed_code`
- `description`
- `fix_suggestion`

L2 운영 필드:

- `metadata.l2.reachability_note`
- `metadata.l2.evidence_refs`
- `metadata.l2.evidence_summary`
- `metadata.l2.retrieval_backend`
- `metadata.l2.chroma_status`
- `metadata.l2.chroma_summary`
- `metadata.l2.chroma_hits`
- `metadata.l2.registry_status`
- `metadata.l2.registry_summary`
- `metadata.l2.osv_status`
- `metadata.l2.osv_summary`
- `metadata.l2.verification_summary`
- `metadata.l2.decision_status`
- `metadata.l2.confidence_score`
- `metadata.l2.confidence_reason`
- `metadata.l2.patch_status`
- `metadata.l2.patch_summary`
- `metadata.l2.patch_diff`
- `metadata.l2.processing_trace`
- `metadata.l2.processing_summary`
- `metadata.l2.category`
- `metadata.l2.remediation_kind`
- `metadata.l2.target_ref`

- `issue_id`, `kisa_reference`, `reachability`, `confidence_score` 같은 예전 flat 이름은 property 호환만 제공한다.

## 코딩 규칙

- 모든 public 함수/메서드는 타입 힌트를 사용한다.
- 추상 계약은 `ABC`와 `@abstractmethod`를 사용한다.
- public 메서드에는 간결한 docstring을 유지한다.
- 예외는 삼키지 말고, 가능한 한 로그 또는 `last_error`로 남긴다.
- 환경변수는 `.env` 또는 `config.py`를 통해 읽는다.
- 레이어 간 데이터 전달은 `models/`와 공통 스키마 record를 기준으로 유지한다.

## 구현 메모

### Pipeline 내부 변수

- `scanners`
- `analyzer`
- `knowledge_repo`
- `fix_repo`
- `log_repo`
- `evidence_retriever`
- `registry_verifier`
- `osv_verifier`
- `patch_builder`
- `analysis_context_map`

### L1-L2 통합 공용 유틸

- `shared/finding_dedup.py`의 `deduplicate_findings()`를 공통 finding 중복 제거 기준으로 사용한다.
- deduplicate 기준 키는 현재 `file_path + cwe_id + line_number` 조합이다.
