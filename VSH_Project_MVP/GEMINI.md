# GEMINI.md

## 프로젝트 개요

VSH는 소스 코드 보안 취약점을 탐지하고, 근거를 보강하고, 수정 제안까지 반환하는 보안 분석 도구다.

현재 구조는 아래 3계층을 기준으로 본다.

- L1: 탐지
- L2: 분석 / 판단 / 수정 제안
- L3: 심층 검증 / 리포팅

## 현재 아키텍처 기준

```text
Interface Layer     -> interfaces/
Orchestration Layer -> orchestration/
Execution Layer     -> layer1/, layer2/
Data Layer          -> repository/
Shared Contract     -> shared/
Domain Model        -> models/
```

`modules/`, `pipeline/`, `tools/`는 기존 import 호환용 wrapper다.

## 현재 폴더 구조

```text
VSH_Project_MVP/
├── shared/
│   ├── contracts.py
│   └── finding_dedup.py
├── models/
│   ├── common_schema.py
│   ├── scan_result.py
│   ├── vulnerability.py
│   └── fix_suggestion.py
├── layer1/
│   ├── scanner/
│   └── common/
├── layer2/
│   ├── analyzer/
│   ├── retriever/
│   ├── verifier/
│   ├── common/
│   └── patch_builder.py
├── orchestration/
│   ├── base_pipeline.py
│   ├── analysis_pipeline.py
│   └── pipeline_factory.py
├── interfaces/
│   └── mcp/server.py
├── repository/
├── dashboard/
├── modules/
├── pipeline/
└── tools/
```

## 설계 원칙

1. SRP를 유지한다.
2. 새 구현은 가능하면 wrapper가 아닌 실제 구현 경로에 추가한다.
3. `interfaces/`는 `orchestration/`만 호출한다.
4. `layer1/`, `layer2/`는 `models/`와 `shared/` 계약을 기준으로 통신한다.
5. 레이어 간 공유 record는 `models/common_schema.py`를 우선 기준으로 본다.

## 현재 핵심 계약

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

### MCP Tool

- `validate_code`
- `scan_only`
- `get_results`
- `apply_fix`
- `dismiss_issue`
- `get_log`

## 현재 모델 기준

### ScanResult

- `findings`
- `vuln_records`
- `package_records`
- `annotated_files`
- `notes`

### Vulnerability

- `cwe_id`
- `severity`
- `line_number`
- `code_snippet`
- `rule_id`
- `reachability_status`
- `references`
- `metadata`

### FixSuggestion

공통 필드:

- `vuln_id`
- `file_path`
- `cwe_id`
- `line_number`
- `kisa_ref`
- `evidence`
- `fix_suggestion`
- `status`

L2 운영 필드:

- `metadata.l2.*`

legacy 이름인 `issue_id`, `kisa_reference` 등은 property 호환만 제공한다.

## 현재 구현 상태

- L2 retrieval / verification / confidence / patch / MCP 정렬 완료
- L1 통합 scanner와 공통 스키마 정렬 1차 완료
- `FixSuggestion`을 공통 필드 + `metadata.l2` 구조로 정리 완료
- 공용 deduplicate 기준 도입 완료

자세한 진행 상태는 아래 문서를 본다.

- `PROGRESS.md`
- `docs/FLOW.md`
- `docs/API_REFERENCE.md`
- 루트 진행 문서: `../docs/L1_L2_INTEGRATION_PROGRESS.md`
