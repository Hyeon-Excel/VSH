# L1-L2 Integration Progress

## 1. 문서 목적

이 문서는 `codex/l1-l2-integration` 브랜치에서 진행한 L1-L2 융합 작업을
`layer2` 기준선과 비교해 사실 기반으로 정리한 기록이다.

- 기준 브랜치: `layer2`
- 현재 작업 브랜치: `codex/l1-l2-integration`
- 기준 분기 커밋: `33fae74` (`fix: MCP scan_only 계약과 L2 렌더링 안전성 보강`)

이 문서는 "어떤 순서로 무엇을 붙였는지", "현재 어디까지 끝났는지",
"무엇이 아직 남아 있는지"를 한 번에 확인하기 위한 문서다.

## 2. 시작 시점 상태

통합 브랜치를 만들기 전 `layer2`는 다음 상태였다.

- L2 retrieval / verification / patch / confidence / MCP 정렬까지 완료
- `layer1/`, `layer2/`, `orchestration/`, `interfaces/` 구조는 이미 정리됨
- L1은 `MockSemgrepScanner`, `TreeSitterScanner`, `SBOMScanner` 중심 구조
- L1과 L2는 연결되어 있었지만, L1 고도화 브랜치의 scanner / normalizer / annotation 개념은 아직 반영되지 않음
- 공통 데이터 스키마는 문서로만 존재했고, 코드 모델로는 아직 정식 반영되지 않음

즉, 이 브랜치의 목표는 새로운 저장소를 만드는 것이 아니라,
이미 정리된 `layer2` 구조 위에 L1 고도화 요소를 현재 구조에 맞게 이식하는 것이었다.

## 3. 통합 진행 과정

### Step 1. L1 통합 스캐너 초안 추가

커밋: `3e44033`

추가/수정:

- `VSH_Project_MVP/layer1/scanner/vsh_l1_scanner.py`
- `VSH_Project_MVP/layer1/common/import_risk.py`
- `VSH_Project_MVP/layer1/common/pattern_scan.py`
- `VSH_Project_MVP/layer1/common/reachability.py`
- `VSH_Project_MVP/orchestration/pipeline_factory.py`
- `VSH_Project_MVP/models/vulnerability.py`

핵심 내용:

- donor L1 브랜치의 구조를 그대로 merge하지 않고, 현재 `layer2` 구조에 맞는 `VSHL1Scanner`를 추가
- pattern scan, typo package 탐지, lightweight reachability, 기존 SBOM 흐름을 하나의 scanner로 묶음
- `L1_SCANNER_MODE=integrated` 또는 `vsh`일 때 통합 scanner를 선택할 수 있도록 factory 연결
- `Vulnerability`에 `rule_id`, `reachability_status`, `references`, `metadata` 필드 확장

### Step 2. L1 정규화 결과와 annotation preview 추가

커밋: `e22f27d`

추가/수정:

- `VSH_Project_MVP/layer1/common/schema_normalizer.py`
- `VSH_Project_MVP/layer1/common/code_annotator.py`
- `VSH_Project_MVP/models/scan_result.py`
- `VSH_Project_MVP/tests/test_l1_integration_scanner.py`

핵심 내용:

- L1 findings를 구조화된 record로 정규화하는 normalizer 추가
- 실제 파일 수정 없이 annotation preview를 생성하는 code annotator 추가
- `ScanResult`에 `vuln_records`, `package_records`, `annotated_files`, `notes` 필드 추가
- 통합 scanner가 정규화 결과와 annotation preview를 함께 반환하도록 확장

### Step 3. 파이프라인과 MCP에 L1 정규화 출력 노출

커밋: `a786782`

추가/수정:

- `VSH_Project_MVP/orchestration/analysis_pipeline.py`
- `VSH_Project_MVP/tests/test_mcp_server_contract.py`
- `VSH_Project_MVP/tests/test_l1_integration_scanner.py`

핵심 내용:

- `run()`과 `run_scan_only()`가 `scan_results`뿐 아니라 `vuln_records`, `package_records`, `annotated_files`, `notes`를 함께 반환
- MCP `scan_only`도 L1 normalized output을 그대로 노출
- L1 정규화 결과가 파이프라인 밖으로도 보이도록 계약을 확장

### Step 4. L1 provenance를 L2 결과 표면까지 반영

커밋: `05ac96a`

추가/수정:

- `VSH_Project_MVP/orchestration/analysis_pipeline.py`
- `VSH_Project_MVP/dashboard/templates/index.html`
- `VSH_Project_MVP/tests/test_e2e.py`
- `VSH_Project_MVP/tests/test_l1_integration_scanner.py`

핵심 내용:

- 로그에 `rule_id`, `l1_reachability_status`, `l1_references` 저장
- run summary에 `l1_vuln_records_total`, `l1_package_records_total`, `annotation_preview_total`,
  `rule_tagged_total`, `reachable_findings_total`, `typosquatting_findings_total` 추가
- 대시보드가 L1 provenance까지 보여주도록 확장

### Step 5. 공통 스키마 1차 적용

커밋: `a0a4648`

추가/수정:

- `VSH_Project_MVP/models/common_schema.py`
- `VSH_Project_MVP/models/scan_result.py`
- `VSH_Project_MVP/layer1/common/schema_normalizer.py`
- `VSH_Project_MVP/L1_L2_SCHEMA_COORDINATION.md`

핵심 내용:

- 팀 공통 스키마인 `VulnRecord`, `PackageRecord`를 코드 모델로 추가
- L1 normalized output이 문자열 dict가 아니라 공통 스키마 typed record를 직접 사용하도록 변경
- `PackageRecord.source`에 `L1`을 허용하는 현재 구현 선택을 문서로 분리 기록

### Step 6. L2 공통 스키마 handoff record 추가

커밋: `398c9c6`

추가/수정:

- `VSH_Project_MVP/layer2/common/schema_mapper.py`
- `VSH_Project_MVP/orchestration/analysis_pipeline.py`
- `VSH_Project_MVP/tests/test_l1_integration_scanner.py`
- `VSH_Project_MVP/tests/test_e2e.py`

핵심 내용:

- `FixSuggestion`과 L1 `VulnRecord`를 바탕으로 L2 판단 결과를 공통 스키마 `VulnRecord`로 다시 매핑하는 `l2_vuln_records` 추가
- 한 요청 안에서 L1 원본 결과와 L2 보강 결과를 같은 스키마 축으로 비교 가능하게 만듦

### Step 7. L2 공통 스키마 record를 로그와 MCP 표면에 반영

커밋: `700d2df`

추가/수정:

- `VSH_Project_MVP/orchestration/analysis_pipeline.py`
- `VSH_Project_MVP/dashboard/templates/index.html`
- `VSH_Project_MVP/docs/API_REFERENCE.md`
- `VSH_Project_MVP/tests/test_l2_contracts.py`
- `VSH_Project_MVP/tests/test_e2e.py`
- `VSH_Project_MVP/tests/test_mcp_server_contract.py`

핵심 내용:

- 각 로그 항목에 `l2_vuln_record` 저장
- 대시보드에서 L2 공통 스키마 provenance를 일부 노출
- MCP `validate_code` 결과가 `l2_vuln_records`를 계약상 포함함을 테스트와 문서에 반영

## 4. 현재 Working Tree 단계

아직 커밋되지 않은 현재 작업은 `FixSuggestion`을 공통 스키마 + `metadata.l2` 구조로 옮기는 전환 단계다.

현재 수정 파일:

- `VSH_Project_MVP/models/fix_suggestion.py`
- `VSH_Project_MVP/orchestration/analysis_pipeline.py`
- `VSH_Project_MVP/docs/API_REFERENCE.md`
- `VSH_Project_MVP/tests/test_l2_contracts.py`
- `VSH_Project_MVP/tests/test_e2e.py`

핵심 내용:

- `FixSuggestion`에 `vuln_id`, `kisa_ref`, `evidence`, `fix_suggestion`,
  `reachability_status`, `reachability_confidence`, `status`, `action_at` 추가
- L2 운영 필드는 `metadata.l2` 안으로 모으고,
  기존 `issue_id`, `kisa_reference`, `confidence_score` 같은 flat 필드는 호환 경로로 유지
- 파이프라인 로그에도 `metadata`와 `vuln_id`를 함께 저장

즉, L1/L2 융합의 다음 단계는 "공통 스키마를 도입했다" 수준이 아니라,
L2 내부 모델도 점진적으로 공통 스키마 관점으로 재정렬하는 작업이다.

## 5. 현재 구조에서 실제로 된 것

현재 브랜치 기준으로 완료된 항목은 아래와 같다.

- L1 통합 scanner 연결 완료
- L1 normalized output 공통 스키마 적용 완료
- L1 annotation preview 생성 및 반환 완료
- L1 provenance를 로그/대시보드/summary까지 노출 완료
- L2 결과를 공통 스키마 `l2_vuln_records`로 재구성 완료
- L2 공통 스키마 record를 로그와 MCP 결과에 노출 완료
- `FixSuggestion`의 공통 스키마 전환 1차 리팩토링 진행 중

## 6. 아직 남아 있는 것

아직 남은 항목은 다음과 같다.

- `FixSuggestion`의 legacy flat 필드를 얼마나 오래 유지할지 결정
- `PackageRecord.source`를 `L1`까지 허용할지 팀 합의
- 실제 L1 고도화 구현(실제 Semgrep/외부 API/더 깊은 reachability)과의 정합 점검
- L3 handoff 최종 계약 확정

## 7. 검증 상태

현재 작업 브랜치에서 최근 확인한 테스트 결과는 다음과 같다.

```bash
cd VSH_Project_MVP
python -m pytest tests -q
```

결과:

- `40 passed, 1 skipped`

즉, 현재 단계는 "L1-L2 1차 통합 완료 + L2 내부 공통 스키마 전환 진행 중"으로 보는 것이 가장 정확하다.

## 8. 요약

`codex/l1-l2-integration` 브랜치는 `layer2` 위에 donor L1 개념을 그대로 merge한 브랜치가 아니다.
대신 현재 `layer2` 구조를 기준으로,

1. L1 통합 scanner를 이식하고
2. L1 결과를 공통 스키마로 정규화하고
3. 그 결과를 L2 파이프라인에 연결하고
4. 다시 L2 판단 결과를 공통 스키마로 내보내고
5. 마지막으로 `FixSuggestion` 내부 구조도 공통 스키마 중심으로 옮기기 시작한

"구조적 통합 브랜치"다.
