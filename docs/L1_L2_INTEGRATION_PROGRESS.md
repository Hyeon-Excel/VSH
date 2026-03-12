# L1-L2 Integration Progress

## 1. 문서 목적

이 문서는 `codex/l1-l2-integration` 브랜치에서 진행한 L1-L2 융합 작업을
`layer2` 기준선과 비교해 사실 기반으로 정리한 기록이다.

- 기준 브랜치: `layer2`
- 현재 작업 브랜치: `codex/l1-l2-integration`
- 현재 HEAD: `a9a2c8b`

## 2. 통합 전 상태

통합 시작 전 `layer2`는 아래 상태였다.

- L2 retrieval / verification / patch / confidence / MCP 정렬 완료
- `layer1/`, `layer2/`, `orchestration/`, `interfaces/` 구조 정리 완료
- L1은 `MockSemgrepScanner`, `TreeSitterScanner`, `SBOMScanner` 중심
- 공통 데이터 스키마는 문서 수준에서만 정리돼 있었고, 코드 모델은 없었다

즉 목표는 새 저장소를 만드는 것이 아니라, 현재 `layer2` 구조 위에
L1 고도화 요소와 공통 스키마를 현재 코드 기준으로 이식하는 것이었다.

## 3. 통합 단계 요약

### Step 1. L1 통합 scanner 추가

- `vsh_l1_scanner.py`
- `pattern_scan.py`
- `import_risk.py`
- `reachability.py`

pattern scan, typo package 탐지, lightweight reachability, SBOM 흐름을 하나의 scanner 경로로 묶었다.

### Step 2. L1 normalized output 추가

- `schema_normalizer.py`
- `code_annotator.py`
- `ScanResult.vuln_records`
- `ScanResult.package_records`
- `ScanResult.annotated_files`
- `ScanResult.notes`

L1 결과를 공통 record 관점으로 정리하고 annotation preview를 반환하게 만들었다.

### Step 3. 파이프라인/MCP에 L1 출력 노출

- `run()`
- `run_scan_only()`
- MCP `scan_only`

L1 normalized output이 파이프라인 밖으로 보이도록 연결했다.

### Step 4. L1 provenance를 L2 표면에 반영

- 로그
- summary
- dashboard

`rule_id`, `l1_reachability_status`, `l1_references`를 외부에서 확인 가능하게 했다.

### Step 5. 공통 스키마 코드 도입

- `models/common_schema.py`

`VulnRecord`, `PackageRecord`를 코드 모델로 추가하고 L1 normalized output에 적용했다.

### Step 6. L2 공통 스키마 handoff 도입

- `layer2/common/schema_mapper.py`
- `l2_vuln_records`

L2 판단 결과도 공통 `VulnRecord` 축으로 다시 만들 수 있게 했다.

### Step 7. L2 공통 스키마 record를 로그/MCP/UI에 반영

- `l2_vuln_record`
- `l2_vuln_records`

L1 원본 결과와 L2 보강 결과를 같은 record 축에서 비교할 수 있게 했다.

### Step 8. FixSuggestion 공통 필드 + metadata.l2 전환

- `FixSuggestion.vuln_id`
- `FixSuggestion.kisa_ref`
- `FixSuggestion.evidence`
- `FixSuggestion.fix_suggestion`
- `FixSuggestion.metadata.l2`

L2 운영 필드를 `metadata.l2`로 정리하고, 공통 필드는 top-level에 두는 구조로 바꿨다.

### Step 9. 공용 deduplicate 도입

- `shared/finding_dedup.py`

L1 scanner와 파이프라인이 같은 deduplicate 기준을 사용하도록 정리했다.

## 4. 현재 완료된 항목

- L1 통합 scanner 연결 완료
- L1 normalized output 공통 스키마 적용 완료
- L1 annotation preview 생성 및 반환 완료
- L1 provenance를 로그/대시보드/summary까지 노출 완료
- L2 결과를 공통 스키마 `l2_vuln_records`로 재구성 완료
- `FixSuggestion`을 공통 필드 + `metadata.l2` 구조로 정리 완료
- L1/L2 공용 deduplicate 로직 적용 완료

## 5. 현재 남은 항목

- `PackageRecord.source` 정책 팀 합의
- `FixSuggestion` 레거시 호환 property 및 로그 평탄화 키 제거 시점 결정
- 실제 L1 고도화 구현과 현재 통합 scanner 정합 점검
- L3 handoff 최종 계약 확정

## 6. 검증 상태

최근 기준 테스트:

```bash
cd VSH_Project_MVP
python -m pytest tests -q
```

결과:

- `41 passed, 1 skipped`

이 수치는 mock/fixture 기반 구조 검증과 L1-L2 통합 회귀가 깨지지 않았다는 의미다.
실제 외부 API 품질이나 운영 환경 안정성을 보증하지는 않는다.

## 7. 현재 판단

현재 브랜치는 단순 실험 브랜치가 아니라,

1. L1 결과를 공통 스키마로 정규화하고
2. 그 결과를 L2 파이프라인에 연결하고
3. 다시 L2 판단 결과를 공통 스키마로 재구성하고
4. L2 내부 모델까지 공통 스키마 관점으로 정리한

구조적 통합 브랜치다.

한 줄로 정리하면:

`codex/l1-l2-integration`은 **L1-L2 1차 통합과 공통 스키마 1차 정렬이 완료된 상태**다.
