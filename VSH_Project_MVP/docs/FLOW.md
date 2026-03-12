# Process Flows

## 전체 흐름

1. 사용자가 코드 변경을 발생시킨다.
2. MCP 인터페이스 또는 대시보드가 `AnalysisPipeline`을 호출한다.
3. L1 scanner가 `ScanResult`와 공통 스키마 `vuln_records`, `package_records`를 생성한다.
4. 파이프라인이 finding을 공통 deduplicate 기준으로 병합한다.
5. L2가 evidence retrieval, verification, analyzer, patch 생성을 수행한다.
6. L2 결과는 `FixSuggestion`과 `l2_vuln_records`로 반환된다.
7. 로그 저장, 대시보드 렌더링, MCP 응답이 이어진다.

## L1 흐름

### `VSHL1Scanner`

통합 L1 경로는 아래 단계를 한 scanner로 묶는다.

1. pattern scan
2. import/package risk scan
3. lightweight reachability annotation
4. 기존 SBOM scanner 결과 합성
5. `deduplicate_findings()` 적용
6. 공통 스키마 `VulnRecord` / `PackageRecord` 생성
7. annotation preview 생성

결과는 `ScanResult` 안에 아래 필드로 담긴다.

- `findings`
- `vuln_records`
- `package_records`
- `annotated_files`
- `notes`

## L1 -> L2 파이프라인

`AnalysisPipeline.run(file_path)` 내부 순서는 현재 아래와 같다.

1. scanner 실행
2. scanner별 `ScanResult` 병합
3. `shared.finding_dedup.deduplicate_findings()`로 중복 제거
4. `EvidenceRetriever`로 evidence context 생성
5. supply-chain finding에 대해 `RegistryVerifier`, `OsvVerifier` 실행
6. analyzer 호출
7. `FixSuggestion` 정규화
8. `PatchBuilder`로 patch preview 생성
9. `l2_vuln_records` 생성
10. 로그 저장
11. `summary`와 함께 결과 반환

## `FixSuggestion` 흐름

현재 `FixSuggestion`은 두 층으로 구성된다.

### 공통 필드

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

### `metadata.l2`

retrieval, verification, confidence, patch, trace 정보는 모두 `metadata.l2` 안에 모은다.

즉, 외부 연계는 공통 필드를 보고, L2 내부 운영 정보는 `metadata.l2`를 통해 본다.

## `scan_only`와 `validate_code`

### `scan_only`

- 전체 분석을 수행하지 않는다.
- scan 결과와 L1 normalized output만 반환한다.
- L2 analyzer 호출과 로그 저장을 생략한다.

### `validate_code`

- L1 + L2 전체 흐름을 수행한다.
- `scan_results`
- `fix_suggestions`
- `vuln_records`
- `package_records`
- `l2_vuln_records`
- `summary`
  를 함께 반환한다.

## 대시보드 흐름

1. 브라우저가 `GET /api/logs` 호출
2. 저장된 로그를 카드 형태로 렌더링
3. 카드에는 아래 정보가 함께 표시된다.
   - L1 rule ID / reachability / references
   - L2 판단, confidence, verification, patch preview
   - L2 공통 스키마 provenance
4. `Accept` 시 상태만 `accepted`로 바꾸고 `fixed_code`를 반환한다.
5. `Dismiss` 시 상태만 `dismissed`로 바꾼다.

현재는 실제 파일 수정/백업은 수행하지 않는다.

## E2E 검증 의미

테스트 `41 passed, 1 skipped`는 아래를 의미한다.

- mock/fixture 기반에서 계약이 깨지지 않는다.
- L1-L2 통합 흐름과 MCP 응답이 동작한다.

이 수치는 실제 L1 구현 품질, 실제 LLM 품질, 실제 외부 API 안정성을 보증하지는 않는다.
