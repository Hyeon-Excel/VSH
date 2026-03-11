# L1-L2 Schema Coordination Notes

작성일: 2026-03-12
기준 브랜치: `codex/l1-l2-integration`

## 목적

L1-L2 통합 과정에서 공통 스키마와 현재 구현 사이에 남아 있는 조율 필요 항목을 정리한다.
이 문서는 구현 완료 보고가 아니라, 팀 합의가 필요한 정책/계약 포인트를 빠르게 확인하기 위한 메모다.

## 항목 1. `PackageRecord.source`에 `L1` 허용 여부

### 현재 상태

- 공통 스키마 원안에서는 `PackageRecord.source`가 `"L3_SBOM"` 고정이다.
- 현재 구현에서는 L1 통합 scanner가 패키지 위험 결과를 `PackageRecord` 형태로도 만들 수 있도록
  `VSH_Project_MVP/models/common_schema.py`에서 `source: Literal["L1", "L3_SBOM"]`로 확장했다.

### 왜 조율이 필요한가

- 이 변경은 L1 단계에서도 package-level record를 공통 구조로 다루기 위해 넣은 것이지만,
  원안과는 다르다.
- 즉, "공통 PackageRecord는 L3 전용인가?" 또는 "L1도 같은 구조를 써도 되는가?"를 팀에서 먼저 정해야 한다.

### 선택지

1. `PackageRecord.source`에 `L1`을 공식 허용한다.
   - 장점: L1-L2-L3가 같은 package record 구조를 공유할 수 있다.
   - 단점: 기존 원안의 "L3 SBOM 전용" 의미가 약해진다.

2. `PackageRecord`는 계속 `L3_SBOM` 전용으로 유지한다.
   - 장점: 원안과 완전히 동일하다.
   - 단점: L1의 package-level 결과는 별도 내부 모델이나 adapter가 필요하다.

### 현재 권고

- 통합 관점에서는 1번이 더 단순하지만, 이건 코드가 아니라 정책 결정에 가깝다.
- 따라서 팀 합의 전까지는 현재 구현이 "임시 확장"임을 전제로 유지한다.

## 항목 2. `FixSuggestion`의 공통 스키마 전환 범위

### 현재 상태

- `FixSuggestion`은 아직 L2 내부 운영 모델이다.
- 필드명과 구조가 공통 스키마와 다르다.
  - `issue_id`
  - `kisa_reference`
  - `reachability` (자연어 설명)
  - `category`
  - `patch_diff`
  - `confidence_score`
  - `processing_trace`

### 왜 조율이 필요한가

- 현재 L1 normalized output은 공통 스키마 기준으로 맞추기 시작했지만,
  L2 결과 모델까지 한 번에 바꾸면 영향 범위가 크다.
- 따라서 "L2 출력도 바로 공통 스키마 본체로 바꿀지", 아니면
  "공통 필드 + L2 전용 metadata" 구조로 단계 전환할지를 먼저 정해야 한다.

### 권고 방향

- 공통 필드:
  - `vuln_id`
  - `kisa_ref`
  - `reachability_status`
  - `fix_suggestion`
  - `status`
  - `evidence`
- L2 전용 필드:
  - `confidence_score`
  - `confidence_reason`
  - `patch_diff`
  - `processing_trace`
  - `retrieval_backend`
  - `chroma_status`
  - `registry_status`
  - `osv_status`

즉, 공통 스키마 필드는 공통 이름으로 맞추고, L2 전용 값은 `metadata.l2` 같은 확장 블록으로 분리하는 방향이 가장 안전하다.

## 항목 3. 후속 구현 순서

팀 합의 후에는 아래 순서로 반영한다.

1. `PackageRecord.source` 정책 확정
2. `FixSuggestion`의 공통 필드와 L2 전용 필드 분리 기준 확정
3. `models/common_schema.py` 최종 반영
4. `layer1/common/schema_normalizer.py`와 `ScanResult` 출력 계약 재정리
5. `FixSuggestion` -> 공통 스키마/metadata 구조 전환
6. 로그, 대시보드, MCP 계약 테스트 갱신

## 메모

- 현재 상태는 "통합을 위한 1차 적용" 단계다.
- 즉시 동작에는 문제 없지만, 공통 스키마를 팀 전체 기준으로 고정하려면 위 두 항목은 반드시 합의가 필요하다.
