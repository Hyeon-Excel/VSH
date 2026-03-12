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

- `FixSuggestion`은 여전히 L2 내부 운영 모델이지만,
  현재는 공통 필드와 `metadata.l2`를 함께 가지는 구조로 1차 전환이 끝난 상태다.
- 공통 필드로 정리된 값:
  - `vuln_id`
  - `kisa_ref`
  - `reachability_status`
  - `reachability_confidence`
  - `evidence`
  - `fix_suggestion`
  - `status`
- L2 전용 운영 값은 `metadata.l2`에 들어간다.
  - `confidence_score`
  - `confidence_reason`
  - `patch_diff`
  - `processing_trace`
  - `retrieval_backend`
  - `chroma_status`
  - `registry_status`
  - `osv_status`
- `issue_id`, `kisa_reference`, `reachability` 같은 예전 이름은 현재 property 호환만 제공한다.

### 왜 조율이 필요한가

- `FixSuggestion` 자체는 이미 공통 필드 + metadata 구조로 옮기기 시작했지만,
  어디까지를 레거시 호환으로 유지할지와 외부 표면에서 flat 키를 언제 걷을지는 아직 정해야 한다.
- 즉, 지금 남은 쟁점은 "전환 여부"가 아니라
  "legacy 호환을 언제 제거할지"와 "로그/MCP 표면도 metadata 중심으로 얼마나 빨리 정리할지"에 가깝다.

### 권고 방향

- 현재 방향은 유지한다.
- 즉, 공통 스키마 필드는 공통 이름으로 맞추고, L2 전용 값은 `metadata.l2` 같은 확장 블록으로 분리한다.
- 남은 작업은 이 구조를 기준으로 로그, 대시보드, MCP가 언제까지 레거시 키를 병행할지 정하는 것이다.

## 항목 3. 후속 구현 순서

팀 합의 후에는 아래 순서로 반영한다.

1. `PackageRecord.source` 정책 확정
2. `FixSuggestion` 레거시 호환 필드 제거 시점 확정
3. `models/common_schema.py` 정책 최종 반영
4. 로그, 대시보드, MCP 표면에서 legacy flat 키 제거 시점 정리

## 메모

- 현재 상태는 "공통 스키마 1차 적용 + legacy 호환 유지" 단계다.
- 즉시 동작에는 문제 없지만, 공통 스키마를 팀 전체 기준으로 고정하려면 위 두 항목은 여전히 합의가 필요하다.
