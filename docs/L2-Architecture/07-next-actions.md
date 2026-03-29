# Next Actions

## 1. 현재 상태

현재 기준으로 완료된 범위:

- L2 retrieval / verification / patch / confidence / MCP 정렬
- L1 통합 scanner 연결
- L1 normalized output 공통 스키마 적용
- L2 결과의 공통 스키마 handoff record 생성
- `FixSuggestion`을 공통 필드 + `metadata.l2` 구조로 정리
- 공용 deduplicate 로직 도입

## 2. 바로 남은 작업

우선순위는 아래 순서가 맞다.

1. `PackageRecord.source` 정책 팀 합의
2. `FixSuggestion` 레거시 호환 property / 로그 키 정리 시점 결정
3. L3 handoff 최종 계약 확정
4. 실제 L1 고도화 경로와 현재 통합 scanner 정합 점검
5. verifier 외부 API 연동 여부 결정

## 3. 후속 리팩토링 후보

- `FixSuggestion` property 접근을 `metadata.l2` 직접 접근으로 통일
- 로그의 레거시 flat 키를 언제 제거할지 결정
- 실제 L1과 mock/scaffold 경로를 분리하거나 통합하는 기준 정리
- 대시보드/API 문서에서 공통 스키마 중심 설명 강화

## 4. 지금 당장 하지 않는 것

- multi-file patch
- 실제 파일 자동 수정/백업
- production-grade 외부 API 최적화
- L3 구현 세부 로직

현재 단계는 기능 공백을 메우는 구간보다, 통합된 구조를 팀 공통 기준으로 고정하는 구간에 가깝다.
