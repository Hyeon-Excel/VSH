# L2 Roadmap and Milestones

> 중요: 이 문서는 현재 코드베이스 기준으로 갱신된 로드맵이다.
> 과거 `src/vsh` 복구 계획은 더 이상 기준선이 아니며,
> 현재 실제 구현 기준선은 `VSH_Project_MVP/layer2`와 `VSH_Project_MVP/orchestration`이다.

## 1. 구현 우선순위

구현은 아래 순서를 유지한다.

1. 현재 기준선 정리
2. L2 orchestration 골격 정리
3. evidence retrieval 구현
4. verifier 구현
5. patch 생성 구현
6. 통합 테스트
7. 품질 보강

이 순서를 바꾸면 계약 변경 비용이 커진다.

## 2. 단계별 로드맵

### Phase 0. 현재 기준선 확정

목표:

- 현재 기준선이 `VSH_Project_MVP/layer2`임을 명확히 함
- `layer2`, `orchestration`, `models` 간 계약 정리
- 실제 코드가 없는 `src/vsh` 계획을 로드맵 기준선에서 제거

작업:

- `models/fix_suggestion.py` 계약 정리
- `orchestration/analysis_pipeline.py` 진입 흐름 정리
- `layer2/` 하위 책임 분리 기준 확정

완료 기준:

- `PipelineFactory.create()`로 L2 실행 가능
- 최소 smoke test 통과

### Phase 1. 계약 고정

목표:

- request/response 모델 고정
- `AnalysisPipeline.run()` 기준 출력 계약 고정
- category별 처리 방향 고정

작업:

- 모델 정의
- pipeline 골격 구현
- placeholder verification summary 반환

완료 기준:

- fixture request 입력 시 response 생성
- 빈 finding 입력 처리 가능

### Phase 2. Retrieval 구현

목표:

- finding에 근거를 붙일 수 있는 최소 기능 확보

작업:

- local JSON 또는 mapping 기반 evidence lookup
- 우선순위 규칙 구현
- evidence refs 반영
- rationale 및 recommendation 기본 템플릿 적용

완료 기준:

- 대표 finding 3종 이상에서 evidence refs 생성
- 근거가 없을 때도 오류 없이 동작

### Phase 3. Verification 구현

목표:

- 공급망 관련 finding을 검증 가능한 구조로 전환

작업:

- registry adapter 구현
- osv adapter 구현
- 응답 정규화
- timeout 및 실패 fallback 처리

완료 기준:

- fixture 기반 정상 및 실패 테스트 통과
- `FOUND`, `NOT_FOUND`, `UNKNOWN`, `ERROR` 상태 구분

### Phase 4. Patch 생성 구현

목표:

- 수정 결과물을 response에 포함

작업:

- deterministic patch 생성 로직 구현
- 필요 시 LLM 기반 patch generation 연결
- code finding patch 생성
- supply chain finding recommendation 또는 patch 생성

완료 기준:

- code finding 최소 2종에서 patch 생성
- 생성 실패 시 graceful fallback

### Phase 5. 통합 품질 보강

목표:

- downstream에서 바로 소비 가능한 응답 완성

작업:

- response 필드 정리
- patch preview 형식 정리
- logging 추가
- 처리 경로 가시성 추가

완료 기준:

- integration test 통과
- 오류와 정상 경로 모두 추적 가능

## 3. 마일스톤 계획

### Milestone 1. L2 Skeleton

산출물:

- 공통 모델
- `AnalysisPipeline` 기본 골격
- placeholder retriever 및 verifier

완료 기준:

- pipeline 실행 성공
- 빈 입력 및 기본 fixture 처리 가능

### Milestone 2. Evidence Ready

산출물:

- retriever 구현
- 근거가 붙은 finding

완료 기준:

- 대표 finding 3종에 evidence refs 생성

### Milestone 3. Verification Ready

산출물:

- registry verifier
- osv verifier
- verification summary

완료 기준:

- 공급망 fixture 검증 흐름 통과

### Milestone 4. Patch Ready

산출물:

- patch builder
- code finding patch
- version bump recommendation 또는 patch

완료 기준:

- patch 포함 response 생성

### Milestone 5. Integration Ready

산출물:

- 통합 테스트
- 문서 정리
- `layer2` 기준 안정 상태

완료 기준:

- `layer2 -> main` 머지 검토 가능
