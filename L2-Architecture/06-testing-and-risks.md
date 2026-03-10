# L2 Testing and Risks

## 1. 테스트 전략

### 단위 테스트

대상:

- retriever
- registry verifier
- osv verifier
- patch builder
- service orchestration

원칙:

- 외부 네트워크 없는 fixture 기반 테스트 우선
- LLM 호출은 mock 또는 fake client 사용

### 통합 테스트

대상:

- code finding -> enrichment + patch
- supply chain finding -> verification summary
- 하위 컴포넌트 일부 실패 -> fail-soft 응답

### 회귀 테스트

반드시 막아야 할 문제:

- evidence 없음으로 전체 요청 실패
- verifier timeout으로 전체 응답 중단
- patch 실패 시 response 자체가 비어버림
- finding ID 또는 순서가 호출마다 흔들림

## 2. 품질 게이트

기능 브랜치를 `layer2`로 머지하기 전 최소 기준:

- 관련 단위 테스트 통과
- import 오류 없음
- 기존 핵심 fixture 회귀 없음

`layer2`를 `main`으로 올리기 전 최소 기준:

- L2 smoke 통과
- 핵심 통합 테스트 통과
- 문서와 구현 불일치 없음

## 3. 리스크 관리

### 리스크 1. 저장소 구조 불안정

대응:

- `VSH_Project_MVP`를 현재 기준선으로 고정
- `src/vsh`는 구현 기준선이 아니라 과거 검토 흔적으로만 취급

### 리스크 2. 외부 검증 API 불안정

대응:

- timeout
- retry 제한
- 상태값 fallback

### 리스크 3. patch 품질 불안정

대응:

- 초기에는 deterministic patch 우선
- 복잡한 경우 recommendation만 반환 허용

### 리스크 4. 설계 변경 빈도 증가

대응:

- 모델 계약 먼저 고정
- service는 adapter 조합형으로 구현
- verifier와 patch builder 분리

### 리스크 5. 통합 브랜치 오염

대응:

- 큰 작업은 기능 브랜치에서 진행
- `layer2` 직접 수정은 문서 및 작은 계약 변경으로 제한
- milestone마다 정리 커밋 수행
