# L2 Branch Strategy

## 1. 운영 원칙

Layer 2 개발은 `main`에서 직접 진행하지 않는다.

운영 기준은 아래와 같다.

- `main`
  - 저장소의 상대적으로 안정적인 기준 브랜치
- `layer2`
  - L2 개발용 통합 브랜치
  - L2 관련 문서, 계약, 통합 결과를 모으는 브랜치
- 기능 브랜치
  - `layer2`에서 파생
  - 특정 기능 단위 구현 후 `layer2`로 머지

즉 `layer2`는 L2 프로젝트의 작업 메인 역할을 하고, 최종 안정화 후 `main`으로 올린다.

## 2. 브랜치 계층

```text
main
  -> layer2
      -> layer2-contracts
      -> layer2-retriever
      -> layer2-registry
      -> layer2-osv
      -> layer2-patch-builder
      -> layer2-integration
```

## 3. 브랜치별 책임

### `main`

- 안정 상태 유지
- 큰 기능이 완성되기 전에는 직접 변경 최소화

### `layer2`

- L2 통합 기준
- 문서 변경
- 모델 계약 반영
- 기능 브랜치 머지 후 통합 확인

### 기능 브랜치

- 하나의 기능만 다룬다
- 짧게 유지한다
- 완료 후 `layer2`로 머지한다

## 4. 기능 브랜치 네이밍

권장 예시:

- `layer2-contracts`
- `layer2-retriever`
- `layer2-registry`
- `layer2-osv`
- `layer2-patch-builder`
- `layer2-tests`

## 5. 현재 개발 방식 제안

현재는 한 명이 개발하더라도 아래 원칙을 유지하는 것이 좋다.

- 작은 문서 수정 정도만 `layer2`에 직접 반영
- 구현 작업은 기능 브랜치에서 진행
- 한 기능이 끝날 때마다 `layer2`에 머지
- `layer2`에서 통합 테스트와 구조 정리 수행

이 방식의 장점:

- 통합 브랜치가 항상 현재 진행 상황을 보여준다
- 기능별 롤백이 쉽다
- 구조 변경 충격 범위를 줄일 수 있다
- 이후 팀원이 합류해도 전략을 유지하기 쉽다

## 6. 머지 운영 규칙

- 머지 대상은 항상 `layer2`
- 한 PR 또는 한 머지는 하나의 기능 단위만 포함
- 머지 전 최소 테스트 수행
- 통합 후 `layer2`에서 smoke 확인
- milestone 완료 시점에만 `main`으로 머지

## 7. `main`으로 올리는 기준

다음 조건을 만족할 때 `layer2 -> main` 머지를 고려한다.

- 모델 계약 고정
- L2 service import 가능
- retriever 동작
- registry 및 osv verifier 기본 동작
- patch 생성 기본 동작
- 핵심 테스트 통과
