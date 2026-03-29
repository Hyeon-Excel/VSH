# Branch Strategy and History

## 1. 현재 기준 브랜치

현재 작업 기준은 아래와 같다.

- `main`
  - 상대적으로 안정적인 기준 브랜치
- `layer2`
  - L2 통합 기준 브랜치
  - `layer2-dev`의 주요 작업이 반영된 상태
- `codex/l1-l2-integration`
  - 현재 활성 작업 브랜치
  - `layer2`를 베이스로 L1-L2 통합과 공통 스키마 정렬을 진행 중

## 2. 브랜치 흐름

```text
main
  -> layer2
      -> codex/l1-l2-integration
```

`layer2-dev`는 장기 개발 브랜치 역할을 마치고 `layer2`에 머지된 이후 정리 대상으로 본다.

## 3. 운영 원칙

- L2 단독 기능 확장은 `layer2`를 기준으로 분기한다.
- L1-L2 구조 통합과 공통 스키마 정렬은 `codex/l1-l2-integration`에서 진행한다.
- milestone 검증이 끝나면 `layer2`로 반영하고, 이후 `main` 머지를 검토한다.
- 문서에는 현재 기준 브랜치와 실제 테스트 상태를 같이 남긴다.

## 4. 최근 이력

| 날짜 | 상태 | 커밋 | 작업 범위 | 검증 |
|------|------|------|-----------|------|
| 2026-03-10 | committed | `25d0f9e` | MCP 계약 정렬 | `29 passed, 1 skipped` |
| 2026-03-10 | committed | `3dc9b3d` | L2 confidence / decision 가시화 | `29 passed, 1 skipped` |
| 2026-03-10 | committed | `0acc785` | L2 analyzer 공통화, Gemini SDK 전환, Chroma 활성 검증 | `33 passed, 1 skipped` |
| 2026-03-12 | committed | `3e44033` | L1 통합 scanner 초안 추가 | `38 passed, 1 skipped` |
| 2026-03-12 | committed | `e22f27d` | L1 정규화 결과 및 annotation preview 추가 | `39 passed, 1 skipped` |
| 2026-03-12 | committed | `a786782` | 파이프라인과 MCP에 L1 normalized output 노출 | `40 passed, 1 skipped` |
| 2026-03-12 | committed | `05ac96a` | L1 provenance를 L2 결과 표면에 반영 | `40 passed, 1 skipped` |
| 2026-03-12 | committed | `a0a4648` | 공통 스키마 1차 적용과 조율 메모 추가 | `40 passed, 1 skipped` |
| 2026-03-12 | committed | `398c9c6` | L2 공통 스키마 handoff record 추가 | `40 passed, 1 skipped` |
| 2026-03-12 | committed | `700d2df` | L2 공통 스키마 record를 로그/MCP 표면에 반영 | `40 passed, 1 skipped` |
| 2026-03-12 | committed | `7f9e4ff` | FixSuggestion을 공통 필드 + metadata.l2 구조로 정리 | `40 passed, 1 skipped` |
| 2026-03-12 | committed | `a9a2c8b` | 공용 deduplicate 로직으로 finding 병합 기준 통일 | `41 passed, 1 skipped` |

## 5. 현재 판단

현재 브랜치 기준으로:

- L2 단독 확장은 사실상 1차 완료
- L1-L2 통합은 1차 완료
- 공통 스키마 적용은 1차 완료
- 남은 작업은 정책 정리와 후속 고도화에 가깝다

## 6. 다음 반영 규칙

1. 코드 변경
2. `pytest tests -q` 또는 범위별 회귀 확인
3. 관련 문서 갱신
4. `layer2` 반영 여부 검토

이 문서는 현재 작업 브랜치 기준의 운영 메모이자 개발 이력 문서로 유지한다.
