# L1 Test Result

- 작성 시각: 2026-02-26 15:56:22 KST
- 대상 프로젝트: `/Users/hyeonexcel/Documents/Workspace/VSH`
- 커밋 SHA: `c28d40b`

## 1. 판정 요약

- 전체 판정: PASS
- Pytest 통과율: 17/17 (100.0%)
- Smoke 테스트: PASS
- 성능 게이트: PASS

## 2. 성능 지표(D4)

- cache miss p95: 979.38 ms (기준 <= 2500 ms)
- cache hit p95: 0.22 ms (기준 <= 200 ms)
- cache miss p50: 957.32 ms
- cache hit p50: 0.13 ms

## 3. 실패 케이스

- 없음

## 4. 미구현/잔여 리스크

- TypeScript alias/multiline import 추출 확장 케이스 추가 필요
- GitHub branch protection에서 `L1 CI Gate / L1 Tests`를 required check로 지정 필요
- 패키지 실존성/타이포스쿼팅 검증은 L2 구현 연동 필요

## 5. 실행 산출물

- 통합 로그: `/Users/hyeonexcel/Documents/Workspace/VSH/artifacts/test-results/l1/l1_test_20260226_155548.log`
- Pytest 로그: `/Users/hyeonexcel/Documents/Workspace/VSH/artifacts/test-results/l1/l1_pytest_20260226_155548.log`
- Smoke 로그: `/Users/hyeonexcel/Documents/Workspace/VSH/artifacts/test-results/l1/l1_smoke_20260226_155548.log`
- 성능 JSON: `/Users/hyeonexcel/Documents/Workspace/VSH/artifacts/test-results/l1/l1_perf_20260226_155548.json`

## 6. 기준 문서

- `docs/layer1.md`
- `docs/roadmap.md`
