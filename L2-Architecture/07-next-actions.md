# L2 Next Actions

## 1. 첫 구현 스프린트 목표

첫 스프린트 목표는 아래 수준까지다.

- 공통 유틸과 계약 정리
- L2 구현 중복 제거
- Analyzer 계층 공통화
- Chroma 활성 환경 검증
- L3 handoff 계약 최종 정리

첫 스프린트에서 제외할 항목:

- multi-file patch
- production-grade 외부 API 최적화
- 실제 파일 자동 수정/백업 레이어

## 2. 즉시 다음 작업

지금 바로 시작할 작업은 아래 순서가 맞다.

1. `analysis_pipeline.py` 정규화/로그 저장 로직 분리
2. `GeminiAnalyzer` / `ClaudeAnalyzer` 공통 베이스 추출
3. 공급망 공통 유틸 테스트 커버리지 보강
4. `google.generativeai` -> `google.genai` 마이그레이션
5. Chroma 활성 환경 기준 end-to-end 검증
6. L3 handoff contract 문서와 응답 payload 최종 정리

## 3. 브랜치별 다음 작업

1. 일상 개발은 `layer2-dev`에서 계속 진행
2. milestone 단위로 `layer2`에 반영
3. 안정화 이후 `main` 반영 여부를 검토

이 순서를 따르면 구현과 통합 비용을 가장 낮게 유지할 수 있다.
