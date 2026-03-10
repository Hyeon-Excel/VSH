# L2 Next Actions

## 1. 첫 구현 스프린트 목표

첫 스프린트 목표는 아래 수준까지다.

- 공통 유틸과 계약 정리
- L2 구현 중복 제거
- Analyzer 계층 공통화
- Gemini SDK 최신화
- Chroma 활성 환경 검증
- L3 handoff 계약 최종 정리

첫 스프린트에서 제외할 항목:

- multi-file patch
- production-grade 외부 API 최적화
- 실제 파일 자동 수정/백업 레이어

## 2. 즉시 다음 작업

지금 바로 시작할 작업은 아래 순서가 맞다.

1. L3 handoff contract 문서와 응답 payload 최종 정리
2. language 하드코딩 제거와 다중 언어 입력 경계 정리
3. analyzer/provider 오류 표면을 더 명시적인 결과 계약으로 정리
4. Tree-sitter Python 의존성 정리와 실제 L1 연결 경계 점검

## 3. 브랜치별 다음 작업

1. 일상 개발은 `layer2-dev`에서 계속 진행
2. milestone 단위로 `layer2`에 반영
3. 안정화 이후 `main` 반영 여부를 검토

이 순서를 따르면 구현과 통합 비용을 가장 낮게 유지할 수 있다.
