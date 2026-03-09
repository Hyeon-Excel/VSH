# L2 Next Actions

## 1. 첫 구현 스프린트 목표

첫 스프린트 목표는 아래 수준까지다.

- `src/vsh` L2 소스 복구
- `L2EnrichFixRequest/Response` 구현
- `L2Service.enrich_fix()` 동작
- `EvidenceRetriever` 기본 key lookup 구현
- `RegistryVerifier`, `OsvVerifier` 기본 placeholder 또는 fixture 기반 구현
- code finding 1종, supply chain finding 1종 테스트 통과

첫 스프린트에서 제외할 항목:

- 실제 vector DB
- 고도화된 diff UI
- multi-file patch
- production-grade 외부 API 최적화

## 2. 즉시 다음 작업

지금 바로 시작할 작업은 아래 순서가 맞다.

1. `src/vsh/common/models.py` 복구
2. `src/vsh/l2_warm/service.py` 복구
3. `src/vsh/l2_warm/rag/retriever.py` 구현
4. `src/vsh/l2_warm/verification/registry.py` 구현
5. `src/vsh/l2_warm/verification/osv.py` 구현
6. `tests/test_l2_service.py` 작성
7. `tests/fixtures/l2/` 생성

## 3. 브랜치별 다음 작업

1. 현재 문서 정리는 `layer2`에 반영
2. 모델 복구는 `codex/l2-contracts`
3. retrieval은 `codex/l2-retriever`
4. registry와 osv는 각 기능 브랜치
5. patch builder는 별도 브랜치
6. 마지막 통합은 `layer2`

이 순서를 따르면 구현과 통합 비용을 가장 낮게 유지할 수 있다.
