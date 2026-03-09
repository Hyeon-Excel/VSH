# L2 Branch Strategy and History

## 1. 현재 운영 방식

현재 Layer 2 개발은 `layer2-dev` 브랜치 하나를 중심으로 계속 진행한다.

운영 기준은 아래와 같다.

- `main`
  - 상대적으로 안정적인 기준 브랜치
- `layer2`
  - L2 통합 브랜치
  - `layer2-dev`에서 충분히 정리된 내용을 최종 반영하는 대상
- `layer2-dev`
  - 실제 개발이 계속 이어지는 장기 작업 브랜치
  - 문서, 계약, 파이프라인, retriever, verifier, patch 작업을 순차적으로 누적

## 2. 브랜치 흐름

```text
main
  -> layer2
      -> layer2-dev
```

현재 기준선은 `VSH_Project_MVP`이며, `src/vsh`가 아니라 이 코드베이스를 계속 확장한다.

## 3. 운영 원칙

- 일상적인 L2 개발은 `layer2-dev`에서 직접 진행
- 기능이 어느 정도 안정화되면 `layer2`로 반영
- milestone 단위 검증이 끝나면 `main`으로 반영 검토
- 병렬 작업이 꼭 필요한 경우에만 임시 하위 브랜치 사용

## 4. 버전 규칙

- `v0.1.x`: 문서화와 구조 정리
- `v0.2.x`: 계약 정리, 파이프라인 안정화, 로컬 테스트 가능화
- `v0.3.x`: evidence retrieval
- `v0.4.x`: registry / osv verification
- `v0.5.x`: patch 및 integration
- `v1.0.0`: `layer2 -> main` 머지 검토 가능한 안정 상태

현재 작업 버전은 `v0.8.1-dev`로 본다.

## 5. 히스토리 기록 규칙

새 커밋을 만들 때마다 아래 표에 한 줄씩 추가한다.

기록 항목:

- 날짜
- 버전
- 상태
- 커밋 해시
- 작업 범위
- 핵심 변경 내용
- 검증 결과

상태 값:

- `committed`
- `working tree`
- `merged`

## 6. 버전 / 커밋 히스토리

| 날짜 | 버전 | 상태 | 커밋 | 작업 범위 | 핵심 변경 내용 | 검증 |
|------|------|------|------|-----------|----------------|------|
| 2026-03-08 | v0.0.1 | committed | `27e58c4` | 저장소 정리 | 루트 `.gitignore` 추가, 파이썬 캐시 추적 제거 | 별도 테스트 없음 |
| 2026-03-08 | v0.1.0 | committed | `8bc3e85` | L2 문서화 | L2 문서를 폴더 구조로 분리하고 설계/로드맵 기준선 확정 | 문서 작업 |
| 2026-03-09 | v0.2.0 | committed | `d22251a` | 계약 및 파이프라인 안정화 | `file_path` 메타데이터 추가, import lazy loading, SBOM 파일 귀속 수정, `analysis_failed` 로깅, 대시보드 L2 메타데이터 노출, mock analyzer 추가, `LLM_PROVIDER=mock` 기반 로컬 E2E 경로 구축, `requirements.txt` 정리 | `pytest tests/test_mock_analyzer.py tests/test_l2_contracts.py -q` -> `9 passed`, `pytest tests/test_e2e.py -q` -> `3 passed, 1 skipped` |
| 2026-03-09 | v0.3.0 | committed | `0c76f33` | evidence retrieval | `EvidenceRetriever` 추가, pipeline -> retriever -> analyzer 흐름 연결, evidence refs / summary 응답 및 로그 반영, 대시보드 evidence 표면 추가 | `pytest tests/test_l2_retriever.py tests/test_mock_analyzer.py tests/test_l2_contracts.py -q` -> `11 passed`, `pytest tests/test_e2e.py -q` -> `3 passed, 1 skipped` |
| 2026-03-09 | v0.4.0 | committed | `f59a925` | verifier 구현 및 L2 패키지 분리 | `RegistryVerifier`, `OsvVerifier` 추가, pipeline verification 후처리 연결, verifier 결과를 response/log/dashboard에 반영, L2 전용 파일을 `layer2/` 패키지로 이동 | `pytest tests/test_l2_verifiers.py tests/test_l2_retriever.py tests/test_mock_analyzer.py tests/test_l2_contracts.py -q` -> `14 passed`, `pytest tests/test_e2e.py -q` -> `3 passed, 1 skipped` |
| 2026-03-09 | v0.5.0 | committed | `657b566` | patch builder 구현 | `PatchBuilder` 추가, verifier 이후 patch preview 생성, response/log/dashboard에 patch diff 반영, patch 테스트 추가 | `pytest tests/test_l2_patch_builder.py tests/test_l2_verifiers.py tests/test_l2_retriever.py tests/test_mock_analyzer.py tests/test_l2_contracts.py -q` -> `16 passed`, `pytest tests/test_e2e.py -q` -> `3 passed, 1 skipped` |
| 2026-03-09 | v0.8.1-dev | working tree | `uncommitted` | analyzer 컨텍스트 통합 | retrieval와 verification 결과를 analyzer 입력 컨텍스트로 병합하고, mock/Gemini/Claude analyzer가 `verification_summary`, retrieval backend, Chroma 상태를 판단 및 출력 메타데이터에 반영하도록 보강 | `cd VSH_Project_MVP && python -m pytest tests/test_mock_analyzer.py tests/test_l2_contracts.py tests/test_l2_retriever.py tests/test_l2_verifiers.py tests/test_l2_patch_builder.py tests/test_e2e.py -q` -> `27 passed, 1 skipped` |

## 7. 다음 버전 목표

다음 목표 버전은 `v0.8.0`이다.

범위:

- patch / recommendation 출력 형식 정교화
- L3 연계를 위한 응답 정제
- 최종 통합 품질 보강
- `layer2 -> main` 머지 전 최종 안정화

## 8. 문서 유지 방법

`layer2-dev`에서 새 커밋을 만들 때는 아래 순서를 같이 지킨다.

1. 코드 변경
2. 테스트 또는 smoke 확인
3. `04-branch-strategy.md` 히스토리 표에 새 행 추가 또는 working tree 행 갱신
4. 커밋

이 문서는 브랜치 전략 문서이면서 동시에 L2 개발 이력 문서로 사용한다.
