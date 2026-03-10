# PROJECT_STRUCTURE.md

## 1. 현재 실제 구현 기준선

현재 VSH 프로젝트의 실제 동작 기준선은 `VSH_Project_MVP`이다.

핵심 패키지 역할은 아래와 같다.

```text
VSH_Project_MVP/
  shared/         # L1/L2/L3 공통 추상 계약
  models/         # 레이어 간 전달 모델
  repository/     # 데이터 접근 계층
  layer1/         # L1 탐지 구현체
  layer2/         # L2 보강/검증/수정 제안 구현체
  orchestration/  # L1 -> L2 흐름 조립
  interfaces/     # MCP 같은 외부 진입점
  dashboard/      # 대시보드 UI/API
  modules/        # 구 경로 호환 wrapper
  pipeline/       # 구 경로 호환 wrapper
  tools/          # 구 경로 호환 wrapper
```

## 2. 패키지별 책임

### `shared/`

- `contracts.py`
  - `BaseScanner`
  - `BaseAnalyzer`

L1, L2, 향후 L3가 공통으로 맞춰야 할 추상 계약이다.

### `models/`

- `ScanResult`
- `Vulnerability`
- `FixSuggestion`

레이어 간 전달 payload는 모두 여기 모델을 기준으로 유지한다.

### `repository/`

- `MockKnowledgeRepo`
- `MockFixRepo`
- `MockLogRepo`
- `BaseReadRepository`
- `BaseWriteRepository`

현재는 Mock JSON 기반이며, 실제 DB로 바꿀 때 이 레이어가 교체 지점이다.

### `layer1/`

- `scanner/mock_semgrep_scanner.py`
- `scanner/treesitter_scanner.py`
- `scanner/sbom_scanner.py`

L1 구현체 전용 영역이다. 실제 Semgrep, SonarQube, 새로운 언어 스캐너를 붙일 위치도 여기다.

### `layer2/`

- `analyzer/`
- `retriever/`
- `verifier/`
- `common/`
- `patch_builder.py`

L1 findings를 받아 근거 보강, 검증, 수정 제안, 신뢰도 판단까지 수행하는 영역이다.

### `orchestration/`

- `base_pipeline.py`
- `analysis_pipeline.py`
- `pipeline_factory.py`

L1과 L2를 실제로 조립하는 통합 지점이다.
향후 L3가 붙으면 이 레이어 또는 그 상위 orchestration이 L2 -> L3 handoff 지점이 된다.

### `interfaces/`

- `mcp/server.py`

MCP 계약을 외부에 공개하는 진입점이다.

### `dashboard/`

- `app.py`
- `templates/index.html`

사람이 보는 검토 UI와 상태 변경 인터페이스다.

## 3. L1 / L2 / L3 연결 지점

### L1을 붙일 위치

- 실제 L1 스캐너 구현 추가: `layer1/scanner/`
- 스캐너 조립 변경: `orchestration/pipeline_factory.py`

### L2를 확장할 위치

- retrieval 확장: `layer2/retriever/`
- verifier 확장: `layer2/verifier/`
- analyzer 확장: `layer2/analyzer/`
- patch 확장: `layer2/patch_builder.py`

### L3를 붙일 위치

- 가장 자연스러운 handoff 지점: `orchestration/analysis_pipeline.py`
- 현재 L2 output contract 소비 위치 후보:
  - `FixSuggestion`
  - `summary`
  - `processing_trace`
  - `decision_status`
  - `confidence_score`

즉, L3는 `layer2/` 내부가 아니라 `orchestration/` 위에서 결과를 받아 후속 분석/리포팅을 수행하는 구조가 맞다.

## 4. 호환 경로

아래 경로는 기존 코드 호환을 위한 wrapper다.

- `modules/`
- `pipeline/`
- `tools/`

새 구현은 가능하면 이 wrapper가 아니라 실제 구현 경로를 직접 사용한다.

예:

- 권장: `from orchestration import PipelineFactory`
- 호환: `from pipeline import PipelineFactory`

- 권장: `from shared.contracts import BaseScanner`
- 호환: `from modules.base_module import BaseScanner`

## 5. 정리

- `layer1/`: 탐지
- `layer2/`: 보강/검증/수정 제안
- `orchestration/`: L1-L2-L3 연결
- `interfaces/`, `dashboard/`: 외부 노출
- `models/`, `repository/`, `shared/`: 공통 기반

현재 기준으로 파일 경계를 볼 때는 이 구조를 우선 기준으로 삼는다.
