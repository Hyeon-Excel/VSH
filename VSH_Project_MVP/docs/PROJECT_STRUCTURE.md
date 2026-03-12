# PROJECT_STRUCTURE.md

## 1. 현재 기준선

현재 VSH의 실제 구현 기준선은 `VSH_Project_MVP/`이다.

```text
VSH_Project_MVP/
  shared/         # 공통 추상 계약, finding dedup 유틸
  models/         # ScanResult, Vulnerability, FixSuggestion, common_schema
  repository/     # knowledge/fix/log 저장소
  layer1/         # L1 scanner 및 보조 로직
  layer2/         # L2 analyzer/retriever/verifier/common/patch
  orchestration/  # L1 -> L2 조립과 실행
  interfaces/     # MCP 서버
  dashboard/      # 웹 UI/API
  modules/        # 구 경로 호환 wrapper
  pipeline/       # 구 경로 호환 wrapper
  tools/          # 구 경로 호환 wrapper
```

## 2. 패키지별 역할

### `shared/`

- `contracts.py`
  - `BaseScanner`
  - `BaseAnalyzer`
- `finding_dedup.py`
  - `deduplicate_findings()`

공통 계약과 공통 finding 병합 규칙을 가진다.

### `models/`

- `scan_result.py`
- `vulnerability.py`
- `fix_suggestion.py`
- `common_schema.py`

레이어 간 payload와 공통 record 기준을 가진다.

### `layer1/`

#### `layer1/scanner/`

- `mock_semgrep_scanner.py`
- `treesitter_scanner.py`
- `sbom_scanner.py`
- `vsh_l1_scanner.py`

#### `layer1/common/`

- `pattern_scan.py`
- `import_risk.py`
- `reachability.py`
- `schema_normalizer.py`
- `code_annotator.py`

L1 탐지, 정규화, annotation preview를 담당한다.

### `layer2/`

#### `layer2/analyzer/`

- `base_llm_analyzer.py`
- `mock_analyzer.py`
- `gemini_analyzer.py`
- `claude_analyzer.py`
- `confidence_support.py`

#### `layer2/retriever/`

- `evidence_retriever.py`
- `chroma_retriever.py`

#### `layer2/verifier/`

- `registry_verifier.py`
- `osv_verifier.py`

#### `layer2/common/`

- `requirement_parser.py`
- `schema_mapper.py`

#### `layer2/`

- `patch_builder.py`

L1 finding을 받아 evidence, verification, 판단, patch, 공통 스키마 handoff를 생성한다.

### `orchestration/`

- `base_pipeline.py`
- `analysis_pipeline.py`
- `pipeline_factory.py`

L1과 L2를 조립하고 외부 호출에 맞는 결과를 만든다.

### `interfaces/`

- `mcp/server.py`

공개 MCP 계약을 제공한다.

### `dashboard/`

- `app.py`
- `templates/index.html`

로그 조회, 상태 변경, provenance/patch/confidence 시각화를 담당한다.

## 3. L1 / L2 / L3 연결 지점

### L1 확장 지점

- `layer1/scanner/`
- `layer1/common/`
- `orchestration/pipeline_factory.py`

### L2 확장 지점

- `layer2/retriever/`
- `layer2/verifier/`
- `layer2/analyzer/`
- `layer2/patch_builder.py`
- `layer2/common/schema_mapper.py`

### L3 연결 지점

가장 자연스러운 handoff 지점은 `orchestration/analysis_pipeline.py`다.

현재 L3가 활용할 수 있도록 준비된 출력:

- `l2_vuln_records`
- `summary`
- `l2_vuln_record`가 포함된 log entry
- `FixSuggestion`의 공통 필드와 `metadata.l2`

## 4. 호환 경로

아래 경로는 현재도 import 가능하지만, 새 구현 기준선은 아니다.

- `modules/`
- `pipeline/`
- `tools/`

예:

- 권장: `from orchestration import PipelineFactory`
- 호환: `from pipeline import PipelineFactory`

- 권장: `from shared.contracts import BaseScanner`
- 호환: `from modules.base_module import BaseScanner`

## 5. 요약

- `layer1/`: 탐지 + 정규화 + annotation preview
- `layer2/`: 보강 + 검증 + 판단 + patch + handoff
- `orchestration/`: L1-L2 연결과 결과 조립
- `interfaces/`, `dashboard/`: 외부 표면
- `models/`, `shared/`, `repository/`: 공통 기반
