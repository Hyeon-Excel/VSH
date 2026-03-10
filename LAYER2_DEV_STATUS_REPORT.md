# layer2-dev 브랜치 상태 보고서

작성일: 2026-03-10  
작성 기준 저장소: `VSH`  
분석 기준 브랜치: `layer2-dev`

---

## 1. 보고서 기준과 근거

이 문서는 아래 사실을 기준으로 작성했다.

- 현재 브랜치: `layer2-dev`
- 현재 `HEAD`: `0acc7858b3d1dee0aac2e44b35c1c7f646ed5859`
- 비교 기준 브랜치 `layer2`: `8bc3e85be33aac68cedb0f7a04b4e308d8e0683c`
- `HEAD`와 `layer2`의 merge-base: `8bc3e85be33aac68cedb0f7a04b4e308d8e0683c`
- 즉, 현재 `layer2-dev`는 `layer2`에서 직접 갈라졌고, `layer2`는 아직 같은 기준 커밋에 머물러 있다.
- `layer2..HEAD` 커밋 수: `15`
- `layer2..HEAD` diff 통계: `75 files changed, 4870 insertions(+), 1048 deletions(-)`
- `layer2..HEAD` 파일 상태 요약:
  - modified: `28`
  - added: `43`
  - renamed: `1`
  - deleted: `3`
- 현재 working tree 상태: `3`개 엔트리 변경 중
- 최신 전체 테스트 실행 결과: `cd VSH_Project_MVP && python -m pytest tests -q` -> `33 passed, 1 skipped`

이 문서는 아래 파일과 실제 Git 상태를 함께 근거로 삼는다.

- `VSH_Project_MVP/PRD.md`
- `VSH_Project_MVP/ARCHITECTURE.md`
- `VSH_Project_MVP/docs/PROJECT_STRUCTURE.md`
- `VSH_Project_MVP/models/fix_suggestion.py`
- `VSH_Project_MVP/interfaces/mcp/server.py`
- `VSH_Project_MVP/dashboard/app.py`
- `L2-Architecture/04-branch-strategy.md`

---

## 2. 출발점: `layer2` 브랜치는 어디까지였는가

현재 `layer2` 브랜치가 가리키는 최신 커밋은 아래 하나다.

- `8bc3e85 docs: L2 설계 문서를 폴더 구조로 분리 및 정리`

즉, 현재 비교 기준인 `layer2`는 문서 정리 단계에 머물러 있고, 실제 L2 구현 코드가 누적된 브랜치는 `layer2-dev`다.

이 점은 다음 사실로 확인된다.

- `git rev-parse layer2`와 `git merge-base HEAD layer2`가 모두 `8bc3e85...`
- `git log --oneline layer2..HEAD`에 L2 구현 관련 커밋이 15개 존재

정리하면, `layer2-dev`는 “문서만 있던 `layer2` 기준선”에서 실제 동작 코드가 쌓인 브랜치다.

---

## 3. `layer2-dev`에서 실제로 어떻게 개발이 진행됐는가

`layer2..HEAD` 기준 커밋 이력은 아래와 같다.

| 순서 | 커밋 | 메시지 |
|------|------|--------|
| 1 | `d22251a` | feat: L2 파이프라인 계약 안정화 및 mock 분석 흐름 추가 |
| 2 | `0c76f33` | feat: L2 evidence retrieval 흐름 추가 및 메타데이터 표면 확장 |
| 3 | `f59a925` | refactor: L2 패키지 분리 및 verification 흐름 통합 |
| 4 | `657b566` | feat: L2 verification 및 patch preview 흐름 통합 |
| 5 | `62a5cc8` | feat: L2 처리 경로 추적 및 실행 요약 추가 |
| 6 | `21c0c6d` | feat: L2 handoff 응답 필드와 실행 요약 정제 |
| 7 | `14d1256` | feat: Chroma RAG retriever를 현재 L2 파이프라인에 통합 |
| 8 | `0019f43` | feat: KISA·금융보안원 체크리스트 RAG 상태 가시화 및 L2 런타임 경로 안정화 |
| 9 | `eda8b7a` | feat: L2 Chroma retrieval fallback과 source 우선순위 검색 강화 |
| 10 | `910da07` | feat: L2 analyzer에 retrieval 및 verification 컨텍스트 통합 |
| 11 | `25d0f9e` | feat: MCP 도구 인터페이스를 문서 계약에 맞게 정렬 |
| 12 | `3dc9b3d` | feat: L2 판단 신뢰도 메타데이터와 요약 집계 추가 |
| 13 | `3629097` | refactor: L2 공급망 공통 유틸과 문서 기준선 정리 |
| 14 | `9b9b845` | refactor: L1/L2/orchestration/interface 계층 구조를 재정리 |
| 15 | `0acc785` | refactor: L2 analyzer 공통화와 Chroma 활성 경로를 정리 |

커밋 흐름을 기능 관점으로 묶으면 다음과 같다.

### 3.1 계약과 로컬 실행 기반

- `FixSuggestion`에 L2 메타데이터가 확장됐다.
- `mock` provider 기반으로 API 키 없이 로컬에서 L2와 E2E 테스트가 가능해졌다.
- `analysis_failed`와 같은 실패 상태가 로그에 남도록 보강됐다.

근거 파일:

- `VSH_Project_MVP/models/fix_suggestion.py`
- `VSH_Project_MVP/orchestration/analysis_pipeline.py`
- `VSH_Project_MVP/layer2/analyzer/mock_analyzer.py`

### 3.2 retrieval / verification / patch / confidence

- `EvidenceRetriever`가 추가됐다.
- `RegistryVerifier`, `OsvVerifier`가 추가됐다.
- `PatchBuilder`가 추가됐다.
- `decision_status`, `confidence_score`, `confidence_reason`가 응답 모델에 포함됐다.
- `processing_trace`, `processing_summary`, `summary`가 파이프라인 결과에 포함됐다.

근거 파일:

- `VSH_Project_MVP/layer2/retriever/evidence_retriever.py`
- `VSH_Project_MVP/layer2/verifier/registry_verifier.py`
- `VSH_Project_MVP/layer2/verifier/osv_verifier.py`
- `VSH_Project_MVP/layer2/patch_builder.py`
- `VSH_Project_MVP/models/fix_suggestion.py`

### 3.3 Chroma RAG 통합

- `.chroma_db`가 브랜치에 포함됐다.
- `ChromaRetriever`가 추가됐다.
- retrieval 결과에 `retrieval_backend`, `chroma_status`, `chroma_summary`, `chroma_hits`가 포함됐다.
- 현재 `HEAD` 기준으로는 `google.genai` 전환, `BaseLlmAnalyzer` 공통화, Chroma exact metadata 우선 조회까지 반영됐다.

근거 파일:

- `VSH_Project_MVP/.chroma_db/chroma.sqlite3`
- `VSH_Project_MVP/layer2/analyzer/base_llm_analyzer.py`
- `VSH_Project_MVP/layer2/retriever/chroma_retriever.py`
- `VSH_Project_MVP/layer2/retriever/evidence_retriever.py`
- `VSH_Project_MVP/config.py`

### 3.4 MCP / Dashboard / 구조 개편

- MCP 공개 계약이 `validate_code`, `scan_only`, `get_results`, `apply_fix`, `dismiss_issue`, `get_log` 기준으로 정리됐다.
- Dashboard는 L2 메타데이터, evidence, verification, patch, confidence를 표시하도록 확장됐다.
- 실제 구현 경계가 `shared/`, `layer1/`, `layer2/`, `orchestration/`, `interfaces/`로 재편됐다.
- 기존 `modules/`, `pipeline/`, `tools/`는 호환 wrapper로 남겨졌다.

근거 파일:

- `VSH_Project_MVP/interfaces/mcp/server.py`
- `VSH_Project_MVP/dashboard/templates/index.html`
- `VSH_Project_MVP/docs/PROJECT_STRUCTURE.md`
- `VSH_Project_MVP/ARCHITECTURE.md`

---

## 4. `layer2` 대비 무엇이 바뀌었는가

### 4.1 새로 생긴 핵심 패키지/경로

`layer2` 브랜치에는 없고, `layer2-dev`에서 추가된 대표 경로는 아래와 같다.

- `VSH_Project_MVP/shared/`
- `VSH_Project_MVP/layer1/`
- `VSH_Project_MVP/layer2/`
- `VSH_Project_MVP/orchestration/`
- `VSH_Project_MVP/interfaces/`
- `VSH_Project_MVP/docs/PROJECT_STRUCTURE.md`
- `VSH_Project_MVP/layer2/analyzer/base_llm_analyzer.py`
- `VSH_Project_MVP/tests/test_l2_contracts.py`
- `VSH_Project_MVP/tests/test_l2_llm_analyzer_base.py`
- `VSH_Project_MVP/tests/test_l2_retriever.py`
- `VSH_Project_MVP/tests/test_l2_verifiers.py`
- `VSH_Project_MVP/tests/test_l2_patch_builder.py`
- `VSH_Project_MVP/tests/test_mock_analyzer.py`
- `VSH_Project_MVP/tests/test_mcp_server_contract.py`

### 4.2 이동/삭제된 경로

`layer2` 대비 이동 또는 삭제된 대표 경로는 아래와 같다.

- `VSH_Project_MVP/modules/analyzer/analyzer_factory.py` -> `VSH_Project_MVP/layer2/analyzer/analyzer_factory.py` (`R072`)
- `VSH_Project_MVP/modules/analyzer/claude_analyzer.py` 삭제
- `VSH_Project_MVP/modules/analyzer/gemini_analyzer.py` 삭제
- `VSH_Project_MVP/modules/analyzer/__init__.py` 삭제

즉, 기존 `modules/analyzer/*` 중심 구조에서 `layer2/analyzer/*` 중심 구조로 이동했다.

### 4.3 수정된 기존 핵심 파일

대표적으로 아래 파일이 크게 변했다.

- `VSH_Project_MVP/dashboard/templates/index.html`
- `VSH_Project_MVP/models/fix_suggestion.py`
- `VSH_Project_MVP/modules/base_module.py`
- `VSH_Project_MVP/modules/scanner/*.py`
- `VSH_Project_MVP/pipeline/*.py`
- `VSH_Project_MVP/tools/server.py`
- `VSH_Project_MVP/repository/log_repo.py`
- `VSH_Project_MVP/requirements.txt`

즉, `layer2-dev`는 문서 추가 수준이 아니라 실제 코드 구조와 실행 경로가 재편된 브랜치다.

---

## 5. 현재 `HEAD` 기준 구현 범위

현재 `HEAD`(`0acc785`) 기준으로 실제 구현되어 있는 범위는 아래와 같다.

### 5.1 L1 영역

존재하는 구현:

- `layer1/scanner/mock_semgrep_scanner.py`
- `layer1/scanner/treesitter_scanner.py`
- `layer1/scanner/sbom_scanner.py`

사실:

- L1 코드는 존재한다.
- 다만 PRD가 말한 “실제 Semgrep”이 아니라 현재 파일명과 구현 기준은 `mock_semgrep_scanner.py`다.

### 5.2 L2 영역

존재하는 구현:

- analyzer: `layer2/analyzer/`
- retriever: `layer2/retriever/`
- verifier: `layer2/verifier/`
- patch: `layer2/patch_builder.py`

현재 L2가 다루는 결과 필드:

- evidence: `evidence_refs`, `evidence_summary`
- retrieval: `retrieval_backend`, `chroma_status`, `chroma_summary`, `chroma_hits`
- verification: `registry_status`, `osv_status`, `verification_summary`
- patch: `patch_status`, `patch_summary`, `patch_diff`
- decision: `decision_status`, `confidence_score`, `confidence_reason`
- handoff: `category`, `remediation_kind`, `target_ref`
- trace: `processing_trace`, `processing_summary`

근거 파일:

- `VSH_Project_MVP/models/fix_suggestion.py`

즉, 현재 L2는 PRD의 초기 “AI 판단 + 수정 제안” 범위를 넘어 retrieval / verification / patch / confidence / handoff 메타데이터까지 포함한다.

### 5.3 Interface / Dashboard 영역

구현 사실:

- MCP 도구는 `validate_code`, `scan_only`, `get_results`, `apply_fix`, `dismiss_issue`, `get_log`로 정리되어 있다.
- Dashboard는 Accept / Dismiss를 제공한다.
- 다만 실제 파일 자동 수정은 하지 않고, `fixed_code` 반환과 상태 업데이트만 수행한다.

근거 파일:

- `VSH_Project_MVP/interfaces/mcp/server.py`
- `VSH_Project_MVP/dashboard/app.py`

`dashboard/app.py`에는 아래 사실이 코드 주석으로 직접 적혀 있다.

- “실제 소스 파일 수정은 하지 않으며, UI에서 fixed_code를 클립보드에 복사할 수 있도록 반환”

즉, 현재 Accept / apply_fix는 “실제 적용”이 아니라 “상태 업데이트 + fixed_code 반환” 단계다.

---

## 6. 현재 working tree 기준 추가 변경 사항

현재 `HEAD` 위에는 아직 커밋되지 않은 변경이 존재한다.

`git status --short` 기준 현재 working tree 엔트리는 `3`개다.

현재 항목은 아래 3개다.

- 수정됨:
  - `VSH_Project_MVP/.chroma_db/95ccabe6-eb05-4f19-8c6d-fcc63a2870c1/data_level0.bin`
  - `VSH_Project_MVP/.chroma_db/chroma.sqlite3`
- 미추적:
  - `LAYER2_DEV_STATUS_REPORT.md`

즉, 현재 working tree에는 코드 미커밋 변경은 없고, Chroma DB 바이너리 2개와 보고서 파일 1개만 남아 있다.

---

## 7. 궁극적인 VSH 프로젝트와 비교했을 때 어디까지 왔는가

아래 평가는 `PRD.md`, `ARCHITECTURE.md`, 현재 코드 상태를 함께 기준으로 한다.

### 7.1 PRD MVP 포함 항목 기준

| 항목 | PRD 기준 | 현재 상태 | 판단 | 근거 |
|------|----------|-----------|------|------|
| Python 지원 | MVP 지원 | 구현됨 | 달성 | `layer1/scanner/*`, `tests/test_e2e.py` |
| L1 탐지 | Semgrep + Tree-sitter + SBOM Mock | scanner 코드는 존재, Semgrep은 mock 구현 | 부분 달성 | `mock_semgrep_scanner.py`, `treesitter_scanner.py`, `sbom_scanner.py` |
| L2 AI 판단 + 수정 제안 | Claude API 기준 | Claude/Gemini/Mock + retrieval/verifier/patch까지 확장 | 달성 이상 | `layer2/analyzer/*`, `patch_builder.py` |
| Mock DB | JSON 파일 기반 | 구현됨 | 달성 | `repository/*`, `mock_db/*` |
| FastAPI Dashboard | Accept / Dismiss | 구현됨 | 달성 | `dashboard/app.py` |
| FastMCP validate_code | 도구 등록 | 구현됨 | 달성 | `interfaces/mcp/server.py` |
| Accept 시 파일 자동 수정 | PRD 포함 | 미구현 | 미달성 | `dashboard/app.py`, `interfaces/mcp/server.py` |
| 수정 전 원본 파일 백업 | PRD 포함 | 미구현 | 미달성 | 관련 구현 없음, `app.py` 주석상 미적용 |

### 7.2 PRD Post-MVP 항목 기준

| 항목 | PRD 기준 | 현재 상태 | 판단 | 근거 |
|------|----------|-----------|------|------|
| L3 (SonarQube, PoC, 리포트) | Post-MVP Phase 2 | 구현 없음 | 미도달 | 관련 패키지 없음 |
| 실제 Vector DB (ChromaDB) | Post-MVP Phase 3 | L2 retrieval 단계에서 부분 도입 | 부분 도달 | `.chroma_db`, `chroma_retriever.py` |
| VS Code Extension | Post-MVP | 구현 없음 | 미도달 | 관련 경로 없음 |
| CI/CD 연동 | Post-MVP | 구현 없음 | 미도달 | 관련 경로 없음 |
| 다중 파일 / 프로젝트 단위 스캔 | Post-MVP | 단일 파일 중심 | 미도달 | `BasePipeline.run(file_path: str)` |

### 7.3 아키텍처 목표 기준

| 아키텍처 목표 | 현재 상태 | 판단 | 근거 |
|--------------|-----------|------|------|
| L1 / L2 / L3 경계 명확화 | `shared`, `layer1`, `layer2`, `orchestration`, `interfaces`로 구조 재편 | 달성 | `docs/PROJECT_STRUCTURE.md`, `ARCHITECTURE.md` |
| wrapper 유지 | `modules`, `pipeline`, `tools` 유지 | 달성 | 실제 경로 존재 |
| 향후 L3 handoff 지점 확보 | `orchestration/analysis_pipeline.py` + `FixSuggestion` handoff 필드 존재 | 부분 달성 | `analysis_pipeline.py`, `fix_suggestion.py` |
| Mock DB -> 실제 DB 교체 포인트 | repository 추상은 유지되지만 Chroma는 retriever 쪽에도 직접 존재 | 부분 달성 | `repository/*`, `chroma_retriever.py` |

---

## 8. 현재 도달 수준에 대한 사실 기반 요약

### 8.1 L2만 놓고 보면

현재 `layer2-dev`는 문서 상태였던 `layer2`를 넘어, 실제 실행 가능한 L2 코드 브랜치가 되었다.

사실:

- retrieval 존재
- verifier 존재
- patch preview 존재
- confidence / decision 메타데이터 존재
- Chroma RAG 연결 코드 존재
- MCP 계약 정렬 존재
- 테스트 `33 passed, 1 skipped`

즉, 현재 L2는 초기 MVP 정의보다 넓은 범위를 구현했다.

### 8.2 VSH 전체 프로젝트로 보면

현재 브랜치는 “전체 VSH 완성본”은 아니다.

사실:

- L1은 mock semgrep 중심이라 PRD의 실제 Semgrep 기준에는 아직 미치지 않는다.
- Accept / apply_fix는 실제 파일 적용/백업이 아니다.
- L3는 아직 없다.
- 다중 파일 / 프로젝트 단위 / CI/CD / VS Code Extension은 아직 없다.

즉, 현재 `layer2-dev`는 다음 상태로 보는 것이 가장 정확하다.

- **L2 구현 브랜치로서는 고도화 단계**
- **VSH 전체 MVP로서는 부분 달성**
- **VSH 궁극 목표(Post-MVP/L3 포함)로서는 중간 단계**

---

## 9. 결론

사실만 요약하면 아래와 같다.

1. 현재 `layer2-dev`는 `layer2`보다 `15`개 커밋 앞서 있으며, `layer2`는 아직 문서 정리 커밋(`8bc3e85`)에 머물러 있다.
2. `layer2-dev`는 문서 브랜치를 실제 구현 브랜치로 바꿨다.
   - L2 계약
   - retrieval
   - verification
   - patch preview
   - confidence
   - Chroma RAG
   - MCP 계약 정렬
   - 구조 재편
3. `HEAD` 기준으로는 L1/L2/orchestration/interface 구조가 정리되어 있고, `BaseLlmAnalyzer`, `google.genai` 전환, Chroma exact-match 보강까지 포함되어 있으며, 테스트는 `33 passed, 1 skipped`다.
4. working tree 기준으로는 코드 미커밋 변경은 없고, `.chroma_db` 바이너리 2개와 보고서 파일 1개만 남아 있다.
5. 전체 VSH 목표와 비교하면 L2는 많이 진척되었지만, 실제 L1 Semgrep, 파일 자동 수정/백업, L3, 다중 파일 스캔, CI/CD 등은 아직 남아 있다.

이 보고서의 핵심 결론은 다음 한 줄이다.

> `layer2-dev`는 “문서만 있던 layer2 브랜치”에서 출발해, 현재는 L2 중심의 실제 동작 코드와 구조를 가진 개발 브랜치까지 도달했지만, VSH 전체 완성 단계에는 아직 이르지 않았다.
