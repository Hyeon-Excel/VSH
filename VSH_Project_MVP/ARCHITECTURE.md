# ARCHITECTURE.md — 기술 설계 문서

## 레이어 구조 및 역할

### Interface Layer (`interfaces/`, `dashboard/`)
- `interfaces/mcp/server.py`
  - MCP 툴 계약을 외부에 공개하는 진입점
- `dashboard/`
  - FastAPI 대시보드와 UI 표시 담당

### Orchestration Layer (`orchestration/`)
- L1 → L2 흐름 제어
- 어떤 스캐너를 어떤 순서로 실행할지 결정
- retrieval / verification / analysis / patch를 조립
- L3가 붙을 경우 이 레이어가 handoff 지점이 됨

### Shared Contract Layer (`shared/`)
- `BaseScanner`, `BaseAnalyzer` 같은 공통 추상 계약 보관
- L1 / L2 / 향후 L3가 같은 인터페이스 기준을 공유

### Layer 1 (`layer1/`)
- scanner 구현체 보관
- mock semgrep, tree-sitter, SBOM 같은 탐지 컴포넌트 담당

### Layer 2 (`layer2/`)
- analyzer / retriever / verifier / patch builder 보관
- L1 findings를 보강, 검증, 수정 제안으로 연결

### Data Layer (`repository/`)
- JSON Mock → 실제 Vector DB 교체 시 이 레이어만 변경
- 상위 레이어는 repository 추상에만 의존

### Domain Model (`models/`)
- 레이어 간 데이터 전달에 사용되는 데이터 구조
- 모든 레이어가 이 모델을 기준으로 통신
- `severity`는 현재 `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` 4단계를 허용

### Compatibility Layer (`modules/`, `pipeline/`, `tools/`)
- 기존 경로를 쓰는 코드가 깨지지 않도록 wrapper 유지
- 실제 구현은 새 패키지(`shared/`, `layer1/`, `orchestration/`, `interfaces/`)를 사용

---

## 의존성 흐름

interfaces/mcp
  └→ orchestration
       ├→ layer1/scanner/* (L1)
       ├→ layer2/* (L2)
       ├→ repository/*
       └→ models/*

모든 의존성은 위에서 아래로만 흐른다. 역방향 없음.

---

## 추상화 포인트

| 추상 클래스 | 현재 구현체 | 확장 가능 구현체 |
|------------|-----------|----------------|
| BaseScanner | MockSemgrepScanner, TreeSitterScanner, SBOMScanner | SemgrepScanner, SonarQubeScanner |
| BaseAnalyzer | MockAnalyzer, GeminiAnalyzer, ClaudeAnalyzer | RuleBasedAnalyzer |
| BaseReadRepository / BaseWriteRepository | MockKnowledgeRepo, MockFixRepo, MockLogRepo | ChromaRepo, SQLiteRepo |
| BasePipeline | AnalysisPipeline | FastPipeline, DeepPipeline |

---

## Mock DB → 실제 DB 교체 전략

repository/ 레이어만 교체하면 됨.
상위 레이어(orchestration/, interfaces/)는 BaseRepository 추상에만 의존하기 때문에
구현체가 MockRepo든 ChromaRepo든 알 필요 없음.

교체 예시:
  MVP:        pipeline = AnalysisPipeline(repo=MockKnowledgeRepo())
  Post-MVP:   pipeline = AnalysisPipeline(repo=ChromaKnowledgeRepo())

---

## 설계 결정 사항 및 이유

1. 레이어 경계 명시화 채택
   이유: L1 / L2 / Interface / Orchestration이 섞여 보이면
         다른 팀원이 실제 L1 또는 향후 L3 구현을 붙일 때 진입점을 찾기 어렵기 때문

2. Repository 패턴 채택
   이유: MVP에서 Mock JSON을 쓰지만 나중에 실제 DB로 교체할 때
         상위 레이어 코드를 건드리지 않기 위함

3. 의존성 주입 채택
   이유: Orchestration이 Scanner를 직접 생성하지 않고 Factory에서 조립하여 주입.
         테스트 용이성 및 구현체 교체 유연성 확보

4. Tree-sitter supported_languages() 추상화
   이유: MVP는 Python만 지원하지만 C, JSON 등 추가 시
         TreeSitterScanner 내부만 확장하면 되도록 설계
