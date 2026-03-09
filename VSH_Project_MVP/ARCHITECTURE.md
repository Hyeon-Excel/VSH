# ARCHITECTURE.md — 기술 설계 문서

## 레이어 구조 및 역할

### Interface Layer (tools/)
MCP 툴 등록과 위임만 담당. 비즈니스 로직 없음.
Claude가 호출하는 진입점. pipeline_factory를 통해 파이프라인을 받아 실행만 함.

### Orchestration Layer (pipeline/)
L1 → L2 흐름 제어.
어떤 스캐너를 어떤 순서로 실행할지 결정.
L1 결과 없으면 clean 처리, 있으면 L2로 위임.
구체적인 실행은 modules/에 위임.

### Execution Layer (modules/)
실제 Semgrep 실행, Tree-sitter AST 파싱, Claude API 호출.
supported_languages()로 언어별 지원 여부 추상화.
새 언어 추가 시 기존 코드 수정 없이 구현체만 추가.

### Data Layer (repository/)
JSON Mock → 실제 Vector DB 교체 시 이 레이어만 변경.
상위 레이어는 변경 없음.

### Domain Model (models/)
레이어 간 데이터 전달에 사용되는 데이터 구조.
모든 레이어가 이 모델을 기준으로 통신.

---

## 의존성 흐름

tools/
  └→ pipeline_factory
       └→ analysis_pipeline
            ├→ scanner/* (L1)
            ├→ analyzer/* (L2)
            └→ repository/*
                 └→ mock_db/ (JSON)

모든 의존성은 위에서 아래로만 흐른다. 역방향 없음.

---

## 추상화 포인트

| 추상 클래스 | MVP 구현체 | 확장 가능 구현체 |
|------------|-----------|----------------|
| BaseScanner | SemgrepScanner, TreeSitterScanner, SBOMScanner | SonarQubeScanner |
| BaseAnalyzer | LLMAnalyzer | RuleBasedAnalyzer |
| BaseRepository | MockKnowledgeRepo, MockFixRepo, MockLogRepo | ChromaRepo |
| BasePipeline | AnalysisPipeline | FastPipeline, DeepPipeline |

---

## Mock DB → 실제 DB 교체 전략

repository/ 레이어만 교체하면 됨.
상위 레이어(pipeline/, tools/)는 BaseRepository 추상에만 의존하기 때문에
구현체가 MockRepo든 ChromaRepo든 알 필요 없음.

교체 예시:
  MVP:        pipeline = AnalysisPipeline(repo=MockKnowledgeRepo())
  Post-MVP:   pipeline = AnalysisPipeline(repo=ChromaKnowledgeRepo())

---

## 설계 결정 사항 및 이유

1. 기능 단위 + 레이어 단위 혼합 채택
   이유: MCP 툴은 Claude가 목적 기준으로 호출하므로 인터페이스는 기능 단위,
         내부 구현은 레이어 단위로 관리하는 것이 유지보수에 유리

2. Repository 패턴 채택
   이유: MVP에서 Mock JSON을 쓰지만 나중에 실제 DB로 교체할 때
         상위 레이어 코드를 건드리지 않기 위함

3. 의존성 주입 채택
   이유: Pipeline이 Scanner를 직접 생성하지 않고 Factory에서 조립하여 주입.
         테스트 용이성 및 구현체 교체 유연성 확보

4. Tree-sitter supported_languages() 추상화
   이유: MVP는 Python만 지원하지만 C, JSON 등 추가 시
         TreeSitterScanner 내부만 확장하면 되도록 설계