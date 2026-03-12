# VSH (Vibe Coding Secure Helper) - L3 Cold Path

## 섹션 1. 프로젝트 개요
VSH(Vibe Coding Secure Helper)는 AI 코딩 환경에서 실시간으로 보안 취약점을 탐지하고 조치 가이드를 제공하는 도구입니다. 그 중 L3 Cold Path는 탐지된 취약점에 대한 법적 증거 자료로서의 보안 리포트를 생성하는 역할을 담당합니다. 본 프로젝트는 '분위기 지켜' 팀에서 개발하며, MVP 단계에서는 Python 언어를 주 타겟으로 합니다. 핵심 차별점은 KISA 및 금융보안원(FSS) 컴플라이언스 기준과의 매핑 기능을 제공하며, 실제 공격 가능성을 PoC(Proof of Concept) 기반으로 증명한다는 점에 있습니다.

## 섹션 2. 시스템 아키텍처
L3 레이어는 실시간성을 중시하는 L1/L2 레이어와 달리, 정밀한 분석과 증거 생성을 목적으로 백그라운드에서 동작합니다. L1은 패턴 기반의 즉각적인 탐지(~0.5초)를 수행하고 L2는 LLM을 통한 컨텍스트 판단(1~3초)을 수행하는 반면, L3는 저장(Ctrl+S) 시점에 트리거되어 종합 리포트를 생성합니다.

전체 데이터 흐름은 다음과 같습니다:
- **Ctrl+S 트리거** → 
  - **M1: SonarQube SAST** (코드 정적 분석을 통한 취약점 탐지) → 
  - **M2: SBOM 스캔** (오픈소스 패키지 취약점 분석, LLM 우회) → 
  - **M3: PoC Docker Sandbox** (격리 환경에서 취약점 공격 실증) → 
  - **M4: L3 Normalizer** (데이터 스키마 검증 및 통합 DB 저장) → 
  - **M5: Report Generator** (최종 Markdown 보안 리포트 생성)

M2(SBOM) 단계에서 LLM을 우회하는 이유는 패키지 취약점이 CVE DB 기반의 확정된 데이터이기 때문입니다. LLM의 재판단은 불필요할 뿐만 아니라 오히려 데이터의 정확성을 오염시킬 위험이 있어 의도적으로 배제되었습니다.

## 섹션 3. 디렉토리 구조
```
l3-dev/
├── mcp_server.py           ← FastMCP 진입점 및 DI 조립
├── l3/
│   ├── __init__.py
│   ├── mock_shared_db.py   ← 테스트용 인메모리 DB 구현체
│   ├── schema.py           ← VulnRecord / PackageRecord 데이터 모델
│   ├── pipeline.py         ← M1~M4 흐름 제어 오케스트레이터
│   ├── normalizer.py       ← 데이터 정규화 및 DB 저장 (M4)
│   ├── report_generator.py ← 리포트 생성기 (M5)
│   └── providers/
│       ├── base.py         ← Provider 추상 인터페이스 (ABC)
│       ├── sonarqube/      ← SAST 분석 모듈 (M1)
│       ├── sbom/           ← 공급망 분석 모듈 (M2)
│       └── poc/            ← 취약점 실증 모듈 (M3)
├── poc_templates/          ← 취약점별 공격 페이로드 템플릿
└── tests/                  ← 단위 및 E2E 테스트 코드
```

## 섹션 4. 개발 환경 설정
**필수 요구사항**
- Python 3.13 이상
- `pip install -r requirements.txt` 실행을 통한 의존성 설치

**주차별 추가 설치 도구**
- Week 2: `syft` (SBOM 생성을 위한 CLI 도구)
- Week 3: `sonar-scanner`, `Docker`
- Week 4: `Docker` (PoC 수행을 위한 샌드박스 환경)

**실행 및 테스트 방법**
- **MCP 서버 실행:** `python mcp_server.py`
- **전체 테스트 실행:** `pytest tests/ -v`
- **Week 1 핵심 테스트:** `pytest tests/test_schema.py tests/test_week1_e2e.py -v`

## 섹션 5. 개발 현황
- **Week 1 (완료):** Mock-First 기반의 전체 파이프라인 구축을 완료했습니다. VulnRecord 및 PackageRecord 스키마를 확정하고, M1부터 M5까지의 흐름을 Mock 데이터를 통해 검증했습니다. 단위 테스트와 E2E 테스트를 모두 통과한 상태입니다.
- **Week 2 (예정):** Syft 및 OSV API를 연동하여 실제 SBOM 스캔 기능을 구현할 예정입니다.
- **Week 3 (예정):** SonarQube 서버와 연동하여 실제 정적 분석 및 Reachability 판단 기능을 구현할 예정입니다.
- **Week 4 (예정):** Docker 기반의 PoC 샌드박스를 구축하고 실제 SQL 인젝션 취약점 증명 기능을 구현할 예정입니다.

## 섹션 6. 핵심 규칙 요약
- **R2 DI 패턴:** 생성자 주입을 통해 구현체와 인터페이스를 분리합니다. Mock에서 Real로 교체할 때 `mcp_server.py`만 수정하면 되므로 확장이 용이합니다. 이를 어길 경우 파이프라인 등 여러 파일을 동시에 수정해야 하는 번거로움이 발생합니다.
- **R6 PackageRecord LLM 우회:** SBOM 결과는 LLM을 거치지 않고 직접 저장합니다. CVE 데이터의 객관성을 유지하기 위함이며, 실수할 경우 LLM의 추측성 답변으로 인해 리포트의 신뢰도가 떨어질 수 있습니다.
- **R8 M3 예외처리:** 특정 레코드의 PoC 실패가 전체 스캔 중단으로 이어지지 않도록 방어합니다. 장애 격리를 위한 필수 규칙이며, 이를 어기면 단 하나의 에러로 인해 전체 리포트 생성이 누락됩니다.
- **severity enum:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` 4가지 값만 엄격히 허용합니다. 데이터 일관성을 위한 규칙이며, 잘못된 값이 입력되면 인스턴스 생성 시 `ValueError`가 발생합니다.
- **status enum:** `VulnRecord`(7개)와 `PackageRecord`(3개)의 상태값을 엄격히 구분합니다. 워크플로우 관리를 위해 중요하며, 허용되지 않은 값은 시스템 내부에서 거부됩니다.
