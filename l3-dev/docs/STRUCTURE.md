# [VSH L3] 시스템 구조 및 모듈 역할

본 문서는 VSH L3 레이어의 아키텍처와 각 모듈이 담당하는 책임을 정의합니다.

---

## 1. 디렉토리 구조 및 핵심 역할
```
l3-dev/
├── docs/                ← (지금 보고 계신) 팀 공유 가이드 문서
├── l3/
│   ├── pipeline.py      ← M1~M4를 조율하는 핵심 오케스트레이터
│   ├── normalizer.py    ← 데이터 검증 및 DB 저장 담당 (M4)
│   ├── report_generator.py ← 리포트 생성 담당 (M5)
│   ├── schema.py        ← 데이터 모델 (VulnRecord / PackageRecord)
│   ├── providers/       ← 외부 도구 연동부 (M1~M3)
│   │   ├── base.py      ← 추상 인터페이스 (AbstractXxxProvider)
│   │   ├── sonarqube/   ← M1: SAST 및 Reachability 분석
│   │   ├── sbom/        ← M2: 패키지 취약점 및 라이선스 스캔
│   │   └── poc/         ← M3: 공격 증명 시뮬레이션
│   └── mock_shared_db.py ← 개발 전용 Mock 데이터베이스
├── poc_templates/       ← 취약점 종류별 공격 템플릿
├── tests/               ← 테스트 코드
└── mcp_server.py        ← 외부 트리거를 위한 MCP 서버
```

---

## 2. 5대 핵심 모듈 (M1 ~ M5)

### M1: SonarQube Provider
- **역할:** 정적 코드 분석(SAST) 및 실행 경로 분석(Reachability).
- **핵심 로직:** Taint Flow가 2단계 이상 연결된 경우에만 `reachability=True`로 판정합니다.

### M2: SBOM Provider
- **역할:** `syft`를 사용하여 SBOM을 생성하고 OSV API를 통해 취약점 정보를 가져옵니다.
- **특징:** LLM을 거치지 않고 즉시 결과를 리포팅합니다.

### M3: PoC Provider
- **역할:** 발견된 취약점에 대해 실제 공격 코드를 실행하여 증명합니다.
- **안전장치:** 네트워크가 차단된 Docker 컨테이너 내에서 `ReadOnly` 모드로 실행됩니다.

### M4: Normalizer
- **역할:** 각 모듈에서 생성된 데이터를 `schema.py` 형식에 맞게 변환하고 DB에 저장합니다.
- **복원력:** 개별 데이터 처리 중 오류가 발생해도 파이프라인 전체가 중단되지 않도록 보호합니다.

### M5: Report Generator
- **역할:** DB에 저장된 결과를 기반으로 KISA/금융보안원 양식에 맞춘 리포트를 생성합니다.

---

## 3. 핵심 디자인 패턴: DI (의존성 주입)
`l3/pipeline.py`는 구체적인 클래스에 의존하지 않고, 오직 `AbstractXxxProvider` 추상 인터페이스만 참조합니다. 이를 통해 Mock 버전에서 Real 버전으로 코드를 수정 없이 변경할 수 있습니다.

---

## 4. 관련 문서
- [프로젝트 개요 (OVERVIEW.md)](./OVERVIEW.md)
- [코드 흐름 및 실행 시퀀스 (FLOW.md)](./FLOW.md)
- [데이터 명세 및 변수 규칙 (DATA_SPEC.md)](./DATA_SPEC.md)
- [개발 가이드 및 준수 수칙 (DEVELOP.md)](./DEVELOP.md)
