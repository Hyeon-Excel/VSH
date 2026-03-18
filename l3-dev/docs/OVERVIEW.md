# [VSH L3] 프로젝트 개요 및 로드맵

VSH(Vibe Coding Secure Helper) 프로젝트의 **L3 Cold Path** 레이어에 오신 것을 환영합니다.

---

## 1. 프로젝트 목적: "속도가 아닌 증명"
L3 레이어는 실시간 피드백보다 **보안 심사에 제출할 법적 증거 문서 생성**에 집중합니다.
단순히 취약점을 찾는 것을 넘어, 실제 공격 가능성을 증명(PoC)하고 관련 법령(KISA/금융보안원)과의 매핑을 제공하는 것이 핵심입니다.

### 핵심 지표
- **정탐률 (Precision):** 오탐을 최소화하고 실제 위험만 보고합니다.
- **컴플라이언스 (Compliance):** KISA 및 금융보안원의 가이드라인을 1:1로 매핑합니다.
- **가시성 (Visibility):** 경영진과 심사기관이 이해할 수 있는 MD/JSON 리포트를 자동 생성합니다.

---

## 2. 4주 개발 로드맵
현재 프로젝트는 **Mock-First + DI(Dependency Injection)** 패턴을 사용하여 단계별로 구축되고 있습니다.

| 주차 | 목표 | 상태 | Provider 상태 |
| :--- | :--- | :--- | :--- |
| **Week 1** | ABC + Mock E2E 구축 | 완료 | 전부 Mock |
| **Week 2** | 실제 SBOM (syft + OSV API) 연동 | 완료 | SBOM Real |
| **Build 3** | SonarQube + Reachability 연동 | 완료 | SBOM + SonarQube Real |
| **Week 4** | PoC Docker + FastMCP 통합 | 완료 | **전부 Real (MVP)** |

 Real SBOM 연동,  CWE-89 실제 탐지, template_registry 기능 추가만 남은 상황

---

## 3. 핵심 아키텍처 원칙
- **Isolated execution:** 모든 PoC 공격 시뮬레이션은 Docker 격리 환경에서 안전하게 수행됩니다.
- **Schema-First:** 모든 데이터는 `VulnRecord` 및 `PackageRecord` 스키마를 엄격히 준수합니다.
- **LLM as interpreter:** LLM은 복잡한 실행 결과를 사람이 읽기 쉬운 언어로 해석하는 용도로만 제한적으로 사용합니다.

---

## 4. 관련 문서
- [구조 및 모듈 역할 (STRUCTURE.md)](./STRUCTURE.md)
- [코드 흐름 및 실행 시퀀스 (FLOW.md)](./FLOW.md)
- [데이터 명세 및 변수 규칙 (DATA_SPEC.md)](./DATA_SPEC.md)
- [개발 가이드 및 준수 수칙 (DEVELOP.md)](./DEVELOP.md)
