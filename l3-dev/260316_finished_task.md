# 2026-03-16 L3 Cold Path 개발 완료 보고 (Finished Tasks)

## 🎯 오늘 완료한 주요 작업 목표
VSH 프로젝트 L3 Cold Path 파이프라인의 **"실제 SonarQube Cloud 연동"** 및 **"LLM 기반 CWE 자동 분류 체계"**를 설계부터 검증까지 완벽하게 구현했습니다.

---

## 🛠️ 상세 구현 내용 및 아키텍처 설계

### 1. LLM Adapter 모듈 구현 (`l3/llm/`)
단순 하드코딩이 아닌, 실제 AI 모델을 활용해 SonarQube의 규칙 ID(Rule ID)를 표준 보안 약점 식별자(CWE)로 매핑하는 추상화 레이어를 구축했습니다.

*   **설계 패턴 (Strategy Pattern):**
    *   `LLMAdapter`라는 추상 클래스(ABC)를 정의하여, 런타임에 Claude 또는 Gemini를 자유롭게 교체할 수 있도록 의존성 역전 원칙(DIP)을 준수했습니다.
*   **Claude Adapter (`claude_adapter.py`):**
    *   Anthropic의 최신 비동기 SDK(`AsyncAnthropic`)를 적용하여 이벤트 루프를 블로킹하지 않는 네이티브 비동기(`async/await`) API 통신을 구현했습니다.
*   **Gemini Adapter (`gemini_adapter.py`):**
    *   Google의 구버전 SDK(`google-generativeai`)에서 발생하는 `FutureWarning`에 대응하여 최신 **`google-genai` (v1.63.0) SDK로 선제적 마이그레이션**을 수행했습니다.
    *   `generate_content`가 동기 함수인 점을 고려하여 `asyncio.to_thread()`와 `lambda`를 결합해 비동기 컨텍스트 내에서 안전하게 호출하도록 설계했습니다.
*   **장애 격리 (Fault Tolerance):**
    *   API 키 누락, 네트워크 타임아웃, 예기치 않은 응답 등 어떤 에러가 발생해도 시스템이 멈추지 않고 `"CWE-UNKNOWN"`이라는 안전한 기본값을 반환하도록 강력한 예외 처리를 적용했습니다.

### 2. SonarQube Real Provider 구현 (`l3/providers/sonarqube/real.py`)
기존의 가짜(Mock) 데이터를 대체하고 실제 SonarQube Cloud 환경과 통신하는 핵심 SAST 스캐닝 로직을 완성했습니다.

*   **API 통신 최적화:**
    *   `requests` 라이브러리의 블로킹 이슈를 해결하기 위해 모든 HTTP 호출을 `asyncio.to_thread()`로 감쌌습니다.
    *   `HTTPBasicAuth`를 사용하여 API 토큰을 통한 인증 방식을 표준화했습니다.
*   **5단계 파이프라인 워크플로우:**
    1.  `_health_check`: 시스템의 가용성(UP)을 먼저 확인.
    2.  `_ensure_project`: 분석 대상 프로젝트를 Cloud에 자동 생성 (이미 존재 시 안전하게 skip 처리).
    3.  `_run_scanner`: `subprocess`와 Docker(`sonarsource/sonar-scanner-cli`)를 사용하여 로컬 코드를 분석.
    4.  `_wait_for_analysis`: 비동기 Polling(`time.monotonic()`, `asyncio.sleep()`) 기법을 적용하여 Cloud 서버의 분석 완료를 대기.
    5.  `_fetch_issues`: 분석 완료 후 발견된 실제 취약점(VULNERABILITY)만 필터링하여 추출.
*   **데이터 모델 정규화 (`_build_vuln_record`):**
    *   추출된 Raw 데이터를 L3 표준 스키마인 `VulnRecord` 객체로 변환합니다.
    *   SonarQube의 Severity(BLOCKER, MAJOR 등)를 VSH 내부 표준(CRITICAL, HIGH, MEDIUM, LOW)으로 정확히 맵핑했습니다.
    *   LLM 어댑터를 의존성 주입(DI) 받아, 추출된 이슈 메시지를 실시간으로 CWE ID로 변환하여 기록합니다.

### 3. 품질 보증 및 테스트 인프라 (`tests/`)
외부 네트워크(API, Docker)에 의존하지 않고 로직의 무결성을 검증하기 위해 철저한 단위 테스트를 구성했습니다.

*   **테스트 기법:**
    *   `unittest.mock` (`patch`, `AsyncMock`, `MagicMock`)을 100% 활용하여 외부 의존성을 완벽히 차단했습니다.
*   **테스트 범위 및 결과 (총 86/86 PASSED):**
    *   LLM 어댑터 파싱 및 예외 검증 (8개)
    *   SonarQube 로직 및 엣지 케이스 시뮬레이션 (25개)
    *   기존 데이터 스키마 및 SBOM 등 전체 회귀 테스트 (Regression Test) 통과.

---

## 💡 개발 스터디 및 인사이트 (Takeaways)

1.  **비동기 프로그래밍의 정교한 제어:**
    동기적 성격을 띠는 라이브러리(`requests`, `subprocess`, 구형 SDK)를 비동기 이벤트 루프(`asyncio`) 환경에 병합할 때, `to_thread`를 사용하여 메인 스레드의 병목을 방지하는 아키텍처 패턴을 몸소 체득했습니다.
2.  **의존성 주입(DI)의 강력함:**
    `RealSonarQubeProvider` 내부에 LLM 객체를 직접 생성하지 않고 외부에서 주입(`__init__(self, llm: LLMAdapter)`)받게 만듦으로써, 향후 LLM 엔진이 변경되더라도 SAST 로직 자체를 수정할 필요가 없다는 설계의 이점을 확인했습니다.
3.  **방어적 프로그래밍 (Defensive Programming):**
    "분석 중 발생하는 어떠한 에러도 전체 프로세스를 멈춰서는 안 된다"는 원칙에 입각하여, 각 단계마다 꼼꼼한 `try-except` 블록과 `scan_error` 처리 로직을 구현하며 안정적인 데이터 파이프라인의 기준을 확립했습니다.
