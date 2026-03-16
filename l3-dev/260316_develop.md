# 2026-03-16 개발 기록: L3 Cold Path LLM 어댑터 구현 및 마이그레이션

## 1. 개요
L3 Cold Path의 핵심 기능 중 하나인 **"CWE 자동 분류"**를 위해 LLM(Large Language Model) 어댑터 모듈을 설계하고 구현했습니다. SonarQube가 탐지한 규칙 ID(`rule_id`)와 메시지를 기반으로 표준 보안 약점 식별자인 `CWE ID`를 도출하는 역할을 수행합니다.

---

## 2. 주요 기술적 결정 사항

### 2.1 전략 패턴(Strategy Pattern) 도입
- **이유**: Claude(Anthropic)와 Gemini(Google) 중 어떤 모델이 더 정확한지 비교 검증이 필요하며, 비용이나 정책에 따라 모델을 자유롭게 교체할 수 있어야 합니다.
- **구현**: `LLMAdapter` 추상 클래스를 정의하고, 모든 구체 어댑터가 이를 상속받아 `classify_cwe()` 메서드를 구현하도록 강제했습니다.

### 2.2 비동기(Asyncio) 프로그래밍 모델 준수
- **Claude (AsyncNative)**: `AsyncAnthropic` 클라이언트를 사용하여 `await` 키워드로 직접 비동기 호출을 수행합니다.
- **Gemini (Thread-based Async)**: `google-genai` SDK의 호출 방식이 동기(Sync) 방식이므로, `asyncio.to_thread()`를 사용하여 워커 스레드에서 실행함으로써 메인 이벤트 루프의 블로킹을 방지했습니다.
  - *특이사항*: `to_thread` 내부에서 키워드 인자를 안전하게 전달하기 위해 `lambda` 함수를 활용했습니다.

### 2.3 철저한 예외 처리 및 정규화
- **장애 격리**: 보안 스캔 도중 LLM 서버가 응답하지 않거나 API 키가 만료되어도 전체 스캔 파이프라인은 멈추면 안 됩니다.
- **로직**: 모든 에러 상황에서 `raise` 대신 `CWE-UNKNOWN` 문자열을 반환하도록 설계했습니다.
- **정규식 파싱**: LLM이 서술형으로 답변하더라도 `re.search(r"CWE-\d+", ...)`를 통해 필요한 ID만 정확히 추출합니다.

---

## 3. 구현 상세

### 3.1 디렉토리 구조 (`l3/llm/`)
- `base.py`: 추상 인터페이스 정의
- `claude_adapter.py`: Anthropic Claude API 연동
- `gemini_adapter.py`: Google Gemini API 연동 (v1.63.0 기준)
- `__init__.py`: 외부 노출 인터페이스 정리

### 3.2 Google GenAI 마이그레이션 (중요)
- 기존 `google-generativeai` 패키지에서 발생하는 `FutureWarning` 및 기술 지원 중단에 대응하기 위해 최신 `google-genai` 패키지로 전환했습니다.
- **변경점**: `genai.configure()` 방식에서 `genai.Client(api_key=...)` 인스턴스 방식으로 변경하여 코드의 응집도를 높였습니다.

---

## 4. 품질 보증 (QA)

### 4.1 Mock 기반 단위 테스트
- 외부 API 서버를 실제로 호출하지 않고 `unittest.mock`의 `patch`, `AsyncMock`, `MagicMock`을 사용하여 모든 시나리오를 시뮬레이션했습니다.
- **테스트 시나리오**:
  1. 정상 응답 시 정확한 CWE 포맷 반환 여부
  2. 모델이 긴 문장으로 답변할 때 파싱 성공 여부
  3. API 키 누락 시 처리
  4. API 호출 예외 발생 시 `CWE-UNKNOWN` 반환 여부
  5. 인터페이스(ABC) 상속 준수 여부

### 4.2 최종 테스트 결과
- **신규 테스트**: 8개 통과 (tests/test_week3_llm_adapter.py)
- **전체 테스트**: 61개 통과 (기존 스키마, SBOM, E2E 테스트 포함)
- **결과**: `61 PASSED, 0 FAILED`

---

## 5. 학습 포인트 (Study Notes)
- **Python Asyncio**: 동기 함수를 비동기 환경에서 호출할 때 `to_thread`를 사용하는 패턴의 중요성을 체득했습니다.
- **SDK Migration**: 클라우드 서비스의 SDK 변경 시 기존 테스트 코드가 어떤 식으로 방어막 역할을 해주는지(Regression Test) 경험했습니다.
- **Security Context**: LLM 프롬프트에 공격 코드를 생성하지 않도록 명시적인 페르소나(System Instruction)를 부여하는 기법을 적용했습니다.

---

**Next Step**: 이제 구현된 `LLMAdapter`를 실제 `SonarQubeProvider`에 주입하여, 탐지된 취약점에 CWE ID를 자동으로 매핑하는 작업을 진행할 예정입니다.
