# [VSH L3] 개발 가이드 및 준수 수칙

본 문서는 개발자가 실제 코드를 작성하거나 테스트를 수행할 때 참고해야 할 기술적 지침과 규칙을 정의합니다.

---

## 1. 개발 환경 설정
- **Python 버전:** `3.13.7` 이상 권장.
- **필수 도구:**
  - `Docker`: PoC 실행을 위해 반드시 설치되어 있어야 합니다.
  - `syft`: SBOM 생성을 위해 필요합니다 (Week 2 이후).
- **의존성 설치:** `pip install -r requirements.txt`

---

## 2. 테스트 및 품질 관리
- **테스트 실행:** `pytest` 명령어로 전체 테스트 수행.
- **E2E 테스트:** `tests/test_week1_e2e.py`를 통해 파이프라인의 전체 흐름을 확인합니다.
- **로깅 규칙:** `logging` 모듈 사용 금지. 대신 `print(f"[L3 모듈명] 메시지")` 형식을 사용합니다.

---

## 3. 12대 골든 규칙 (Golden Rules)
팀원들이 코드 작성 시 반드시 지켜야 할 **절대 금지 사항**입니다.

1.  **추상화 강제:** 모든 Provider는 `AbstractXxxProvider`를 상속해야 합니다.
2.  **DI 준수:** `pipeline.py`에서 구체 클래스를 직접 import하지 않습니다.
3.  **Severity 직접 지정:** CVSS 점수에서 `severity`를 자동 계산하지 않습니다.
4.  **FSS 참조 검증:** `fss_ref` 필드에 빈 문자열(`""`)을 허용하지 않습니다.
5.  **Status 정합성:** 지정된 7개(Vuln) / 3개(Package) 상태값만 사용합니다.
6.  **SBOM LLM 우회:** `PackageRecord` 생성 시 LLM을 호출하지 않습니다.
7.  **PoC 코드 보호:** Exploit 공격 코드 원문을 DB에 저장하지 않습니다.
8.  **Normalizer 복원력:** 단일 레코드 저장 실패가 전체 스캔을 중단시키지 않도록 합니다.
9.  **인터페이스 일치:** Mock과 Real의 메서드 시그니처를 동일하게 유지합니다.
10. **Source 고정:** 각 Provider별 정해진 `source` 문자열만 사용합니다.
11. **Reachability 판정:** SonarQube Flow가 2개 이상일 때만 `True`로 판정합니다.
12. **Gemini API 제한:** PoC 템플릿 생성에는 LLM을 사용하지 않습니다.

---

## 4. 관련 문서
- [프로젝트 개요 (OVERVIEW.md)](./OVERVIEW.md)
- [시스템 구조 및 모듈 역할 (STRUCTURE.md)](./STRUCTURE.md)
- [코드 흐름 및 실행 시퀀스 (FLOW.md)](./FLOW.md)
- [데이터 명세 및 변수 규칙 (DATA_SPEC.md)](./DATA_SPEC.md)
---
