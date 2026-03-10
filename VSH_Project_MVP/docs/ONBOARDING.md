# ONBOARDING.md — 팀원 합류 가이드

## 프로젝트 이해 순서

1. PRD.md 읽기 — 무엇을 왜 만드는지 이해
2. ARCHITECTURE.md 읽기 — 기술 구조 이해
3. CONVENTIONS.md 읽기 — 네이밍 및 코딩 규칙 숙지
4. PROGRESS.md 확인 — 현재 어느 단계인지 파악
5. docs/FLOW.md 읽기 — 실제 코드 흐름 파악

## 환경 세팅

1. 가상환경 생성
   python -m venv venv
   source venv/bin/activate  (Windows: venv\Scripts\activate)

2. 패키지 설치
   pip install -r requirements.txt

3. 환경변수 설정
   cp .env.example .env
   로컬 구조 확인만 할 때는 `.env`에서 `LLM_PROVIDER=mock` 유지
   실제 LLM을 검증하려면 아래 중 하나를 설정
   - `LLM_PROVIDER=gemini` + `GEMINI_API_KEY`
   - `LLM_PROVIDER=claude` + `ANTHROPIC_API_KEY`

4. 실행 확인
   python interfaces/mcp/server.py

5. 대시보드 확인
   uvicorn dashboard.app:app --port 3000

## 핵심 규칙 요약

- 레이어 간 역방향 의존 절대 금지
- interfaces/ 는 orchestration/ 에만 의존
- 새 스캐너 추가 시 `shared/contracts.py`의 `BaseScanner` 기준을 따름
- 새 DB 추가 시 `BaseReadRepository` / `BaseWriteRepository` 기준을 따름
- 반환 타입은 항상 models/ 도메인 모델 사용

## 모르는 것이 생기면

- 코드 흐름: docs/FLOW.md
- 함수 설명: docs/API_REFERENCE.md
- 변수 설명: docs/VARIABLES.md
- 설계 이유: ARCHITECTURE.md
