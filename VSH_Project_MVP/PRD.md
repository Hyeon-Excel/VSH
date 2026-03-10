# PRD.md — Security MCP 제품 요구사항

## 제품 개요

### 무엇을 만드는가
코드 보안 취약점을 자동으로 탐지하고 AI가 수정 제안까지 해주는 MCP 기반 보안 분석 도구

### 왜 만드는가
개발자가 코드를 작성할 때 보안 취약점을 놓치는 문제를 해결하기 위해.
기존 정적 분석 도구는 탐지만 하고 수정 방법을 알려주지 않는다.
이 도구는 탐지 + AI 판단 + 수정 제안 + 자동 적용까지 한 번에 해결한다.

### 누가 사용하는가
- 보안을 고려한 코드를 작성하고 싶은 개발자
- 코드 리뷰 시 보안 취약점을 자동으로 검토하고 싶은 팀
- Claude IDE / Cursor 등 AI 코딩 환경을 사용하는 개발자

---

## 핵심 기능 요구사항

### L1 — 자동 탐지
- Semgrep으로 코드 패턴 기반 취약점 스캔
- Tree-sitter로 AST 파싱하여 의심 구간 추출
- SBOM으로 requirements.txt의 취약 패키지 탐지
- 아무것도 없으면 "clean" 반환 후 종료

### L2 — AI 판단
- L1 결과를 Claude API에 전달
- Mock Knowledge DB (KISA/OWASP) 참조하여 컨텍스트 제공
- 취약점 여부 판단 (있음 / 없음 / 오탐)
- 수정 제안 코드 생성

### 대시보드
- localhost:3000 에서 분석 결과 확인
- Accept 클릭 시 파일 자동 수정
- Dismiss 클릭 시 오탐으로 로그 기록
- 수정 전 원본 파일 백업

### MCP 툴 인터페이스
- Claude IDE에서 validate_code 툴 직접 호출 가능
- 코드 생성/수정 후 자동으로 보안 검증

---

## 지원 언어 범위

MVP: Python
Post-MVP: C, JSON, JavaScript (Tree-sitter 파서 추가로 확장)

---

## 비기능 요구사항

- 새 스캐너 추가 시 기존 코드 수정 없이 구현체만 추가 가능
- Mock DB → 실제 Vector DB 교체 시 상위 레이어 코드 변경 없음
- MVP 이후 L3 추가 시 pipeline/ 확장만으로 가능

---

## MVP 범위 vs 전체 범위

### MVP에 포함
- L1: Semgrep + Tree-sitter (Python) + SBOM Mock
- L2: Claude API 판단 + 수정 제안
- Mock DB: JSON 파일 기반
- FastAPI 대시보드: Accept / Dismiss
- FastMCP: validate_code 툴 등록

### MVP에서 제외
- L3: SonarQube, PoC 생성, 리포트 생성 (MD/JSON/PDF)
- 실제 Vector DB (ChromaDB 등)
- VS Code Extension
- 다중 파일 / 프로젝트 단위 스캔
- CI/CD 파이프라인 연동
- diff 형태도 고려

### Post-MVP Phase 계획
- Phase 2: L3 추가 (SonarQube, PoC, 리포트)
- Phase 3: DB 고도화 (Mock JSON → ChromaDB)
- Phase 4: 인터페이스 확장 (VS Code Extension, CI/CD)
- Phase 5: 고도화 (오탐률 개선, 언어 확장)

---

## 현재 구현 메모 (2026-03-10)

이 문서는 원래 MVP 요구사항 문서이며, 아래 항목은 현재 구현과의 차이를 설명하기 위한 참고 메모다.

- 현재 analyzer provider는 `Claude`만이 아니라 `Gemini`, `Claude`, `Mock` 3종을 지원한다.
- 현재 L1 코드 경로는 존재하지만, Semgrep 부분은 실제 바이너리 호출이 아니라 `mock_semgrep_scanner.py` 기반이다.
- 현재 MCP 공개 도구는 `validate_code` 하나만이 아니라 `validate_code`, `scan_only`, `get_results`, `apply_fix`, `dismiss_issue`, `get_log` 6개다.
- `apply_fix` / Dashboard Accept는 현재 실제 파일 수정과 백업을 수행하지 않고, 상태 업데이트와 `fixed_code` 반환만 수행한다.
- Chroma RAG와 patch/diff preview는 현재 브랜치에서 선행 구현되어 있으나, 원래 PRD에서는 Post-MVP 또는 고려 항목으로 분류되어 있었다.
