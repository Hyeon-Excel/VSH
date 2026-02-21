# VSH

VSH(Vibe Secure Helper)는 AI가 생성한 코드를 IDE 단계에서 점검하는 FastMCP 기반 보안 도우미입니다.

## 현재 상태

- 문서 중심의 기획 단계에서 구현 가능한 상세 설계 단계로 전환
- `docs/architecture.md`, `docs/contracts.md`, `docs/roadmap.md` 추가
- `src/vsh/` 패키지 스캐폴딩 및 레이어 인터페이스 스텁 추가

## 핵심 목표

- L1: 1초 내 정적 탐지 + 주석 패치
- L2: 근거 보강(RAG) + 검증(OSV/Registry) + 수정 Diff
- L3: 전체 스캔 + SBOM + 제출 가능한 리포트

## 디렉터리

- `docs/`: 실행 가능한 설계 문서
- `src/vsh/`: MCP 서버 및 L1/L2/L3 구현
- `tests/fixtures/`: 취약/안전 코드 샘플

## 다음 구현 순서

1. L1 Semgrep runner + normalize + annotation patch 완성
2. FastMCP 서버에 `vsh.l1.scan_annotate` 연결
3. L2 검증/근거 계층과 L3 리포트 계층 단계적 확장
