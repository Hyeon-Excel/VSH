# VSH Implementation Roadmap

## Phase 0: Foundation

- [x] 설계 문서 고정 (`architecture`, `contracts`)
- [x] 패키지 스캐폴딩 생성
- [ ] 개발 의존성 설치 및 로컬 실행 환경 고정

Exit criteria:

- `src/vsh` 트리 및 모델 import가 깨지지 않음

## Phase 1: L1 MVP

- [ ] Semgrep runner 구현 (timeout, JSON 파싱)
- [ ] finding normalize 구현 (metadata 매핑)
- [ ] annotation patch 생성기 구현
- [ ] `vsh.l1.scan_annotate` MCP 연결
- [ ] fixture 기반 테스트 통과

Exit criteria:

- 취약 샘플에서 finding 검출
- 안전 샘플에서 오탐 낮음
- p95 < 1초 목표

## Phase 2: L2 Warm Path

- [ ] RAG 인덱스/검색 계층 구현
- [ ] Registry 존재성 검증 구현
- [ ] OSV querybatch 연동 구현
- [ ] fix patch 생성기 구현
- [ ] `vsh.l2.enrich_fix` MCP 연결

Exit criteria:

- findings에 근거/검증 결과 포함
- 외부 API 장애 시 fallback 동작

## Phase 3: L3 Cold Path

- [ ] Sonar runner 구현
- [ ] Syft SBOM 생성 구현
- [ ] SBOM 기반 OSV 매핑 구현
- [ ] Markdown/JSON 리포트 렌더링
- [ ] `vsh.l3.full_report` MCP 연결

Exit criteria:

- 보고서/JSON/SBOM 산출물 생성
- baseline/actions_log 반영

## Phase 4: Hardening

- [ ] 캐시/성능 최적화
- [ ] 에러 코드 및 관측성 정리
- [ ] CI 파이프라인 연결
- [ ] 운영용 샘플 리포트 검증
