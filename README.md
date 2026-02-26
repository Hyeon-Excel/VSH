# VSH

VSH(Vibe Secure Helper)는 AI가 생성한 코드를 IDE 단계에서 점검하는 FastMCP 기반 보안 도우미입니다.

## 현재 상태

- L1 Hot Path MVP 구현 완료
  - Semgrep + Tree-sitter 동시 스캔
  - finding 정규화 + annotation patch 생성
  - patch 파일 적용 스크립트(`scripts/apply_l1_annotations.py`)
  - findings JSON 추출 스크립트(`scripts/export_l1_findings.py`)
- L1 테스트/품질 게이트 구축
  - pytest + smoke + perf + 리포트 자동화
  - GitHub Actions L1 CI 워크플로 추가
- L2/L3는 서비스 경계/계약은 고정되었고, 외부 연동 로직은 단계적으로 구현 예정

## 핵심 목표

- L1: 1초 내 정적 탐지 + 주석 패치
- L2: 근거 보강(RAG) + 검증(OSV/Registry) + 수정 Diff
- L3: 전체 스캔 + SBOM + 제출 가능한 리포트

## 프로젝트 계층 구조

```text
VSH/
├── .github/workflows/      # CI 워크플로
├── docs/                   # 아키텍처/레이어/로드맵 문서
├── rules/l1/               # L1 Semgrep 룰셋
├── scripts/                # 테스트/리포트/유틸 스크립트
├── src/vsh/
│   ├── mcp_server.py       # FastMCP 도구 등록 진입점
│   ├── common/             # 공통 모델/타입
│   ├── l1_hot/             # L1(Hot Path) 구현
│   ├── l2_warm/            # L2(Warm Path) 구현(일부 스텁)
│   └── l3_cold/            # L3(Cold Path) 구현(일부 스텁)
├── tests/
│   ├── fixtures/           # 취약/안전 샘플 코드
│   └── test_*.py           # 레이어 테스트
├── guide.md                # 협업자용 운영 가이드
└── L1-test-result.md       # L1 최신 테스트 결과 요약
```

## L1 폴더/파일 역할

`src/vsh/l1_hot/`

- `service.py`
  - L1 오케스트레이션 핵심
  - Semgrep + Tree-sitter 동시 실행
  - 캐시 처리 및 에러 격리
  - 최종 `L1ScanAnnotateResponse` 조립
- `semgrep_runner.py`
  - Semgrep CLI 실행 래퍼
  - timeout/JSON 파싱/오류 처리
  - CLI 실패 시 fallback 스캐너 실행
- `tree_sitter_runner.py`
  - Tree-sitter 기반 import/require 후보 추출
  - 파서 미가용 시 regex fallback 수행
- `normalize.py`
  - Semgrep raw JSON을 `Finding` 모델로 정규화
  - severity/category/reachability/confidence 매핑
- `annotate.py`
  - 탐지 결과를 코드 주석 diff(`annotation_patch`)로 생성
- `__init__.py`
  - L1 공개 API export (`L1Service`, `TreeSitterRunner`)

## L1 -> L2/L3 확장 전략

- `Finding`/`Verification` 공통 모델 재사용
  - L1 결과를 L2에서 근거/검증 데이터로 보강하고, L3 리포트에서 동일 ID로 추적
- `import_candidates` 확장
  - L1 추출 결과를 L2 Registry/OSV 검증 입력으로 사용
  - L3 SBOM 결과와 교차 매칭하여 공급망 위험 우선순위화
- `annotation_patch` 확장
  - 현재 L1의 "탐지 기반 주석"을 L2에서 "근거/수정코드 보강 주석"으로 승격
  - 필요 시 L3 리포트 링크/증빙 ID를 주석에 추가
- 자동화 스크립트 재사용
  - `test_l1_all.sh` 파이프라인을 L2/L3 게이트로 수평 확장
  - 결과 리포트 포맷(`L1-test-result.md`)을 레이어별 공통 포맷으로 일반화

## 다음 구현 순서

1. L2: RAG/Registry/OSV 실연동 + enriched finding/수정 patch 생성
2. L2: L1 주석 패치 업그레이드(근거, CVE, 수정 코드)
3. L3: Sonar/SBOM 실연동 및 제출형 리포트 생성
4. 레이어 통합 CI 게이트(merge blocking) 완성
