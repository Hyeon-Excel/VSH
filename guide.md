# VSH Collaboration Guide

## 1. 목적

VSH 프로젝트의 현재 작동 방식과 진행 상태를 빠르게 파악하고,
동일한 방식으로 L1 테스트를 재현할 수 있도록 정리한 운영 가이드입니다.

## 2. 프로젝트 개요

- 프로젝트명: VSH (Vibe Secure Helper)
- 목표: AI 코딩 과정에서 보안 취약점을 조기에 탐지하고, 근거/수정 가이드를 제공
- 인터페이스: FastMCP 서버 (`src/vsh/mcp_server.py`)

레이어 역할:

- L1 (Hot Path): Semgrep + Tree-sitter 기반 빠른 탐지/주석 패치
- L2 (Warm Path): 근거 보강(RAG), 레지스트리/OSV 검증, 수정안 강화
- L3 (Cold Path): 저장소 단위 심층 스캔, SBOM/리포트 생성

## 3. 현재 구현 상태

완료:

- L1 MVP 구현
  - Semgrep 실행/정규화
  - Tree-sitter import 후보 추출
  - Semgrep + Tree-sitter 동시 실행
  - annotation patch 생성
  - 캐시/장애 격리 처리
- L1 테스트 체계
  - pytest + smoke + perf + 결과 리포트 자동 생성
- L1 CI 게이트 워크플로
  - `.github/workflows/l1-ci.yml`

진행 중/미구현:

- L2 실질 구현 (RAG/Registry/OSV 연동)
- L3 실질 구현 (Sonar/Syft 실연동)
- 브랜치 보호의 required check 설정 (GitHub 저장소 설정 필요)

## 4. 핵심 디렉터리

- `src/vsh/`: 애플리케이션 코드
  - `src/vsh/l1_hot/`: L1 구현
  - `src/vsh/l2_warm/`: L2 스텁/서비스
  - `src/vsh/l3_cold/`: L3 스텁/서비스
- `rules/l1/`: L1 Semgrep 룰셋
- `tests/`: pytest 케이스 및 fixture
- `scripts/`: 테스트 자동화/리포트/유틸 스크립트
- `artifacts/test-results/l1/`: L1 실행 로그 및 성능 결과

## 5. 로컬 실행 준비

```bash
cd /Users/hyeonexcel/Documents/Workspace/VSH
source .venv/bin/activate
python -m pip install -e ".[dev,l1]"
```

Semgrep 확인:

```bash
semgrep --version
```

## 6. L1 테스트 실행 방법

### 6.1 전체 파이프라인 (권장)

```bash
bash scripts/test_l1_all.sh
```

실행 항목:

- pytest: 기능/회귀/격리/캐시/취약 샘플
- smoke: 엔진 경로 및 기본 탐지 확인
- perf: p50/p95 성능 게이트 확인
- report: `L1-test-result.md` 자동 갱신

### 6.2 취약 샘플 테스트만 빠르게

```bash
python -m pytest -q tests/test_l1_vuln_samples.py
```

샘플 fixture:

- `tests/fixtures/python_multi_bad.py`
- `tests/fixtures/javascript_multi_bad.js`
- `tests/fixtures/typescript_xss_bad.ts`
- `tests/fixtures/secrets_multiple_bad.txt`

## 7. 취약점 탐지 결과 확인 포인트

`pytest passed`는 "검증 조건이 맞았다"는 의미입니다.
실제 취약점 상세는 아래에서 확인하면 됩니다.

- 테스트 assert:
  - `tests/test_l1_vuln_samples.py`
- 실행 로그:
  - `artifacts/test-results/l1/l1_test_*.log`
  - `artifacts/test-results/l1/l1_smoke_*.log`
- 통합 리포트:
  - `L1-test-result.md`

## 8. 파일별 Findings JSON 추출 (협업용)

새 스크립트:

- `scripts/export_l1_findings.py`

예시:

```bash
python scripts/export_l1_findings.py \
  --files tests/fixtures/python_multi_bad.py tests/fixtures/javascript_multi_bad.js
```

결과:

- 기본 출력 경로: `artifacts/test-results/l1/findings/`
- 파일별 JSON에 `findings`, `import_candidates`, `timing_ms`, `errors` 포함

patch까지 포함하려면:

```bash
python scripts/export_l1_findings.py \
  --files tests/fixtures/python_multi_bad.py \
  --include-patch
```

## 8.1 annotation patch 파일 적용 (선택)

현재 L1은 기본적으로 patch를 "생성"한다.
실제 파일 반영이 필요하면 아래 스크립트를 사용한다.

- `scripts/apply_l1_annotations.py`

dry-run(권장 시작):

```bash
python scripts/apply_l1_annotations.py \
  --files tests/fixtures/javascript_multi_bad.js \
  --dry-run \
  --print-patch
```

실제 적용:

```bash
python scripts/apply_l1_annotations.py \
  --files tests/fixtures/javascript_multi_bad.js \
  --backup
```

옵션:

- `--dry-run`: 파일 쓰기 없이 결과 미리보기
- `--print-patch`: 생성된 unified diff 출력
- `--backup`: 적용 전 `*.bak` 백업 생성
- `--strict`: L1 오류/적용 실패 발생 시 non-zero 종료

## 9. CI/협업 규칙

- CI 워크플로: `.github/workflows/l1-ci.yml`
- PR 머지 차단을 위해 저장소 설정에서 required check로 아래 항목 지정 필요:
  - `L1 CI Gate / L1 Tests`

권장:

- `.github/workflows/*` 변경은 CODEOWNERS 리뷰 강제
- L1 변경 시 `scripts/test_l1_all.sh` 결과를 확인 후 커밋

## 10. 참고 문서

- `README.md`
- `docs/architecture.md`
- `docs/layer1.md`
- `docs/roadmap.md`

## 11. 향후 개발 로드맵 (L1 확장 중심)

### 11.1 Milestone L2

- L1 `findings`를 입력으로 RAG 근거(`kisa_key`, `fsec_key`) 보강
- L1 `import_candidates`를 Registry/OSV 검증 파이프라인으로 연결
- L1 `annotation_patch`를 L2 단계에서 "근거 + CVE + 수정코드"가 포함된 패치로 확장

### 11.2 Milestone L3

- L3 Sonar/SBOM 결과를 L1/L2 finding과 병합해 단일 이슈 목록 구성
- L1/L2에서 축적한 `finding_id`를 리포트 증빙 ID로 재사용
- 최종 리포트에서 "탐지(L1) -> 보강(L2) -> 감사/제출(L3)" 흐름을 추적 가능하게 유지

### 11.3 운영 원칙

- L1 계약(`Finding`, `import_candidates`, `annotation_patch`)은 하위 호환 유지
- L2/L3는 L1 출력 포맷을 확장만 하고, 깨지 않도록 버전 관리
- 새로운 기능은 가능하면 `scripts/test_l1_all.sh`와 동일한 게이트 패턴으로 추가
