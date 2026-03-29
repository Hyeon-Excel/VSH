# VSH (Vulnerability Scanning and Heuristic) Security Platform

> 🚀 이 프로젝트는 L1/L2/L3 역할 분리를 갖춘 보안 취약점 탐지 및 검증 PoC입니다.

## 1. 개요

VSH는 Python 코드 및 패키지를 대상으로 한 계층형 취약점 평가 엔진입니다.
- **L1 (빠른 탐지)**: 규칙/정적 패턴/typosquatting/SBOM + reachability + 취약점 normalize
- **L2 (LLM Reasoning)**: 취약점 주변 코드 컨텍스트에서 위험성 판단, `likely_vulnerable/suspicious/not_vulnerable` 판단
- **L3 (확증/검증)**: 심층 static path 분석 + retry/poc 생성 + cold path 검증

프로덕션 목표
- 낮은 FP (오탐) + 높은 대응 우선순위
- 대규모 OTA 스캔에耐하는 아키텍처 (모듈/파이프라인 분리)
- IDE/CLI/자동화 파이프라인 연계

## 2. 주요 기능

### CLI
- `python VSH_Project_MVP/scripts/vsh_cli.py scan-file <file> --format json|markdown|summary`
- `python VSH_Project_MVP/scripts/vsh_cli.py scan-project <dir> --format json|markdown|summary`
- `python VSH_Project_MVP/scripts/vsh_cli.py diagnostics <file_or_dir>`
- `python VSH_Project_MVP/scripts/vsh_cli.py watch <dir>`

### Watcher (Live)
- `python VSH_Project_MVP/scripts/watch_and_scan.py --path ./target_project`

### API / MCP
- `VshRuntimeEngine().analyze_file(path)`
- `VshRuntimeEngine().analyze_project(path)`
- `VshRuntimeEngine().get_diagnostics(path)`

### 핵심 출력 객체
- `vuln_records`: L1/L2/L3 통합 취약점
- `package_records`: SBOM/패키지 위험 정보
- `l2_reasoning_results`: L2 판정
- `l3_validation_results`: L3 확인 상태
- `diagnostics`, `aggregate_summary`, `previews` (markdown/json)

## 3. 아키텍처

- `layer1/` : 정적 스캔, 패턴+SBOM+reachability
- `layer2/` : `reasoning` + provider (mock/openai/gemini) + 시나리오 추론
- `vsh_runtime/` : 통합 엔진, 리포트, risk 연산, watch, pipeline 관제
- `models/` : 공통 스키마 (`VulnRecord`, `PackageRecord`)
- `tests/` : 유닛/통합/엔드투엔드

### 업데이트된 핵심 처치
- reachability 강화: 함수 기반 call graph + global script heuristics
- L2 provider추상화: `LLM_PROVIDER` env 선택 (`mock` 기본)
- L3 validator: `l3_validator` cold path (evidence driven) + L2 confidence 허용
- 리포트: engine에서 `l3_*` 필드 포함

## 4. 설치

```bash
cd /workspaces/VSH/VSH_Project_MVP
python -m pip install -r requirements.txt
python -m pip install pytest
```

옵션 (Gemini):
```bash
export GEMINI_API_KEY="<your key>"
export LLM_PROVIDER=gemini
```

## 5. 실행

### 로컬 샘플
```bash
PYTHONPATH=. python VSH_Project_MVP/scripts/vsh_cli.py scan-file /path/to/code.py --format json
```

### 테스트
```bash
cd /workspaces/VSH/VSH_Project_MVP
PYTHONPATH=. pytest -q tests/test_runtime_workflow.py tests/test_l1_integration_scanner.py
```

## 6. 체크리스트 / 릴리즈 포인트

- ✅ `L1` : typosquatting, SBOM, 경로/의존성 위험
- ✅ `L2` : 도메인 기반 reasoning + `is_vulnerable` 메타
- ✅ `L3` : static evidence 확인 + 추천 수정
- ✅ `report` : JSON/Markdown/aggregate
- ✅ `git push` (rasasoe-integration)

## 7. 기여

- 브랜치: `rasasoe-integration` (메인 작업), `L3-dev` 서브 목표
- 커밋: `Improve L3 validation integration ...` (현재까지)
- 이후 작업: SBOM 확대, ABI/REACH 확률 모델, L3 POC 엔진, IDE 리포트 플러그인

## 8. 한글/영문 문서
- `ARCHITECTURE.md`
- `LIMITATIONS.md`
- `HANDOFF.md`
- `docs/integration/ide_workflow.md`

