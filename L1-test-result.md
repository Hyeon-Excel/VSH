# L1 Test Result

- 작성 시각: 2026-02-24 13:48:01 KST
- 대상 프로젝트: `/Users/hyeonexcel/Documents/Workspace/VSH`
- 검토 대상: L1 스캔/정규화/주석 패치/서비스 오케스트레이션

## 1. 검토 범위

- 코드
  - `src/vsh/l1_hot/semgrep_runner.py`
  - `src/vsh/l1_hot/normalize.py`
  - `src/vsh/l1_hot/annotate.py`
  - `src/vsh/l1_hot/service.py`
- 룰셋
  - `rules/l1/python.yml`
  - `rules/l1/javascript.yml`
  - `rules/l1/secrets.yml`
- 테스트
  - `tests/test_l1_scan.py`
  - `tests/test_l1_patch.py`

## 2. 이번 검토에서 반영한 사항

- Semgrep CLI 결과에 `engine=semgrep-cli` 메타를 명시하도록 보강
- L1 테스트 자동화 스크립트 추가
  - `scripts/test_l1_pytest.sh`
  - `scripts/test_l1_smoke.sh`
  - `scripts/test_l1_all.sh`
- `test_l1_pytest.sh`가 실행 환경별로 pytest 가능한 Python 인터프리터를 자동 선택하도록 보강

## 3. 실행한 테스트

### 3.1 통합 실행

```bash
./scripts/test_l1_all.sh
```

실행 로그:

- `/Users/hyeonexcel/Documents/Workspace/VSH/artifacts/test-results/l1/l1_test_20260224_134744.log`

### 3.2 세부 결과

- Pytest L1 테스트
  - 결과: `5 passed`
  - 항목:
    - Python SQLi 탐지
    - JavaScript XSS 탐지
    - 안전 샘플 무탐지
    - annotation patch unified diff 형식 검증
    - 무탐지 시 빈 patch 검증
- Smoke 테스트
  - Semgrep CLI 경로 탐지 성공
  - Python 샘플 탐지 성공 (`python_findings=1`)
  - JavaScript 샘플 탐지 성공 (`js_findings=1`)
  - 강제 fallback 경로 탐지 성공 (`fallback_findings=1`)

## 4. 결론

- L1 MVP는 현재 기준에서 정상 동작함
  - 룰 기반 탐지 동작
  - Finding 정규화 동작
  - Annotation patch 생성 동작
  - 서비스 레벨 오케스트레이션 동작
- Semgrep CLI가 존재할 때 `semgrep-cli` 경로, 실패/강제 상황에서는 `fallback` 경로가 동작함
