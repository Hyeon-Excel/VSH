# Layer 1 (L1) — Hot Path: Real-time Pattern Detection + Inline Annotation

## 0. 목적

- **즉시성(핫패스)**: 개발 흐름을 끊지 않는 속도로 위험 신호를 내는 레이어
- **역할 분리**: L1은 “발견 + 주석 패치 생성”까지, 네트워크/LLM은 하지 않는다

---

## 1. 입력/출력

### 입력

- code: 스니펫 또는 파일 내용
- language: python/javascript/c/cpp/iac/auto
- file_path
- mode: snippet|file

### 출력

- findings[]
- import_candidates[]
- annotation_patch(unified diff)
- timing_ms
- errors[]

---

## 2. 내부 구성

### 2.1 Semgrep Runner

- 최소 룰셋으로 빠르게 스캔
- 출력은 JSON으로 받아 normalize 단계로 전달

### 2.2 (옵션) Tree-sitter

- 언어 판별 보조
- import/require 구문 추출(후속 L2에 전달할 “후보 목록” 생성)

---

## 3. 탐지 범위(MVP)

- CODE 취약점(대표)
  - SQL Injection (Python)
  - XSS (JS)
  - Hardcoded Secrets (공통)
- SUPPLY_CHAIN(대표)
  - “import/require 목록 추출”까지만(L1에서 네트워크 조회는 금지)

---

## 4. Reachability(휴리스틱, L1 수준)

L1에서의 reachability_hint는 “정밀 분석”이 아니라 **빠른 힌트**다.

- YES: source(입력)와 sink(위험 함수/패턴)가 가까이 존재
- NO: sink는 있으나 source 흔적 없음
- UNKNOWN: 판단 불가(파일 구조/프레임워크 의존)

정밀 도달성(taint/dataflow)은 L2/L3에서 강화(또는 L1 옵션 기능으로만 제한적으로).

---

## 5. 주석 패치(annotation_patch) 생성 규칙

- “취약 위치 바로 아래” 또는 “해당 라인 끝”에 주석 블록 삽입
- 주석 블록은 다음 필드 순서를 유지(발표용 출력과 동일하게)
  - 위험도(내부 점수 또는 severity)
  - CWE
  - KISA 근거 키(kisa_key)
  - Reachability 힌트
  - 영향(짧게)
  - 권장 조치(코드가 아니라 ‘방향’ 위주; 실제 코드는 L2에서)

---

## 6. L1 룰 메타데이터 규약(필수)

모든 Semgrep rule은 metadata에 아래 키를 포함한다.

- cwe: ["CWE-89"]
- owasp: ["A03"]
- kisa_key: "INPUT_VALIDATION_1"
- fsec_key: "WEB_3_1"
- severity: "HIGH"

이렇게 하면 L1 normalize가 단순해지고 L2/L3 매핑이 자동화된다.

---

## 7. 산출물(테스트)

- fixtures/ 에 취약/안전 샘플코드 페어를 만든다.
  - python_sqli_bad.py / python_sqli_good.py
  - js_xss_bad.js / js_xss_good.js
  - secrets_bad._ / secrets_good._
- 실행 스크립트
  - `scripts/test_l1_all.sh`: pytest + smoke + perf + report
  - `scripts/export_l1_findings.py`: 파일별 findings JSON 추출
  - `scripts/apply_l1_annotations.py`: annotation patch 파일 적용

---

## 8. References

- Semgrep CLI JSON: https://semgrep.dev/docs/cli-reference
- Semgrep output schema: https://github.com/semgrep/semgrep-interfaces

---

## 9. L1 테스트 판정 기준(D0 고정)

아래 기준은 L1 단계에서 PASS/FAIL을 판정하는 고정 기준이다.

- 기능 정확도
  - 기준:
    - 취약 샘플(Python SQLi, JS XSS) 각각 finding 1개 이상
    - 안전 샘플(Python/JS) finding 0개
    - import 후보 추출(`sqlite3`, `require/import`) 성공
  - 검증:
    - `tests/test_l1_scan.py`
    - `tests/test_l1_tree_sitter.py`
    - `scripts/test_l1_smoke.sh`
- 병렬 실행/격리
  - 기준:
    - Semgrep/Tree-sitter 병렬 실행 증명(start delta < 120ms, synthetic elapsed < 550ms)
    - Semgrep 실패 시에도 import 추출 결과 유지
    - Tree-sitter 실패 시에도 finding/annotation 결과 유지
  - 검증:
    - `tests/test_l1_tree_sitter.py`
    - `tests/test_l1_resilience.py`
- 성능(Hot Path)
  - 기준:
    - 목표(target): cache miss p95 <= 1000ms
    - 게이트(gate): cache miss p95 <= 2500ms
    - cache hit p95 <= 200ms
  - 검증:
    - `scripts/test_l1_perf.sh`
- 리포트(D7)
  - 기준:
    - `L1-test-result.md`에 실행 시각, 커밋 SHA, pytest 통과율, p95, 실패 케이스, 미구현 항목을 자동 기록
  - 검증:
    - `scripts/test_l1_all.sh`
    - `scripts/write_l1_test_result.py`
