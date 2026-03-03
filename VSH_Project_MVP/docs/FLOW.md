# Process Flows

## Domain Model Flow

Domain Model은 레이어 간 데이터 전달의 핵심이며, 모든 레이어는 이 모델을 기준으로 통신합니다.

### Data Flow Diagram

1. **Scanner (L1)**: 소스 파일을 읽고 취약점을 탐지하여 `ScanResult` 객체를 생성합니다.
   - `ScanResult(findings=[Vulnerability(...)])`

2. **Pipeline**: `ScanResult.is_clean()` 메서드로 취약점 유무를 판단합니다.
   - **Clean**: 추가 처리 없이 종료.
   - **Vulnerable**: `ScanResult` 객체를 Analyzer(L2)로 전달합니다.

3. **Analyzer (L2)**: 취약점 분석 후 수정 제안을 담은 `FixSuggestion` 객체를 생성합니다.
   - `FixSuggestion(issue_id, original_code, fixed_code, description)`

4. **Repository**: `FixSuggestion` 및 `ScanResult` 정보를 DB에 저장합니다.

---

### Layer Dependency

`Pipeline` -> `models`
`Scanner` -> `models`
`Analyzer` -> `models`
`Repository` -> `models`

모든 레이어는 `models` 패키지에 정의된 클래스에 의존하며, 레이어 간에는 객체 인스턴스로 데이터를 주고받습니다.

---

## Repository Layer Flow

Repository 레이어는 상위 레이어가 데이터의 물리적 저장소에 관계없이 동일한 인터페이스로 데이터를 다룰 수 있게 합니다.

### Inheritance Structure
- **BaseReadRepository (Abstract)**
  - `MockKnowledgeRepo`: `knowledge.json` 보안 지식 읽기 전용
  - `MockFixRepo`: `kisa_fix.json` 수정 가이드 읽기 전용
- **BaseWriteRepository (Abstract, extends BaseReadRepository)**
  - `MockLogRepo`: `log.json` 분석 결과 로그 읽기/쓰기/상태 업데이트

---

## Entire L1 → L2 Pipeline Flow (Step 5)

이 흐름은 `AnalysisPipeline.run(file_path)` 호출 시 내부적으로 오케스트레이션 되는 전체 과정입니다.

1. **입력 수신**: `file_path` 문자열
2. **L1 스캔 (탐지)**: 
   - 주입된 3개의 스캐너(`Semgrep`, `TreeSitter`, `SBOM`)를 차례대로 실행하여 각각의 `ScanResult` 반환.
3. **통합 및 중복 제거**:
   - 수집된 모든 `findings` 통합.
   - `_deduplicate()` 메서드(`cwe_id` + `line_number` 기준)로 중복된 취약점 제거.
4. **L2 분석 (심층 분석 및 수정 제안)**:
   - `knowledge_repo.find_all()`과 `fix_repo.find_all()`을 통해 전체 데이터를 가져옴.
   - `analyzer.analyze()` 호출.
5. **로깅 및 상태 추적**:
   - Analyzer가 반환한 `fix_suggestions`를 순회하며 `LogRepo`에 초기 상태(`status="pending"`)와 함께 상세 정보 저장.
6. **출력 반환**:
   - `scan_results`와 `fix_suggestions` 객체들을 JSON으로 직렬화할 수 있는 `dict` 리스트 형태로 변환하여 최종 반환.

---

## Dashboard Interface Flow (Step 7)

대시보드는 개발자가 분석 결과를 최종적으로 검토하고 조치하는 사용자 인터페이스입니다.

### 대시보드 액션 흐름
1. **리스트 조회**: 브라우저 접속 -> `GET /api/logs` 호출 -> `LogRepo`에서 전체 기록 로드 -> 화면에 카드 형태로 렌더링.
2. **Accept (수정 승인)**:
   - 개발자가 버튼 클릭 -> `POST /api/logs/{id}/accept` 호출.
   - 서버: DB 상태를 `accepted`로 업데이트 후 제안된 `fixed_code` 반환.
   - 브라우저: 수신된 코드를 클립보드에 자동 복사 -> UI 상태(색상, 텍스트) 변경.
3. **Dismiss (무시)**:
   - 개발자가 버튼 클릭 -> `POST /api/logs/{id}/dismiss` 호출.
   - 서버: DB 상태를 `dismissed`로 업데이트.

---

## E2E Validation Flow (Step 8)

시스템의 모든 컴포넌트가 의도대로 협력하는지 확인하는 최종 검증 프로세스입니다.

### 전체 데이터 흐름
1. **초기화**: 테스트 시작 전 `log.json`을 `[]`로 리셋 (데이터 격리).
2. **분석**: `pipeline.run("e2e_target.py")` 실행 -> L1 탐지 -> L2 분석 -> `log.json` 자동 저장.
3. **조회**: Dashboard에서 `GET /api/logs` 호출 -> 탐지 내역 카드 확인.
4. **조치**: 
   - 사용자가 `Accept` 클릭 -> 서버 상태 업데이트 및 `fixed_code` 수신 -> 클립보드 복사.
   - 사용자가 `Dismiss` 클릭 -> 서버 상태 업데이트 (`dismissed`).
5. **재검증**: `pipeline.run("e2e_target_fixed.py")` 실행 -> CWE-89, CWE-798 미탐지 확인.

### 검증 범위 구분
- **수동 검증 (Browser UI)**: 카드 렌더링 시각적 확인, 배지 색상, 클립보드 실제 복사 여부, 버튼 비활성화 상태 등.
- **자동 검증 (pytest API)**: HTTP 상태 코드, JSON 필드 누락 여부, 정규식 매칭 결과, `log.json` 파일 쓰기 성공 여부.

### 알려진 제약사항 및 동작
- `SBOMScanner`는 파일 경로와 관계없이 프로젝트 루트의 의존성을 체크하므로, 소스 코드가 수정되어도 `requirements.txt`가 취약하다면 지속적으로 탐지 결과에 포함됩니다.
