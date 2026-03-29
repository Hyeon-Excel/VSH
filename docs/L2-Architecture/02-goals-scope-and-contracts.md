# L2 Goals, Scope, and Contracts

## 1. 목표와 비목표

### 목표

- L1 findings를 더 신뢰할 수 있는 결과로 변환
- 보안 기준 문서를 근거로 연결
- 공급망 관련 finding을 검증 가능한 상태로 정규화
- patch 또는 diff 결과물을 생성
- 추후 MCP, 대시보드, HITL에 연결 가능한 응답 구조 확보

### 비목표

- 저장소 전체 프로젝트 스캔
- SonarQube 수준의 대규모 SAST
- SBOM 생성
- 최종 보고서 렌더링
- 완전 자동 수정 적용

이 항목들은 L3 또는 interface 계층의 책임으로 남긴다.

## 2. 기술 구성 원칙

L2는 하나의 기술로 해결하지 않는다. 다음 조합으로 설계한다.

### LLM

- finding 맥락 해석
- rationale 생성
- recommendation 생성
- patch 또는 diff 초안 생성

### Retrieval

- KISA, OWASP, FSEC, 내부 보안 기준 등 근거 연결
- 규칙 ID, CWE, 보안 키 기반 참조 조회
- LLM 입력에 신뢰 가능한 근거 주입

초기에는 로컬 기반 retrieval로 시작한다.

- JSON
- key lookup
- 규칙 매핑

이후 필요 시 확장한다.

- embedding
- vector DB
- ranking

### Verification

- `RegistryVerifier`
  - 패키지 존재 여부
  - 메타데이터 확인
- `OsvVerifier`
  - 알려진 취약 버전 여부
  - advisory 결과 정규화

### Patch Synthesis

- 초기에는 deterministic patch 우선
- 필요한 경우 LLM patch generation 추가
- 공급망 finding은 version bump 또는 recommendation 중심

## 3. L2 범위

### 포함 범위

- 단일 요청 단위의 finding enrichment
- evidence retrieval
- registry 및 osv verification
- patch 또는 diff 생성
- rationale 및 recommendation 반환
- errors 집계

### 제외 범위

- 저장소 전체 검색
- 전체 리포트 렌더링
- 최종 배포용 문서 생성
- 실제 코드 자동 반영

## 4. 입력과 출력 계약

### 입력 계약

L2는 아래 데이터를 입력으로 받는다.

- 원본 코드
- L1 findings
- 프로젝트 컨텍스트
  - 언어
  - 파일 경로
  - import 또는 package candidate
  - 프레임워크 힌트

예상 모델:

- `L2EnrichFixRequest`
  - `code: str`
  - `findings: list[Finding]`
  - `project_context: dict[str, Any] | None`

### 출력 계약

L2는 아래 구조를 반환한다.

- `enriched_findings`
- `verification`
- `fix_patch`
- `errors`

예상 모델:

- `L2EnrichFixResponse`
  - `enriched_findings: list[Finding]`
  - `fix_patch: str`
  - `verification: VerificationSummary`
  - `errors: list[str]`

## 5. 데이터 모델 기준

현재 실제 코드 기준선은 `VSH_Project_MVP/models`와 `VSH_Project_MVP/layer2`다.
따라서 아래 모델 설명은 `src/vsh` 복구 계획이 아니라 현재 구현에서 사용하는 계약을 설명하기 위한 참고 구조다.

### `Finding`

- `id`
- `rule_id`
- `severity`
- `category`
- `location`
- `cwe`
- `owasp`
- `kisa_key`
- `fsec_key`
- `message`
- `reachability_hint`
- `confidence`
- `evidence_refs`
- `rationale`
- `recommendation`

### `VerificationRecord`

- `subject`
- `state`
- `details`

### `VerificationSummary`

- `registry`
- `osv`

### `Location`

- `file_path`
- `start_line`
- `start_col`
- `end_line`
- `end_col`
