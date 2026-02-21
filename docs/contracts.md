# VSH Contracts (Design v0)

## 1. Canonical Enums

- `Severity`: `CRITICAL | HIGH | MEDIUM | LOW`
- `Category`: `CODE | SUPPLY_CHAIN`
- `ReachabilityHint`: `YES | NO | UNKNOWN`
- `ScanMode`: `snippet | file`
- `VerificationState`: `FOUND | NOT_FOUND | UNKNOWN | ERROR`

## 2. Finding Model

필수 필드:

- `id: str`
- `rule_id: str`
- `severity: Severity`
- `category: Category`
- `location.file_path: str`
- `location.start_line/start_col/end_line/end_col: int`
- `cwe: list[str]`
- `owasp: list[str]`
- `kisa_key: str | null`
- `fsec_key: str | null`
- `message: str`
- `reachability_hint: ReachabilityHint`
- `confidence: float (0.0~1.0)`

확장 필드(옵션):

- `evidence_refs: list[str]`
- `rationale: str | null`
- `recommendation: str | null`

## 3. Tool Input/Output

### 3.1 `vsh.l1.scan_annotate`

Input:

- `code: str`
- `language: str`
- `file_path: str`
- `mode: ScanMode`

Output:

- `findings: list[Finding]`
- `annotation_patch: str` (unified diff)
- `timing_ms: int`
- `errors: list[str]`

### 3.2 `vsh.l2.enrich_fix`

Input:

- `code: str`
- `findings: list[Finding]`
- `project_context: dict[str, Any] | null`

Output:

- `enriched_findings: list[Finding]`
- `fix_patch: str` (unified diff)
- `verification.registry: list[VerificationRecord]`
- `verification.osv: list[VerificationRecord]`
- `errors: list[str]`

### 3.3 `vsh.l3.full_report`

Input:

- `repo_path: str`
- `baseline_findings: list[Finding]`
- `actions_log: list[ActionLog]`

Output:

- `report_md_path: str`
- `report_json_path: str`
- `sbom_path: str | null`
- `summary: str`
- `errors: list[str]`

## 4. Patch Contract

- 포맷: unified diff
- L1 patch: 경고 주석 삽입 중심 (코드 의미 유지)
- L2 patch: 취약 코드 수정 중심 (HITL 승인 필요)
- patch 생성 실패 시 빈 문자열 허용 + `errors`에 원인 기록

## 5. Error Contract

- 도구 실패를 예외로 중단하지 않고 구조화된 오류 배열로 반환
- 권장 오류 코드:
  - `L1_TIMEOUT`
  - `L1_TOOL_MISSING`
  - `L2_OSV_UNAVAILABLE`
  - `L2_REGISTRY_UNAVAILABLE`
  - `L3_SONAR_FAILED`
  - `L3_SBOM_FAILED`
