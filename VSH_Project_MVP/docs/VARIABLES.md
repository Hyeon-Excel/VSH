# Variables & Constants

## Domain Model Constants

### Severity Levels
취약점의 심각도를 나타내며, `Vulnerability.severity` 필드에 사용됩니다.

- **HIGH**: 즉각적인 조치가 필요한 심각한 보안 위협 (예: Command Injection, SQL Injection)
- **MEDIUM**: 잠재적인 보안 위협이나 조건부로 발생 가능한 취약점
- **LOW**: 코드 품질이나 모범 사례 위반 수준의 경미한 이슈

### Language Codes
지원하는 언어 코드 목록 (`ScanResult.language` 필드 등에서 사용)

- **python**: Python 언어 (MVP 지원)
- **c**: C 언어 (Post-MVP 예정)
- **javascript**: JavaScript 언어 (Post-MVP 예정)

---

## Repository & Storage

### Log Data Structure (log.json)
`Pipeline` 실행 후 `LogRepo`에 영구 저장되는 데이터 구조입니다.
- `issue_id`: 고유 식별자 (`{file_path}_{cwe_id}_{line_number}`)
- `file_path`: 분석 대상 소스 파일 경로
- `cwe_id`: 탐지된 취약점 유형
- `severity`: "HIGH", "MEDIUM", "LOW"
- `line_number`: 코드 라인 번호
- `code_snippet`: L1에서 탐지된 의심 코드 한 줄
- `original_code`: L2 분석 시 사용된 원본 전체 컨텍스트 (수정 전)
- `fixed_code`: AI가 제안한 안전한 코드 (수정 후)
- `status`: 현재 처리 상태 (`pending`, `accepted`, `dismissed`)

### Status Allowed Values
- **pending**: 분석 직후의 기본 상태
- **accepted**: 사용자가 수정을 승인하고 코드를 복사한 상태
- **dismissed**: 사용자가 오탐으로 판단하여 무시한 상태

---

## Dashboard UI & Interactions

### Clipboard Copy Fallback
대시보드 브라우저에서 `Accept` 클릭 시 `navigator.clipboard` API를 통한 자동 복사를 시도합니다. 만약 브라우저 보안 정책이나 권한 문제로 실패할 경우, 카드 하단에 읽기 전용 `textarea`를 노출하여 사용자가 수동으로 복사할 수 있게 합니다.

### Paths & Constants (config.py)
- `KNOWLEDGE_PATH`: `mock_db/knowledge.json`
- `FIX_PATH`: `mock_db/kisa_fix.json`
- `PROJECT_ROOT`: 프로젝트 루트 디렉토리 (`pathlib.Path`)

### Environment Variables (.env)
- `LOG_PATH`: 분석 결과 로그 파일 경로 (`mock_db/log.json`)
- `LLM_PROVIDER`: 사용할 AI 제공자 (`gemini` 또는 `claude`)
- `DASHBOARD_PORT`: 대시보드 서버 포트 (기본값: 3000)
