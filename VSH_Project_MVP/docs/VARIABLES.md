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
각 로그 항목은 다음 필드를 포함합니다.
- `issue_id`: 고유 식별자 (ScanResult + FixSuggestion 조합)
- `file_path`: 분석 대상 소스 파일 경로
- `status`: 현재 처리 상태 (pending / accepted / dismissed)
- `cwe_id`: 탐지된 취약점 유형
- `severity`: 취약점 심각도

### Status Allowed Values
`MockLogRepo.update_status`에서 허용하는 값:
- **pending**: 분석 직후의 기본 상태 (대시보드 표시용)
- **accepted**: 사용자가 수정을 승인한 상태 (파일 수정 적용 대상)
- **dismissed**: 사용자가 오탐으로 판단하여 무시한 상태 (로그에는 남으나 대시보드에서는 필터링 가능)

### Paths & Constants (config.py)
- `KNOWLEDGE_PATH`: `mock_db/knowledge.json` (지식 베이스 경로)
- `FIX_PATH`: `mock_db/kisa_fix.json` (수정 가이드 경로)
- `MOCK_DB_DIR`: `mock_db/` 폴더 절대 경로
- `PROJECT_ROOT`: 프로젝트 루트 디렉토리 (`pathlib.Path`)

### Environment Variables (.env)
- `LOG_PATH`: 분석 결과 로그가 저장되는 JSON 파일 경로 (기본값: `mock_db/log.json`)
- `ANTHROPIC_API_KEY`: Claude API 연동을 위한 키
- `DASHBOARD_PORT`: 대시보드 서버 포트 (기본값: 3000)

---

## Scanner Detection Logic

### VULNERABLE_PACKAGES (config.py)
SBOMScanner에서 대조하는 취약 패키지 DB 구조입니다.
- `package_name`: (key) 패키지 소문자 이름
- `vulnerable_below`: 취약한 버전의 상한선 (이 버전 미만이면 취약)
- `cve`: 관련 CVE 식별자

### 탐지 방식 차이
1. **SemgrepScanner (문자열 매칭)**: 소스 코드를 한 줄씩 읽으며 정규표현식 패턴이 존재하는지 검사합니다.
2. **TreeSitterScanner (AST 파싱)**: 코드를 구조적으로 분석하여 '함수 호출(Call Node)' 구문에서만 패턴을 검사하여 오탐을 줄입니다.
3. **SBOMScanner (SBOM 대조)**: 패키지 의존성 파일(`requirements.txt`)의 버전을 `VULNERABLE_PACKAGES`와 비교하여 취약한 라이브러리 사용을 탐지합니다.

### SBOM 탐지 예시 (Vulnerability 필드)
- `cwe_id`: "CWE-829" (Inclusion of Functionality from Untrusted Control Sphere)
- `severity`: "HIGH"
