# [VSH L3] 데이터 명세 및 변수 규칙

본 문서는 L3에서 사용하는 핵심 데이터 모델인 `VulnRecord`와 `PackageRecord`의 상세 명세를 정의합니다.

---

## 1. VulnRecord (코드 취약점 정보)
코드 레벨에서 발견된 보안 취약점을 담는 핵심 모델입니다.

### 주요 필드
- **vuln_id:** `VSH-YYYYMMDD-UUID[:8]` 형식 (예: `VSH-20260309-A1B2C3D4`)
- **severity:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (CVSS에서 자동 계산 금지!)
- **status:** 현재 상태를 나타내는 7가지 허용값
  - `pending`: 초기 탐지 상태
  - `accepted` / `dismissed`: 개발자의 조치 결과
  - `poc_verified` / `poc_failed`: PoC 수행 결과
  - `poc_skipped`: Docker 미설치 등으로 건너뜀
  - `scan_error`: 분석 자체 실패

### 핵심 제약 사항
- **fss_ref:** 금융보안원 참조값. 빈 문자열(`""`)은 `None`으로 자동 변환됩니다.
- **cvss_score:** 참고용일 뿐, `severity` 결정에 직접적인 영향을 주지 않습니다.

---

## 2. PackageRecord (SBOM 패키지 정보)
프로젝트가 사용하는 외부 패키지의 보안 정보를 담습니다.

### 주요 필드
- **package_id:** `PKG-UUID[:8]` 형식 (예: `PKG-B2C3D4E5`)
- **source:** 항상 `"L3_SBOM"`으로 고정됩니다.
- **status:** 3가지 허용값
  - `safe`: 취약점 없음
  - `upgrade_required`: 취약점 발견, 업그레이드 필요
  - `license_violation`: 허용되지 않는 라이선스 사용 중

### 핵심 제약 사항
- **LLM 우회:** SBOM 데이터는 LLM을 거치지 않고 소스 도구(syft 등)의 결과를 즉시 반영합니다.

---

## 3. ID 명명 규칙 (NAMING.md 기반)
- **날짜 기반 ID:** 취약점 식별자는 생성 날짜를 포함하여 추적이 용이하게 합니다.
- **UUID 활용:** 동일 날짜에 발생한 여러 취약점을 구분하기 위해 8자리의 UUID 접미사를 사용합니다.

---

## 4. 관련 문서
- [프로젝트 개요 (OVERVIEW.md)](./OVERVIEW.md)
- [시스템 구조 및 모듈 역할 (STRUCTURE.md)](./STRUCTURE.md)
- [코드 흐름 및 실행 시퀀스 (FLOW.md)](./FLOW.md)
- [개발 가이드 및 준수 수칙 (DEVELOP.md)](./DEVELOP.md)
