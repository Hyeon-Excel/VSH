# VSH L3 API 명세서 (API Specification)

본 문서는 VSH(Vibe Coding Secure Helper) L3 Cold Path 레이어의 외부 인터페이스 및 데이터 스키마를 정의합니다. L1/L2 레이어 개발자와의 협업을 위한 가이드라인을 포함합니다.

---

## 섹션 1. MCP 툴 명세 (MCP Tool Specification)

L3 Cold Path는 FastMCP를 통해 IDE(Cursor/Claude)에서 호출 가능한 도구를 노출합니다.

### scan_project
프로젝트 전체에 대한 정적 분석(SAST), 공급망 분석(SBOM), 공격 실증(PoC)을 수행하고 최종 보안 리포트를 생성합니다.

*   **설명**: 프로젝트 보안 스캔 실행 및 리포트 생성
*   **트리거**: Cursor/Claude IDE에서 소스 코드 저장(Ctrl+S) 시 호출
*   **파라미터**:
    | 파라미터명 | 타입 | 필수 | 설명 |
    | :--- | :--- | :---: | :--- |
    | `project_path` | `str` | ✅ | 스캔을 수행할 프로젝트의 루트 경로 |

*   **반환값**:
    *   **타입**: `str`
    *   **형식**: `"스캔 완료: reports/vsh_report_{YYYYMMDD_HHMMSS}.md"`
    *   **예시**: `"스캔 완료: reports/vsh_report_20240315_143022.md"`

*   **내부 실행 순서**:
    1.  `pipeline.run(project_path)` 호출: M1(SAST) → M2(SBOM) → M3(PoC) 단계를 거쳐 M4(Normalizer)가 결과를 DB에 저장합니다.
    2.  `report_generator.generate()` 호출: M5 단계로, DB에서 모든 결과를 읽어 요약 및 상세 정보를 포함한 Markdown 리포트를 생성합니다.
    3.  생성된 리포트 파일의 경로를 포함한 성공 메시지를 반환합니다.

*   **에러 처리**:
    *   **Week 1**: 예외 발생 시 상위로 전파되어 클라이언트에서 런타임 에러로 인지됩니다.
    *   **Week 3~4**: 실제 구현 단계에서는 예외를 포착하여 사용자 친화적인 에러 메시지 문자열을 반환하도록 고도화될 예정입니다.

---

## 섹션 2. 데이터 스키마 (Data Schema)

L3 시스템에서 관리하는 핵심 데이터 모델입니다.

### VulnRecord (코드 취약점 기록)
소스 코드 분석 및 PoC 검증을 통해 발견된 취약점 정보입니다.

| 필드명 | 타입 | 필수 | 기본값 | 설명 | 허용값 |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `vuln_id` | `str` | ✅ | - | 취약점 식별자 | 예: "VSH-20260309-ABCD" |
| `source` | `str` | ✅ | - | 분석 소스 | `L1`, `L2`, `L3_SONARQUBE`, `L3_POC` |
| `detected_at` | `str` | ✅ | - | 탐지 시각 (ISO 8601) | - |
| `file_path` | `str` | ✅ | - | 취약 파일 경로 | - |
| `line_number` | `int` | ✅ | - | 취약 라인 번호 | - |
| `code_snippet` | `str` | ✅ | - | 취약 코드 원문 | - |
| `vuln_type` | `str` | ✅ | - | 취약점 유형 | 예: "SQLi", "XSS" |
| `cwe_id` | `str` | ✅ | - | CWE ID | 예: "CWE-89" |
| `cve_id` | `Optional[str]` | - | `None` | CVE ID | - |
| `cvss_score` | `float` | ✅ | - | CVSS 점수 (0.0~10.0) | - |
| `severity` | `str` | ✅ | - | 위험도 수준 | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `kisa_ref` | `str` | ✅ | - | KISA 준거항목 | - |
| `fss_ref` | `Optional[str]` | - | `None` | 금융보안원 준거항목 | - |
| `owasp_ref` | `Optional[str]` | - | `None` | OWASP TOP 10 매핑 | - |
| `reachability` | `Optional[bool]`| - | `None` | 실행 도달 가능성 | `True`, `False`, `None` |
| `fix_suggestion`| `Optional[str]` | - | `None` | 수정 권장 방안 | - |
| `status` | `str` | ✅ | `"pending"` | 조치 상태 | 아래 허용값 참조 |
| `action_at` | `Optional[str]` | - | `None` | 조치 시각 | - |

*   **`status` 허용값**: `pending`, `accepted`, `dismissed`, `poc_verified`, `poc_failed`, `poc_skipped`, `scan_error`
*   **검증 규칙 (`__post_init__`)**:
    1.  `severity`가 위 4개 허용값 외의 값이면 `ValueError`를 발생시킵니다.
    2.  `fss_ref`가 빈 문자열(`""`)로 들어오면 `None`으로 자동 변환하여 데이터 일관성을 유지합니다.
    3.  `status`가 위 7개 허용값 외의 값이면 `ValueError`를 발생시킵니다.

### PackageRecord (패키지 취약점 기록)
SBOM 스캔을 통해 발견된 오픈소스 라이선스 및 패키지 취약점 정보입니다.

| 필드명 | 타입 | 필수 | 기본값 | 설명 | 허용값 |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `package_id` | `str` | ✅ | - | 패키지 분석 식별자 | - |
| `detected_at` | `str` | ✅ | - | 탐지 시각 (ISO 8601) | - |
| `name` | `str` | ✅ | - | 패키지 이름 | - |
| `version` | `str` | ✅ | - | 현재 설치 버전 | - |
| `ecosystem` | `str` | ✅ | - | 패키지 생태계 | `PyPI`, `npm`, `Maven` 등 |
| `cve_id` | `Optional[str]` | - | `None` | 관련 CVE ID | - |
| `severity` | `str` | ✅ | - | 위험도 수준 | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `cvss_score` | `Optional[float]`| - | `None` | CVSS 점수 | - |
| `license` | `Optional[str]` | - | `None` | 패키지 라이선스 | - |
| `license_risk` | `bool` | ✅ | - | 라이선스 위험 여부 | - |
| `status` | `str` | ✅ | - | 패키지 조치 상태 | 아래 허용값 참조 |
| `fix_suggestion`| `Optional[str]` | - | `None` | 업데이트 권장 버전 | - |
| `source` | `str` | ✅ | `"L3_SBOM"` | 데이터 소스 (고정값) | `L3_SBOM` |

*   **`status` 허용값**: `safe` (취약점 없음), `upgrade_required` (업그레이드 필요), `license_violation` (라이선스 위반)
*   **`source` 고정 규칙**: `PackageRecord`의 `source`는 항상 `"L3_SBOM"`이어야 하며 변경이 불가능합니다.

---

## 섹션 3. AbstractSharedDB 인터페이스 (Shared DB Interface)

L1/L2 레이어가 분석 결과를 Shared Log RAG DB에 접근하거나 저장할 때 사용하는 추상 인터페이스입니다.

#### `write(record)`
*   **설명**: `VulnRecord` 또는 `PackageRecord` 객체를 DB에 영구 저장합니다.
*   **파라미터**: `record: VulnRecord | PackageRecord`
*   **반환값**: `None`
*   **예외**: 데이터베이스 연결 실패나 제약 조건 위반 시 `Exception`이 발생하며 상위로 전파됩니다.

#### `read_all_vuln()`
*   **설명**: 현재 DB에 저장된 모든 코드 취약점(`VulnRecord`) 목록을 조회합니다.
*   **파라미터**: 없음
*   **반환값**: `list[VulnRecord]` (데이터가 없으면 빈 리스트를 반환합니다.)
*   **주의**: 원본 데이터 보호를 위해 내부 리스트의 **복사본을 반환**합니다. 반환된 리스트를 수정해도 DB 원본에는 영향을 주지 않습니다.

#### `read_all_package()`
*   **설명**: 현재 DB에 저장된 모든 패키지 분석 기록(`PackageRecord`) 목록을 조회합니다.
*   **파라미터**: 없음
*   **반환값**: `list[PackageRecord]` (데이터가 없으면 빈 리스트를 반환합니다.)
*   **주의**: 위와 동일하게 **복사본을 반환**합니다.

---

## 섹션 4. Mock → Real 교체 가이드 (Migration Guide)

L3는 의존성 주입(DI) 패턴을 사용하여 설계를 완료했습니다. 개발 주차에 따라 구현체를 교체하는 방법은 다음과 같습니다.

### 교체 원칙
`mcp_server.py`의 상단 `import` 문과 객체 생성 부분 단 **2줄만 변경**하면 됩니다. 파이프라인(`pipeline.py`)을 포함한 다른 모든 비즈니스 로직 파일은 수정이 전혀 필요하지 않습니다.

#### Week 2 교체 (SBOM 스캔 실체화)
*   **변경 전**: `from l3.providers.sbom.mock import MockSBOMProvider; sbom = MockSBOMProvider()`
*   **변경 후**: `from l3.providers.sbom.real import RealSBOMProvider; sbom = RealSBOMProvider()`
*   **사전 준비**: 로컬 환경에 `syft` CLI 도구가 설치되어 있어야 합니다.

#### Week 3 교체 (SonarQube 연동 실체화)
*   **변경 전**: `from l3.providers.sonarqube.mock import MockSonarQubeProvider; sonarqube = MockSonarQubeProvider()`
*   **변경 후**: `from l3.providers.sonarqube.real import RealSonarQubeProvider; sonarqube = RealSonarQubeProvider()`
*   **사전 준비**: `sonar-scanner` CLI 및 `Docker` 환경이 필요합니다.

#### Week 4 교체 (PoC 샌드박스 실체화)
*   **변경 전**: `from l3.providers.poc.mock import MockPoCProvider; poc = MockPoCProvider()`
*   **변경 후**: `from l3.providers.poc.real import RealPoCProvider; poc = RealPoCProvider()`
*   **사전 준비**: PoC용 템플릿 실행을 위한 격리된 `Docker` 실행 환경이 필요합니다.

### 교체 후 검증 방법
구현체 교체 후에도 시스템의 안정성을 보장하기 위해 아래 테스트를 반드시 수행합니다.
1.  `pytest tests/test_schema.py -v`: 데이터 검증 로직 확인
2.  `pytest tests/test_week1_e2e.py -v`: 전체 파이프라인 흐름 확인

**참고**: Week 1에서 작성된 Mock 테스트는 `mcp_server`의 전역 객체를 `patch`하여 사용하므로, 실제(Real) 구현체로 교체된 후에도 여전히 전체 흐름의 정합성을 검증하는 용도로 사용될 수 있습니다.
