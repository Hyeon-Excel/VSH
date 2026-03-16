# 📢 [공유] VSH L3 레이어 개발 현황 및 협업 가이드

본 문서는 L1, L2 팀원들과의 원활한 기술 연동 및 데이터 일관성 유지를 위해 작성되었습니다. 현재 Week 2의 핵심 목표인 **"데이터 모델 고도화"** 및 **"실제 SBOM 스캔 연동"**이 성공적으로 완료되었습니다.

---

## 1. 데이터 규약 및 모델 변경 (Data Contract)
L1/L2 분석 결과를 Shared DB에 기록할 때 아래 변경사항을 반드시 확인해 주세요.

*   **모델 위치 분리:** 이제 모든 데이터 모델은 `l3/models/` 패키지에서 전문적으로 관리됩니다.
*   **VulnRecord (코드 취약점) 주요 변경:**
    *   **정밀 위치 정보:** `rule_id`, `end_line_number`, `column_number`, `end_column_number`, `language` 필드가 추가되었습니다. 에디터 하이라이팅 연동을 위해 정확한 숫자 기입이 필요합니다.
    *   **리치어빌리티 세분화:** 기존 `bool` 타입에서 `reachability_status` (reachable/unreachable/unknown)와 `reachability_confidence` (high/medium/low)로 변경되었습니다. **반드시 소문자**로 입력해야 합니다.
*   **데이터 검증 로직 (`__post_init__`):**
    *   객체 생성 시 허용되지 않은 `severity`나 `status` 값이 들어오면 즉시 `ValueError`가 발생합니다. (보안 리포트의 무결성 보장)
    *   `fss_ref` 필드에 빈 문자열(`""`)을 넣으면 자동으로 `None`으로 변환되어 리포트 가독성을 높입니다.
*   **하위 호환성 유지:** 기존에 사용하던 `from l3.schema import VulnRecord` 경로를 그대로 사용해도 내부적으로 신규 모델과 연결되도록 설계되어 있습니다.

---

## 2. 실제 SBOM 스캔 도입 (Real Scan Logic)
가짜 데이터가 아닌, 실제 프로젝트의 오픈소스 취약점을 탐지하기 시작했습니다.

*   **탐지 도구:** `syft`를 활용하여 프로젝트 루트의 `requirements.txt` 및 설치된 패키지 의존성을 추출합니다.
*   **취약점 DB:** Google의 **OSV(Open Source Vulnerability) API**를 실시간으로 호출하여 최신 CVE 정보를 매핑합니다.
*   **데이터 최적화:**
    *   하나의 취약점이 여러 식별자(GHSA, PYSEC 등)로 보고될 경우, **중복 CVE를 자동으로 제거**하여 리포트 중복을 방지합니다.
    *   현재는 MVP 목표에 따라 **Python 패키지**만 선별적으로 분석합니다.

---

## 3. 개발 환경 업데이트 (Dev-Environment)
로컬에서 L3 기능을 테스트하기 위해 아래 설정이 필요합니다.

*   **필수 CLI 도구 설치:** 실제 스캔을 수행하려면 `syft`가 설치되어 있어야 합니다.
    *   Windows: `winget install anchore.syft`
*   **의존성 업데이트:** 신규 라이브러리 반영을 위해 명령어를 실행해 주세요.
    *   `pip install -r requirements.txt`
*   **Python 버전:** 프로젝트 표준인 **Python 3.13.x** 환경을 권장합니다.

---

## 4. 시스템 안정성 및 품질 (QA & Reliability)
현재 L3 레이어는 매우 견고한 상태를 유지하고 있습니다.

*   **테스트 커버리지:** 현재 **총 53개의 자동화 테스트 케이스**가 작성되어 있으며, 100% 통과(PASSED) 중입니다.
    *   `test_models.py`: 신규 모델 검증 (14개)
    *   `test_schema.py`: 하위 호환성 검증 (23개)
    *   `test_week1_e2e.py`: 전체 파이프라인 흐름 검증 (3개)
    *   `test_week2_sbom.py`: 실제 SBOM API 로직 검증 (13개)
*   **장애 격리 (Fault Tolerance):** 네트워크 일시 오류나 특정 패키지의 분석 실패가 전체 스캔 프로세스를 중단시키지 않도록 설계되었습니다. 실패한 항목은 로그를 남기고 리포트에는 안전하게 표시됩니다.

---

## 5. IDE 연동 및 사용 가이드 (Usage Guide)
L3 기능을 활용하는 방법입니다.

*   **MCP 툴 호출:** Cursor나 Claude 에디터에서 `scan_project` 도구를 호출하면 전체 스캔이 시작됩니다.
*   **리포트 확인:** 스캔 완료 후 `reports/` 폴더에 생성된 `.md` 파일을 확인하세요.
    *   **Tip:** VS Code에서 해당 파일을 열고 **`Ctrl + Shift + V`**를 누르면 표와 서식이 적용된 예쁜 문서를 볼 수 있습니다.
*   **수동 실행 명령어 (터미널):**
    ```bash
    python -c "import asyncio; from mcp_server import scan_project; print(asyncio.run(scan_project('.')))"
    ```

---

**궁금한 점이나 데이터 구조 추가 제안이 있다면 언제든 L3 담당자에게 문의해 주세요!**
