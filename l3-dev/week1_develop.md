# VSH L3 Cold Path — Week 1 상세 개발 기록

본 문서는 **분위기 지켜** 팀의 L3 Cold Path 레이어 Week 1 개발 과정과 주요 설계 결정을 팀원들과 공유하기 위해 작성되었습니다.

---

## 1. 아키텍처 설계 및 파이프라인 구축

Week 1의 핵심 목표는 실제 도구가 없는 상태에서도 데이터가 M1부터 M5까지 끊김 없이 흐르는 **"동작하는 뼈대"**를 만드는 것이었습니다.

### 파이프라인 흐름 (M1 ~ M5)
- **M1 (SonarQube Mock)**: 코드 정적 분석 결과 모사.
- **M2 (SBOM Mock)**: 패키지 취약점 결과 모사 (LLM을 거치지 않는 직행 경로 확보).
- **M3 (PoC Mock)**: Docker 환경에서의 공격 실증 단계 모사.
- **M4 (Normalizer)**: 데이터 검증 및 저장. **단일 레코드 실패가 전체 스캔을 중단시키지 않는 장애 격리(Fault Tolerance)** 로직 적용.
- **M5 (Report Generator)**: 최종 마크다운 리포트 생성.

---

## 2. 데이터 모델 리팩토링 (Data Model Evolution)

기존의 단순했던 스키마를 실제 분석에 필요한 정밀한 구조로 고도화했습니다.

### [VulnRecord] — 코드 취약점
- **위치 정밀화**: `rule_id`, `end_line_number`, `column_number`, `end_column_number`, `language` 필드를 추가하여 에디터(Cursor)에서의 하이라이팅 및 정밀 분석 기반 마련.
- **리치어빌리티 개선**: 기존 `bool` 타입을 제거하고, `reachability_status` (reachable/unreachable/unknown)와 `reachability_confidence` (high/medium/low)로 세분화하여 분석의 불확실성까지 표현 가능하게 함.
- **검증 강화**: `__post_init__`을 통해 7단계의 엄격한 데이터 검증 및 정규화(예: `fss_ref` 빈 문자열 처리) 수행.

### [PackageRecord] — 오픈소스 취약점
- **증거 기록**: `code_snippet` 필드를 추가하여 해당 패키지가 `requirements.txt` 등 어느 지점에서 선언되었는지 기록.
- **필수값 조정**: 패키지 취약점은 해결책이 명확하므로 `fix_suggestion`을 필수 필드로 변경.

---

## 3. 하위 호환성 및 패키지 구조

모델 정의를 `l3/models/` 패키지로 분리하여 전문화했습니다.
- **`l3/schema.py`의 역할**: 파일을 삭제하는 대신 `l3/models/`에서 클래스를 가져와 다시 노출(Proxy)하게 함으로써, 기존에 `l3.schema`를 import하던 모든 파일(pipeline, mcp_server 등)을 수정 없이 그대로 사용할 수 있게 함.

---

## 4. 검증 및 테스트 결과

시스템의 안정성을 증명하기 위해 세 단계의 테스트를 운영합니다.

1. **`tests/test_models.py` (14개)**: 신규 모델의 생성 및 `__post_init__` 예외 처리(ValueError 등) 집중 검증.
2. **`tests/test_schema.py` (23개)**: 기존 테스트 fixture를 신규 스키마에 맞게 업데이트하여 하위 호환성 검증.
3. **`tests/test_week1_e2e.py` (3개)**: `scan_project` 툴 호출부터 리포트 파일 생성까지의 전체 프로세스 검증.

**✅ 최종 결과: 총 40개 테스트 케이스 전부 통과 (PASSED)**

---

## 5. 실행 방법 (직접 확인하기)

팀원들이 로컬에서 직접 동작을 확인해볼 수 있는 명령어입니다.

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. 전체 테스트 실행
$env:PYTHONPATH="."; pytest --tb=short -v

# 3. 리포트 생성 샘플 실행 (PowerShell/CMD 한 줄 실행)
python -c "import asyncio; from mcp_server import scan_project; print(asyncio.run(scan_project('test/mock_project')))"
```

생성된 리포트는 `reports/` 폴더에서 확인할 수 있으며, VS Code에서 `Ctrl + Shift + V`를 누르면 예쁜 문서 형태로 볼 수 있습니다.

---

## 6. 향후 계획 (Week 2)
- 실제 **Syft** 도구를 연동한 SBOM 스캔 구현.
- **OSV API**를 통한 패키지 취약점 실데이터 조회 기능 도입.
