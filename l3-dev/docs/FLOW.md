# [VSH L3] 코드 흐름 및 실행 시퀀스

본 문서는 L3 스캔이 시작되어 리포트가 생성되기까지의 데이터 흐름을 설명합니다.

---

## 1. 전체 실행 시퀀스 (M1 ~ M4)
`l3/pipeline.py`의 `L3Pipeline.run()` 메서드가 전체 과정을 오케스트레이션합니다.

1.  **M1 (SonarQube):** 프로젝트 경로를 스캔하여 SAST 취약점 목록(`VulnRecord`)을 추출합니다.
2.  **M2 (SBOM):** 프로젝트의 종속성 정보를 읽어 패키지 취약점 및 라이선스 정보(`PackageRecord`)를 생성합니다.
3.  **M4 (Save M2):** SBOM 결과는 LLM을 거치지 않고 **즉시 DB에 저장**됩니다.
4.  **M3 (PoC):** M1에서 발견된 각 취약점에 대해 PoC 실행 여부를 결정하고, 결과를 해석합니다.
5.  **M4 (Save M1/M3):** PoC 결과가 포함된 최종 `VulnRecord`를 DB에 저장합니다.

---

## 2. Mock → Real 전환 방식 (DI 패턴)
우리 프로젝트는 주차별로 Mock 모듈을 Real 모듈로 교체합니다. 이 변경은 오직 **`mcp_server.py`의 단 한 줄**에서만 발생합니다.

```python
# mcp_server.py 예시

# Week 1: Mock 객체 주입
pipeline = L3Pipeline(
    sonarqube=MockSonarQubeProvider(),
    sbom=MockSBOMProvider(),
    poc=MockPoCProvider(),
    normalizer=normalizer
)

# Week 3: 실무 적용 시 Real 객체로 교체
pipeline = L3Pipeline(
    sonarqube=RealSonarQubeProvider(), # 이 부분만 수정
    sbom=RealSBOMProvider(),
    poc=MockPoCProvider(),
    normalizer=normalizer
)
```

---

## 3. MCP 기반 트리거 흐름
외부 클라이언트(Cursor, Claude 등)에서 스캔을 요청하면 다음 순서로 동작합니다.

1.  **Tool: `trigger_l3_scan` 호출**
    - 백그라운드 태스크로 `pipeline.run()` 실행.
    - 클라이언트에게는 즉시 "스캔 시작됨" 메시지 반환.
2.  **백그라운드 처리**
    - M1 → M2 → M3 순차 진행.
    - 각 단계 완료 시마다 진행 상황 로깅.
3.  **Tool: `generate_report` 호출**
    - DB에서 저장된 모든 레코드를 읽어 MD/JSON 리포트 파일 생성.
    - 리포트 경로를 사용자에게 반환.

---

## 4. 관련 문서
- [프로젝트 개요 (OVERVIEW.md)](./OVERVIEW.md)
- [시스템 구조 및 모듈 역할 (STRUCTURE.md)](./STRUCTURE.md)
- [데이터 명세 및 변수 규칙 (DATA_SPEC.md)](./DATA_SPEC.md)
- [개발 가이드 및 준수 수칙 (DEVELOP.md)](./DEVELOP.md)
