# Layer 3 (L3) — Cold Path: Deep Scan + SBOM + Compliance Report

## 0. 목적

- 프로젝트 전체를 대상으로 심층 검증을 수행하고,
- 컴플라이언스 관점(KISA/금융/OWASP)의 **제출 가능한 리포트**를 만든다.

---

## 1. 입력/출력

### 입력

- repo_path
- baseline_findings(optional): L1/L2 결과
- actions_log(optional): Accept/Dismiss 기록

### 출력

- report.md
- report.json
- sbom 파일(선택: SPDX/CycloneDX/Syft JSON)

---

## 2. 심층 정적 분석(SAST)

- SonarQube(또는 SonarScanner)로 전체 프로젝트 분석
- 결과 이슈를 수집해 L1/L2 finding과 병합(중복 제거/상향 조정)

---

## 3. SBOM 생성 + 취약점/라이선스 분석

### 3.1 SBOM 생성

- Syft로 repo/filesystem 스캔 → SBOM 생성

### 3.2 취약점 매칭

- SBOM에서 package+version 추출
- OSV querybatch로 취약점 목록 획득
- 결과를 “SUPPLY_CHAIN” 카테고리 finding으로 리포트에 반영

### 3.3 라이선스

- SBOM이 제공하는 라이선스 정보를 리포트 요약에 포함

---

## 4. 컴플라이언스 스코어링(권장)

- KISA 준수율: (충족 항목 / 전체 항목)
- 금융보안원 준수율: (충족 항목 / 전체 항목)
- 위험도 가중치: CRITICAL/HIGH/MEDIUM/LOW
- Human-in-the-Loop 로그: “누가/언제/무엇을 수락/거부했는지” 표로 포함

---

## 5. 리포트 구조(노션 예시와 정렬)

- 종합 점수
- 준수율 테이블
- 취약점 상세(근거/도달성/영향/조치)
- SBOM 요약(위험 라이브러리/라이선스)
- 개발자 조치 내역(HITL)
- 면책 문구(강제 포함)

---

## 6. References

- Syft(SBOM): https://github.com/anchore/syft
- OSV API: https://google.github.io/osv.dev/api/
