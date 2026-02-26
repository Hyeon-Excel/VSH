# VSH Implementation Roadmap (Current)

## 0) 현재 기준선

완료:

- L1 Hot Path 구현
  - Semgrep + Tree-sitter 동시 실행
  - finding 정규화 + annotation patch 생성
  - patch apply 유틸(`scripts/apply_l1_annotations.py`)
  - findings export 유틸(`scripts/export_l1_findings.py`)
- L1 테스트/게이트 체계
  - pytest + smoke + perf + 자동 리포트
  - GitHub Actions L1 CI 워크플로

진행 중:

- L2/L3 외부 연동 로직(RAG/Registry/OSV/Sonar/SBOM)
- branch protection required check 설정(저장소 설정 영역)

---

## 1) Milestone A: L1 안정화 (Done/Hardening)

- [x] L1 계약(입출력 모델) 고정
- [x] 취약/안전 fixture 기반 회귀 테스트
- [x] 장애 격리 테스트(Semgrep 실패, Tree-sitter 실패)
- [x] 성능 게이트(cache miss/hit p95)
- [x] 주석 patch 생성 및 적용 경로 제공
- [x] 문서/협업 가이드 최신화

Exit criteria:

- L1 테스트 전체 통과
- 산출물(`L1-test-result.md`, perf JSON, logs) 재현 가능
- 협업자가 로컬에서 동일 명령으로 결과 재현 가능

---

## 2) Milestone B: L2 Warm Path 구현

핵심 목표:

- L1 결과를 "설명 가능한 보안 판단"으로 승격

작업 항목:

- [ ] RAG Retriever 구현 (KISA/FSEC/OWASP 근거 검색)
- [ ] RegistryVerifier 구현 (PyPI/npm 존재성 검증)
- [ ] OsvVerifier 구현 (OSV querybatch)
- [ ] L2 `enriched_findings`에 근거/검증 결과 주입
- [ ] L2 `fix_patch` 생성기 구현 (최소 변경 원칙)
- [ ] L1 `annotation_patch` 업그레이드 템플릿 설계
  - L2 보강 후 "근거/CVE/수정코드"를 포함한 주석 포맷 확장

L1 재사용 포인트:

- `findings`: L2 판단 입력의 주축
- `import_candidates`: 공급망 검증 입력
- `finding_id`: L2/L3 추적 ID로 유지

Exit criteria:

- L2 응답에 evidence/verification이 실제 데이터로 채워짐
- 외부 API 장애 시 `UNKNOWN` fallback 유지
- L2 단위/통합 테스트 통과

---

## 3) Milestone C: L3 Cold Path 구현

핵심 목표:

- 프로젝트 단위 심층 분석과 제출 가능한 리포트 완성

작업 항목:

- [ ] SonarRunner 실연동 및 Finding 변환
- [ ] SyftRunner 실연동 및 SBOM 산출
- [ ] SBOM + OSV 매핑
- [ ] L1/L2/L3 finding 병합/중복제거 로직
- [ ] Markdown/JSON 리포트 렌더러 고도화
- [ ] actions_log 반영 감사 추적

L1/L2 재사용 포인트:

- L1/L2 `finding_id` 기반으로 리포트 추적 가능성 유지
- L2 근거(evidence_refs)와 L3 감사 결과를 동일 레코드로 집계

Exit criteria:

- report.md/report.json/sbom 산출물 생성
- baseline/actions_log 포함된 감사 가능한 리포트 생성

---

## 4) Milestone D: 통합 운영/품질

작업 항목:

- [ ] L2/L3 CI 게이트 추가 및 merge blocking 완성
- [ ] CODEOWNERS + workflow 보호 정책 적용
- [ ] 관측성(타이밍/오류코드/실패 원인) 표준화
- [ ] 레이어 통합 E2E 시나리오(탐지 -> 보강 -> 리포트) 구축

Exit criteria:

- PR 머지 조건에 레이어별 게이트 포함
- 운영 시나리오 문서 및 플레이북 완비

---

## 5) 구현 원칙 (협업자/에이전트 공통)

- L1 계약 호환성 우선: `Finding`, `import_candidates`, `annotation_patch`
- 확장은 "추가" 방식으로 진행하고, 기존 필드 의미를 변경하지 않음
- 테스트 없는 기능 추가 금지 (최소 smoke/pytest 1개 이상)
- 문서/스크립트/코드 변경을 한 세트로 유지
