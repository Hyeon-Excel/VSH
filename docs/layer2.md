# Layer 2 (L2) — Warm Path: Contextual Filtering + Evidence + Fix Diff

## 0. 목적

- L1 결과(findings)를 “실제 위험”으로 정제하고,
- KISA/금융보안원 근거를 붙여 설명 가능하게 만들며,
- “수정 Diff”를 생성하되 최종 반영은 Human-in-the-Loop로 강제한다.

---

## 1. 입력/출력

### 입력

- code
- findings[] (L1 출력)
- project_context(optional): 주변 코드/설정/프레임워크 힌트

### 출력

- enriched_findings[]
  - evidence_refs: KISA/금융 항목
  - rationale: 왜 위험한지(짧게)
  - confidence 조정
- fix_patch(unified diff)
- verification
  - registry_check 결과(존재/미존재/오류)
  - osv_check 결과(CVE 목록/없음/오류)

### L1 재사용 계약

- `findings[]`는 L2의 기본 입력 계약이며, 필드 의미를 변경하지 않는다.
- `import_candidates`는 Registry/OSV 검증 대상으로 사용한다.
- L2는 L1 결과를 덮어쓰지 않고 `enriched_findings`로 확장한다.
- L1의 `annotation_patch`는 L2에서 "근거/CVE/수정 코드"가 보강된 형태로 확장 가능하다.

---

## 2. RAG 지식 베이스

### 2.1 소스

- KISA 시큐어코딩 가이드
- 금융보안원 체크리스트
- (보조) OWASP Top 10, CWE 설명

### 2.2 저장 구조(권장)

- 문서 chunk에 `kisa_key`, `fsec_key`, `tags(SQLi/XSS/Secrets/SCM)`를 메타데이터로 부여
- ChromaDB에 저장하고 검색은 `kisa_key/fsec_key` 우선 + 자연어 보조

---

## 3. 공급망 검증(네트워크 허용)

### 3.1 Registry 존재성 확인

- import/require 목록으로 PyPI/npm 조회
- “미존재”이면 hallucination 의심
- “유사 이름”은 v2(Levenshtein/allowlist)로 확장

### 3.2 OSV 취약점 조회

- (가능하면) lockfile 기반으로 package+version 목록 구성
- OSV querybatch로 CVE/OSV ID 조회
- 결과를 finding에 첨부

---

## 4. Fix Diff 생성 원칙

- 변경 최소화(“안전한 API로 치환”, “파라미터 바인딩”, “innerHTML 제거”)
- 코드 의미 변경 가능성이 있으므로 **항상 사용자 승인(accept)** 전제
- 실패 시 “수정 방향”만 제공하고 diff는 생략 가능

---

## 5. 오탐 감소(컨텍스트 필터)

- “테스트/샘플 코드”, “내부 관리자 페이지”, “외부 입력 없음” 같은 신호를 반영해
  - severity 하향 또는 reachability_hint를 UNKNOWN/NO로 조정
- 단, 기준과 근거를 함께 출력(Explainable)

---

## 6. References

- OSV querybatch: https://google.github.io/osv.dev/post-v1-querybatch/
- MCP Tools spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
