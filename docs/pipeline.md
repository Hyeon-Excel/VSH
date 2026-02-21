# VSH Pipeline (End-to-End)

## 0. 목표

- AI 코딩 흐름을 방해하지 않는 **1초 미만 피드백(L1 중심)** 제공
- KISA/금융보안원 기준의 **근거(Evidence) + Diff 패치 + 최종 리포트** 제공
- 최종 반영은 항상 사람(Human-in-the-Loop)

---

## 1. 구성 요소

- **MCP Client**: Cursor/Claude 등 (LLM이 tool 호출)
- **VSH MCP Server (FastMCP, Python)**: tool 3개(L1/L2/L3) 제공
- **Engines**
  - L1: Semgrep(+Tree-sitter 옵션) — 패턴 기반 탐지
  - L2: LLM + RAG(ChromaDB) + Registry/OSV 검증 — 근거/수정안
  - L3: SonarQube + SBOM(Syft) + OSV — 심층 검증/리포트

---

## 2. 트리거(언제 실행되나)

### 2.1 기본 트리거(권장)

1. **코드 생성 직후**: 모델이 즉시 L1 tool 호출 (snippet 단위)
2. **사용자 “검사해줘” 요청**: L1 → L2 순차 호출
3. **제출/배포 전**: L3 tool 호출 (repo 단위)

### 2.2 Human-in-the-Loop

- 모델은 VSH가 반환한 `annotation_patch` 또는 `fix_patch`를 사용자에게 보여주고,
- 사용자가 **Accept** 시에만 패치 적용
- 적용/거부 이벤트는 `actions_log`로 남겨 L3 리포트에 포함

---

## 3. 전체 파이프라인(순서)

### Step A — L1 Hot Path (즉시 경고 + 주석 패치)

**입력**

- code(스니펫/파일), language, file_path, mode

**처리**

- Semgrep 스캔(최소 룰셋)
- Finding 정규화
- 취약 위치에 “VSH 알림 주석 블록”을 삽입하는 unified diff 생성

**출력**

- findings[]
- annotation_patch(diff)
- timing_ms

**성과**

- 사용자에게 “왜 위험한지”가 코드 안에 즉시 보인다(주석)
- 후속 L2/L3가 동일 findings를 재사용한다

---

### Step B — L2 Warm Path (근거+검증+수정 Diff)

**입력**

- code, findings[], (선택) project_context

**처리**

- RAG로 KISA/금융보안원 항목 매핑 및 근거문 추출
- (네트워크 허용) Registry 존재성 확인 / OSV 취약점 조회
- 오탐 감소(컨텍스트 기반)
- 수정 Diff 생성(“권장 수정 코드”를 patch로 제공)

**출력**

- enriched_findings[] (근거/링크/확신도 포함)
- fix_patch(diff)
- evidence_refs[] (KISA/금융 항목 키 기반)

---

### Step C — L3 Cold Path (전체 리포트)

**입력**

- repo_path, baseline_findings(optional), actions_log(optional)

**처리**

- SonarQube 전체 스캔(심층 SAST)
- Syft로 SBOM 생성
- OSV로 SBOM 기반 취약점 매칭
- KISA/금융/OWASP 기준으로 점수/준수율 산출
- Markdown + JSON 리포트 생성

**출력**

- report.md
- report.json
- sbom.(spdx|cyclonedx|syft.json) (선택)

---

## 4. 데이터 계약(Data Contract)

### 4.1 Finding(최소 필드)

- id, rule_id
- severity: CRITICAL|HIGH|MEDIUM|LOW
- category: CODE|SUPPLY_CHAIN
- location: { file_path, start_line, start_col, end_line, end_col }
- cwe: ["CWE-89"] 같은 배열
- owasp: ["A03"] 같은 배열(가능하면)
- kisa_key, fsec_key (매핑 키)
- message
- reachability_hint: YES|NO|UNKNOWN
- confidence: 0.0~1.0

### 4.2 Patch 형식

- unified diff(표준)
- L1: 주석 삽입 중심(코드 의미 변경 최소화)
- L2: 취약점 수정 중심(코드 의미 변경 있음, 반드시 HITL)

---

## 5. 성능 예산(권장)

- L1: 0.2~0.8s (최대 1s 내)
- L2: 1~3s (네트워크/LLM 포함)
- L3: 수 초~수 분(백그라운드)

---

## 6. 실패/폴백 정책

- L1 실패: “분석 불가” + 원인 로그 반환(코드 변경 없이)
- L2 네트워크 실패: 근거/검증 항목을 “UNKNOWN”으로 표시하고 패치 생성은 계속(가능한 범위)
- L3 실패: 생성 가능한 산출물부터 생성(예: SonarQube 실패 시 SBOM/OSV 기반 리포트라도 출력)

---

## 7. References

- Semgrep CLI JSON: https://semgrep.dev/docs/cli-reference
- MCP Tools spec: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- OSV querybatch: https://google.github.io/osv.dev/post-v1-querybatch/
- Syft(SBOM): https://github.com/anchore/syft
