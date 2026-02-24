# VSH — Vibe Security Helper

> AI 코딩 환경(Cursor, Claude)에서 실시간으로 보안 취약점을 탐지하고 KISA 기준으로 근거를 제시하는 MCP 보안 도구

---

## 아키텍처 (3-Layer)

| 레이어 | 이름 | 응답 시간 | 핵심 기술 | 상태 |
|--------|------|-----------|-----------|------|
| L1 | Hot Path | **0.5초** | Semgrep + 폴백 패턴 + AST Reachability + SBOM | ✅ 구현 완료 |
| L2 | Warm Path | **1~3초** | LLM (Claude) + RAG (ChromaDB) + KISA 매핑 | 🔧 구현 예정 |
| L3 | Cold Path | **백그라운드** | SonarQube SAST + 전체 리포트 생성 | 🔧 구현 예정 |

---

## 프로젝트 구조

```
VSH/
├── main.py                     # MCP 서버 진입점
├── pyproject.toml
├── requirements.txt
├── src/
│   └── vsh/
│       ├── server.py           # FastMCP 도구 정의
│       ├── models.py           # Finding / ScanResult 데이터 모델
│       ├── l1/                 # ✅ Hot Path (구현 완료)
│       │   ├── scanner.py      # Semgrep + 폴백 패턴 매칭
│       │   ├── sbom.py         # 패키지 CVE + 환각 탐지 (OSV API)
│       │   ├── reachability.py # Python AST 기반 Taint 분석
│       │   ├── aggregator.py   # L1 파이프라인 조합
│       │   └── formatter.py    # 한국어 인라인 주석 생성
│       ├── l2/                 # 🔧 Warm Path (디렉토리만)
│       │   ├── llm.py          # LLM 심층 분석
│       │   ├── rag.py          # ChromaDB 지식 베이스
│       │   └── kisa_mapper.py  # KISA/금융보안원 매핑
│       └── l3/                 # 🔧 Cold Path (디렉토리만)
│           ├── sonarqube.py    # SonarQube SAST 연동
│           └── reporter.py     # 전체 보안 리포트 생성
├── rules/
│   └── semgrep/
│       ├── python/             # SQLi, CMDi, Secrets, Path Traversal
│       └── javascript/         # XSS, SQLi
└── tests/
    └── test_l1.py
```

---

## 설치 및 실행

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. (선택) Semgrep 설치 — 미설치 시 내장 폴백 패턴으로 동작
pip install semgrep

# 3. MCP 서버 실행
python main.py

# 4. 테스트
pytest tests/
```

### Cursor / Claude Desktop 연동

`~/.cursor/mcp.json` 또는 Claude Desktop 설정에 추가:

```json
{
  "mcpServers": {
    "vsh": {
      "command": "python",
      "args": ["/절대경로/VSH/main.py"]
    }
  }
}
```

---

## MCP 도구

| 도구 | 설명 |
|------|------|
| `scan_code(code, language, filename?)` | 코드 스니펫 실시간 스캔 → 인라인 주석 삽입 |
| `scan_file(file_path)` | 파일 스캔 → 인라인 주석 삽입 |
| `check_packages(requirements_path)` | requirements.txt / package.json CVE + 환각 탐지 |

---

## 탐지 취약점 (L1)

| 취약점 | CWE | CVSS | 지원 언어 |
|--------|-----|------|-----------|
| SQL Injection | CWE-89 | 9.8 | Python, JS |
| XSS | CWE-79 | 8.2 | JavaScript |
| OS Command Injection | CWE-78 | 9.8 | Python |
| Path Traversal | CWE-22 | 7.5 | Python |
| Hardcoded Secrets | CWE-798 | 8.4 | Python, JS |
| Insecure Deserialization | CWE-502 | 8.1 | Python |
| 패키지 환각 (Hallucination) | CWE-829 | 8.6 | PyPI, npm |
| 취약 라이브러리 (CVE) | CWE-1035 | — | PyPI, npm |

---

## 실제 동작 확인

기획서의 SQLi 예시 코드를 그대로 넣으면:

**입력 코드**
```python
user_input = request.GET['q']
query = f"SELECT * FROM users WHERE id={user_input}"
cursor.execute(query)
```

**VSH 출력 — 주석 자동 삽입**
```python
user_input = request.GET['q']
query = f"SELECT * FROM users WHERE id={user_input}"
# ⚠️  [VSH 알림] SQL Injection 취약점 감지
# ─────────────────────────────────────────────────
# 위험도      : ★★★★★ CRITICAL | CVSS 9.8
# 취약점      : CWE-89 (SQL Injection)
# 근거        : KISA 시큐어코딩 가이드 — 입력데이터 검증 및 표현 1항 (SQL 삽입)
# Reachability: ✅ 실제 도달 가능 (외부 입력 → 위험 코드 직접 연결 확인됨)
#
# 💥 영향 범위: DB 전체 조회 / 삭제 / 변조 가능
#
# 🔧 권장 수정 코드:
# cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
# ─────────────────────────────────────────────────
cursor.execute(query)
```

---

## 다음 단계

```bash
# 의존성 설치
pip install -r requirements.txt

# 단위 테스트
pytest tests/

# MCP 서버 실행
python main.py
```

---

## 팀

**분위기 지켜** | 팀장: 박혁규 | 팀원: 박혁규, 김유리, 모상인, 최현수, 김민건

*본 도구는 보조 수단이며, 최종 보안 책임은 개발자에게 있습니다.*
*적용 기준: KISA 시큐어코딩 가이드 | 금융보안원 체크리스트 | OWASP Top 10*
