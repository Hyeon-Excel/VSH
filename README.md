# 🛡️ VSH v1.0 - Vibe Secure Helper

**VSH(Vibe Secure Helper)** 는 실시간 AppSec 가로채기(interceptor) 도구로, 코드 취약점, 공급망 보안, 패키지 환각(hallucination) 감지를 통합합니다.

## 🎯 핵심 기능 (v1.0)

### L1 Hot Path (0.3~1.0s)
- **Semgrep 기반 패턴 탐지**: SQL Injection, XSS, Command Injection 등
- **패키지 환각/타이포스쿼팅 감지**: PyPI/npm 레지스트리 존재성 검증
- **SBOM 생성**: syft 지원 (없으면 requirements.txt/package-lock.json 자동 fallback)
- **OSV API 취약점 조회**: 라이브러리 취약점 데이터베이스 조회
- **간이 Reachability**: 소스(외부입력) → 싱크(취약 호출) 간 파일 내 근접성 분석

### 출력
- **IDE 주석 스타일 알림**: 코드 위치에 직접 삽입 가능한 형식
- **Markdown 리포트**: 종합 보안 점수 + 취약점 + 공급망 위험 + 환각 패키지

---

## 📁 프로젝트 구조

```
vsh/
  ├─ pyproject.toml
  ├─ README.md
  ├─ vsh/
  │  ├─ __init__.py
  │  ├─ cli.py                      # 메인 CLI 진입점
  │  ├─ core/
  │  │  ├─ __init__.py
  │  │  ├─ config.py                # VSHConfig 설정 클래스
  │  │  ├─ models.py                # Pydantic 데이터 모델
  │  │  └─ utils.py                 # 공용 유틸리티 함수
  │  ├─ engines/
  │  │  ├─ __init__.py
  │  │  ├─ semgrep_engine.py        # Semgrep 실행
  │  │  ├─ registry_engine.py       # 패키지 존재성 검증
  │  │  ├─ sbom_engine.py           # SBOM 생성
  │  │  ├─ osv_engine.py            # OSV API 조회
  │  │  ├─ reachability_engine.py   # 간이 Reachability
  │  │  └─ report_engine.py         # 리포트 생성
  │  ├─ rules/
  │  │  └─ semgrep/
  │  │     ├─ python.yml            # Python 취약 패턴 룰
  │  │     └─ javascript.yml        # JavaScript 취약 패턴 룰
  │  └─ demo_targets/
  │     ├─ python_sqli.py           # SQL Injection 데모
  │     ├─ js_xss.js                # XSS 데모
  │     └─ python_pkg_hallucination.py  # 패키지 환각 데모
  ├─ scripts/
  │  └─ install_semgrep.sh
  └─ docker/
     ├─ Dockerfile
     └─ docker-compose.yml
```

---

## 🚀 빠른 시작

### 1️⃣ 환경 설정

#### Windows 환경
```powershell
# Python 3.10+ 필요
python -m venv .venv
.venv\Scripts\Activate.ps1

pip install -e .
pip install semgrep
```

#### Linux/macOS 환경
```bash
python -m venv .venv
source .venv/bin/activate

pip install -e .
pip install semgrep
```

### 2️⃣ 데모 스캔

```bash
# Python 데모 스캔 (SQL Injection + 패키지 환각)
vsh vsh/demo_targets --out vsh_out --lang python --no-syft

# JavaScript 데모 스캔 (XSS)
vsh vsh/demo_targets --out vsh_out --lang javascript --no-syft
```

### 3️⃣ 결과 확인

```bash
# 콘솔 출력
# ✅ 요약 표(findings, 공급망 취약점, 환각 패키지 개수, 보안 점수)
# ✅ 인라인 주석 스타일 알림 (장성 문제가 있는 파일별)
# ✅ 패키지 환각 목록

# 마크다운 리포트
cat vsh_out/VSH_REPORT.md
```

---

## 🔧 명령어 옵션

```bash
vsh <project_path> [OPTIONS]

옵션:
  --out <dir>           # 출력 디렉토리 (기본값: vsh_out)
  --lang <lang>         # 강제 언어 설정 (python|javascript, 기본값: auto detect)
  --no-syft             # syft 비활성화 (fallback 사용)
```

### 예시

```bash
# 특정 프로젝트 스캔
vsh /path/to/myproject --out results --lang python

# syft 없이 스캔
vsh . --no-syft

# JavaScript 프로젝트
vsh ./frontend --lang javascript
```

---

## 📊 출력 형식

### 콘솔 요약
```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ VSH Scan Summary                                          ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Type                     │ Count                          │
├──────────────────────────┼────────────────────────────────┤
│ Code Findings            │ 1                              │
│ Dependency Vulns (OSV)   │ 0                              │
│ Hallucinated Packages    │ 1                              │
│ Score                    │ 65 / 100                       │
└──────────────────────────┴────────────────────────────────┘
```

### 인라인 주석 (IDEe 주석 삽입용)
```python
# ⚠️ [VSH 알림] SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.
# ─────────────────────────────────────────────────
# 위험도      : ★★★★★ CRITICAL | CVSS 9.8
# 취약점      : CWE-89
# CVE         : CVE-2023-32315
# Reachability: ✅ 실제 도달 가능
#
# 💬 메시지   : SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.
#
# 🔧 권장 수정 코드:
# query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))
```

### Markdown 리포트 (`vsh_out/VSH_REPORT.md`)
```markdown
# 🛡️ VSH 보안 진단 리포트

**프로젝트명** : demo_targets
**진단일시**   : 2026-02-20 14:30:45
**진단엔진**   : VSH v1.0 (Semgrep + SBOM + OSV + Registry Check)

## 📊 종합 보안 점수 : 65 / 100

## 🚨 코드 취약점
### [CRITICAL] SQL Injection 가능성 — `python_sqli.py:6`
- **ID**           : VSH-PY-SQLI-001
- **CWE**          : CWE-89
- **CVE**          : CVE-2023-32315
- **CVSS**         : 9.8
- **Reachability** : YES
- **메시지**       : SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.
- **조치**         : query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))
- **참고**         : KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현

## 📦 공급망 / 라이브러리 취약점 (OSV)
- 탐지된 라이브러리 취약점 없음(또는 조회 실패)

## 🧨 패키지 환각 / 존재성 이상
- ❌ 레지스트리 미존재 의심: `reqeusts`
```

---

## 🎬 발표 데모 시나리오 (2분)

1. **SQL Injection 탐지**
   ```bash
   vsh vsh/demo_targets --lang python --no-syft
   ```
   - 결과: `python_sqli.py` 에서 **CRITICAL** SQLi 발견
   - Reachability: **YES** (실제 도달 가능)

2. **패키지 환각 감지**
   - 결과: `python_pkg_hallucination.py` 에서 `reqeusts` 미존재
   - 타이포스쿼팅 공격 예방 가능

3. **Markdown 리포트 검토**
   - `vsh_out/VSH_REPORT.md` 열기
   - 종합 점수 65/100 확인
   - 취약점, 공급망, 환각 항목 검토

---

## 🔐 지원 언어 & 취약점 유형 (v1.0)

### Python 규칙
- **VSH-PY-SQLI-001**: SQL Injection (f-string)
- **VSH-PY-SECRET-001**: 하드코딩된 Secret Key
- **VSH-PY-CMDI-001**: Command Injection

### JavaScript 규칙
- **VSH-JS-XSS-001**: DOM XSS (innerHTML)

### 공급망 (SBOM/OSV)
- PyPI 라이브러리
- npm 패키지

### 패키지 검증
- PyPI 레지스트리 존재성 확인
- npm 레지스트리 존재성 확인

---

## 🛠️ 의존성

### 필수
- Python >= 3.10
- `pydantic>=2.6`
- `rich>=13.7`
- `pyyaml>=6.0`
- `requests>=2.31`
- `semgrep` (자동 설치 아님, 수동 설치 권장)

### 선택
- `syft`: SBOM 생성 (없으면 requirements.txt/package-lock.json 사용)

---

## 📦 설치 및 개발

### 소스에서 설치
```bash
git clone <repo>
cd vsh
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
pip install semgrep
```

### Docker 실행
```bash
cd docker
docker-compose up
```

---

## 🚧 알려진 제한사항 (v1.0)

- **Reachability**: 간단한 휴리스틱 기반 (taint 분석 미포함)
- **Semgrep 룰**: 데모 목적의 기본 룰만 포함 (확장 가능)
- **OSV API**: 네트워크 필수 (오프라인 미지원)
- **동적 분석**: 정적 분석만 지원

---

## 📚 다음 스텝 (v2.0+)

- [ ] FastMCP 서버 (Cursor/Claude 에이전트 연동)
- [ ] SonarQube 연동 (L3 분석)
- [ ] CI/CD 파이프라인 (GitHub Actions)
- [ ] KISA/금융보안원 RAG DB 통합 (근거 자동 인용)
- [ ] 고도화된 Reachability (Tree-sitter + taint 분석)
- [ ] 실시간 IDE 플러그인 (VS Code)

---

## 📞 문의 & 기여

- 이슈: [GitHub Issues](https://github.com/your-repo/issues)
- Pull Requests 환영합니다!

---

**Made with ❤️ by Vibe Security Team**

VSH v1.0.0 | 2026-02-20
