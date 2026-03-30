## 최종 퇴고 README

```markdown
# VSH - Vibe Coding Secure Helper

> AI 코딩 환경 실시간 보안 취약점 탐지 시스템  
> 팀명: 분위기 지켜 | 팀장: 박혁규

---

## 프로젝트 개요

VSH는 개발자가 코드를 저장하는 순간 보안 취약점을 자동으로 탐지하고,  
LLM 기반 수정 제안과 KISA/OWASP 법적 근거를 함께 제공하는 MCP 서버입니다.

```

파일 저장 감지 → L1 (Hot Path) : 패턴 매칭 + AST 분석 → 즉시 탐지 → L2 (Warm Path) : LLM 심층 분석 + KISA/OWASP 근거 → L3 (Cold Path) : SonarQube SAST + SBOM + PoC Docker 검증 (백그라운드 병렬) → 보안 리포트 자동 생성 (reports/)

````

---

## 탐지 가능한 취약점

| CWE ID | 취약점 유형 | KISA 근거 | OWASP |
|--------|------------|-----------|-------|
| CWE-89 | SQL Injection | DB-01 | A03:2021 |
| CWE-78 | OS Command Injection | OS-01 | A03:2021 |
| CWE-829 | 취약한 외부 컴포넌트 (SBOM) | SW-8 | A06:2021 |
| CWE-798 | 하드코딩된 자격증명 | AM-01 | A07:2021 |

---

## 사전 요구사항

- Python 3.10 이상
- Docker Desktop (L3 SonarQube/PoC 실행용, 실행 중이어야 함)
- Git

---

## 설치 방법

### 1. 저장소 클론

```bash
git clone https://github.com/Hyeon-Excel/VSH.git
cd VSH
git checkout MVP-final
````

### 2. 의존성 설치

```bash
pip install -r requirements.txt
pip install watchdog chromadb fastmcp python-dotenv syft
```

### 3. 환경변수 설정

프로젝트 루트에 `.env` 파일을 생성하고 아래 내용을 입력하세요.  
**⚠️ `.env` 파일은 절대 Git에 커밋하지 마세요.**

```env
# LLM 설정
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here

# SonarCloud 설정
SONAR_TOKEN=your_sonar_token_here
SONAR_PROJECT_KEY=your_project_key_here
SONAR_ORG=your_organization_here
SONAR_URL=https://sonarcloud.io
```

**API 키 발급:**

- Gemini API: https://aistudio.google.com/app/apikey
- SonarCloud 토큰: https://sonarcloud.io → My Account → Security  
    → Generate Token → **Project Analysis Token** 선택

### 4. ChromaDB 초기화 (최초 1회 필수)

```bash
python init_chroma.py
```

> `init_chroma.py`가 없다면 아래 명령어로 직접 실행하세요:
> 
> ```bash
> python -c "
> import json, chromadb
> from chromadb.utils import embedding_functions
> DB_DIR = 'VSH-l1-l2-integration/VSH_Project_MVP/.chroma_db'
> KNOWLEDGE_JSON = 'VSH-l1-l2-integration/VSH_Project_MVP/mock_db/knowledge.json'
> ef = embedding_functions.DefaultEmbeddingFunction()
> client = chromadb.PersistentClient(path=DB_DIR)
> try: client.delete_collection('vsh_kisa_guide')
> except: pass
> col = client.create_collection('vsh_kisa_guide', embedding_function=ef)
> knowledge = json.load(open(KNOWLEDGE_JSON, encoding='utf-8'))
> col.add(
>     documents=[f\"{k['name']} {k['description']}\" for k in knowledge],
>     metadatas=[{'cwe': k['id'], 'source': 'KISA' if 'KISA' in k.get('reference','') else 'OWASP', 'kisa_article': k.get('reference',''), 'title': k['name']} for k in knowledge],
>     ids=[f\"{k['id']}_{i}\" for i, k in enumerate(knowledge)]
> )
> print(f'완료: {len(knowledge)}건 임베딩')
> "
> ```

---

## 실행 방법

### 시연 모드 (권장)

3초 후 `vuln_sample.py`를 자동으로 분석하고 종료합니다.

```bash
# Windows PowerShell
chcp 65001
$env:PYTHONIOENCODING="utf-8"
python vsh_demo.py
```

### 파일 감시 모드

`vuln_sample.py`를 저장(Ctrl+S)할 때마다 자동 분석합니다.

```bash
chcp 65001
$env:PYTHONIOENCODING="utf-8"
python vsh_watcher.py
```

### Claude Code CLI 연동

```bash
claude mcp add vsh --command "python" --args "mcp_server_unified.py"
```

---

## 리포트 예시

분석 완료 후 `reports/` 폴더에 자동 저장됩니다.

```
📊 종합 보안 점수 : 93 / 100
탐지된 취약점    : 4건 (HIGH 2, MEDIUM 1)
위험 라이브러리  : 17개

[HIGH] CWE-89 SQL Injection  ✅ PoC 검증 완료
  KISA  : KISA 시큐어코딩 DB-01
  OWASP : A03:2021 - Injection
  CVSS  : 9.8

📦 SBOM: requests 2.9.0 → CVE-2018-18074 외 16건
```

---

## 디렉토리 구조

```
VSH/
├── mcp_server_unified.py       # 통합 MCP 서버 (진입점)
├── vsh_demo.py                 # 시연용 자동 실행 스크립트
├── vsh_watcher.py              # 파일 감시 스크립트
├── vuln_sample.py              # 시연용 취약점 샘플 파일
├── sonar-project.properties    # SonarQube 설정
├── reports/                    # 생성된 보안 리포트 저장 위치
├── .env                        # 환경변수 (Git 제외)
├── VSH-l1-l2-integration/      # L1/L2 파이프라인 (팀 공통)
│   └── VSH_Project_MVP/
│       ├── layer1/             # 패턴 매칭 + AST 스캐너
│       ├── layer2/             # LLM 분석기 + ChromaDB RAG
│       └── mock_db/            # KISA/CWE 지식베이스
└── l3-dev/                     # L3 Cold Path (Lucas 담당)
    └── l3/
        ├── pipeline.py         # L3 오케스트레이터 (수정 금지)
        ├── providers/
        │   ├── sonarqube/      # SonarQube SAST
        │   ├── sbom/           # SBOM (syft + OSV API)
        │   └── poc/            # PoC Docker 샌드박스
        └── normalizer.py       # CWE 메타 + ChromaDB RAG 연동
```

---

## 기술 스택

|분류|기술|
|---|---|
|언어|Python 3.13|
|LLM|Google Gemini API|
|MCP|FastMCP|
|SAST|SonarCloud (프리티어)|
|SBOM|syft + OSV API|
|PoC 검증|Docker 샌드박스|
|RAG|ChromaDB + all-MiniLM-L6-v2|
|파일 감시|watchdog|

---

## 트러블슈팅

**Q. L3 SonarQube 스캔이 실패해요**  
→ Docker Desktop이 실행 중인지 확인하세요  
→ `.env`의 `SONAR_TOKEN` 타입이 **Project Analysis Token**인지 확인하세요  
→ SonarCloud → Administration → Analysis Method → **Manually** 선택 확인

**Q. ChromaDB 관련 오류가 발생해요**  
→ `python init_chroma.py`를 다시 실행하세요  
→ `.chroma_db` 폴더가 없으면 ChromaDB 초기화가 필요합니다

**Q. KISA 근거가 N/A로 나와요**  
→ ChromaDB 초기화가 완료됐는지 확인하세요  
→ `VSH-l1-l2-integration/VSH_Project_MVP/.chroma_db` 폴더가 존재해야 합니다

---

## 라이선스

본 프로젝트는 학술/연구 목적으로 개발되었습니다.
