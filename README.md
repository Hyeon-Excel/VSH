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

## 📁 프로젝트 구조 상세 설명

```
vsh/
├── pyproject.toml                 # 프로젝트 설정 및 의존성
├── README.md                      # 이 파일
├── pytest.ini                     # 테스트 설정
├── vsh/                          # 메인 패키지
│   ├── __init__.py
│   ├── cli.py                     # 메인 CLI 진입점 (vsh 명령어)
│   ├── core/                      # 핵심 설정 및 모델
│   │   ├── __init__.py
│   │   ├── config.py              # VSHConfig: 프로젝트 경로, 언어, 출력 설정
│   │   ├── models.py              # 데이터 모델 (Finding, VulnRecord, PackageRecord, ScanResult)
│   │   └── utils.py               # 공용 유틸리티 (파일 읽기, 명령어 실행 등)
│   ├── engines/                   # 보안 엔진들 (L1 담당)
│   │   ├── __init__.py
│   │   ├── semgrep_engine.py      # Semgrep 실행 및 패턴 매칭
│   │   ├── registry_engine.py     # 패키지 존재성 검증 (환각/타이포스쿼팅)
│   │   ├── sbom_engine.py         # SBOM 생성 (syft 또는 fallback)
│   │   ├── osv_engine.py          # OSV API를 통한 취약점 조회
│   │   ├── reachability_engine.py # 간이 도달가능성 분석
│   │   ├── typosquatting_engine.py # 타이포스쿼팅 탐지 (L1 확장)
│   │   ├── schema_normalizer.py   # Finding → VulnRecord/PackageRecord 변환
│   │   ├── code_annotator.py      # 코드에 주석 삽입
│   │   └── report_engine.py       # Markdown 리포트 생성
│   ├── rules/                     # Semgrep 룰 정의
│   │   └── semgrep/
│   │       ├── python.yml         # Python 취약점 패턴
│   │       └── javascript.yml     # JavaScript/TypeScript 취약점 패턴
│   └── demo_targets/              # 데모용 취약 코드
│       ├── python_sqli.py         # SQL Injection 데모
│       ├── js_xss.js              # XSS 데모
│       └── python_pkg_hallucination.py # 패키지 환각 데모
├── modules/                       # 모듈러 스캐너 아키텍처
│   ├── __init__.py
│   └── scanner/
│       ├── __init__.py
│       ├── base_scanner.py        # BaseScanner 추상 클래스
│       └── vsh_l1_scanner.py      # VSHL1Scanner 구현체
├── pipeline/                      # 분석 파이프라인
│   ├── __init__.py
│   └── analysis_pipeline.py       # L1/L2/L3 파이프라인 조율
├── tests/                         # 단위/통합 테스트
│   ├── __init__.py
│   └── test_vsh_l1_scanner.py     # L1 스캐너 테스트
├── scripts/                       # 유틸리티 스크립트
│   └── install_semgrep.sh         # Semgrep 설치 스크립트
├── docker/                        # Docker 구성
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── ...
└── vsh_out/                       # 출력 디렉토리 (자동 생성)
    └── VSH_REPORT.md              # 생성된 리포트
```

### 🔍 각 모듈 상세 설명

#### Core 모듈 (`vsh/core/`)
- **`config.py`**: 프로젝트 설정 중앙화. `VSHConfig` 클래스로 프로젝트 루트, 언어, 출력 경로 등 관리
- **`models.py`**: 모든 데이터 구조 정의
  - `Finding`: 기본 탐지 결과
  - `VulnRecord`: 정규화된 취약점 레코드 (L1/L2/L3 공통)
  - `PackageRecord`: 정규화된 패키지 레코드
  - `ScanResult`: 전체 스캔 결과 통합
- **`utils.py`**: 파일 I/O, 명령어 실행, 언어 감지 등의 공용 함수

#### Engine 모듈 (`vsh/engines/`)
- **`semgrep_engine.py`**: Semgrep 실행 및 결과 파싱. Python/JS용 룰 자동 선택
- **`registry_engine.py`**: PyPI/npm API로 패키지 존재성 검증 + 타이포스쿼팅 탐지
- **`sbom_engine.py`**: syft로 SBOM 생성, 실패시 requirements.txt 파싱으로 fallback
- **`osv_engine.py`**: OSV.dev API로 알려진 취약점 조회
- **`reachability_engine.py`**: 파일 내에서 입력→취약함수 근접성 분석
- **`typosquatting_engine.py`**: Levenshtein 거리로 유사 패키지 탐지 (L1 확장)
- **`schema_normalizer.py`**: L1 결과를 VulnRecord/PackageRecord로 정규화
- **`code_annotator.py`**: 소스코드에 취약점 주석 삽입 (Python: #, JS: //)
- **`report_engine.py`**: Markdown 리포트 생성

#### Scanner 모듈 (`modules/scanner/`)
- **`base_scanner.py`**: `BaseScanner` 추상 클래스. 모든 스캐너의 인터페이스 정의
- **`vsh_l1_scanner.py`**: L1 스캐너 구현. 여러 엔진을 조율하고 결과를 통합

#### Pipeline 모듈 (`pipeline/`)
- **`analysis_pipeline.py`**: `AnalysisPipeline` 클래스. L1/L2/L3 레이어를 연결
  - `run_l1(scan_only=True)`: 탐지만 수행
  - `run_l1(scan_only=False, annotate=True)`: 탐지 + 코드 주석 삽입

---

## 🏗️ L2/L3 확장 가이드

### L2 Layer (Warm Path) - 설명/수정안/LLM 분석
L2는 L1의 결과를 받아서 더 깊이 있는 분석을 수행합니다.

#### L2 붙이기 쉽게 하는 방법:
1. **AnalysisPipeline 확장**:
```python
@dataclass
class AnalysisPipeline:
    scanner: BaseScanner
    analyzer: object | None = None  # L2 분석기
    reporter: object | None = None  # L3 리포터

    def run_l2(self, scan_result: ScanResult) -> ScanResult:
        """L2 분석 실행"""
        if self.analyzer and hasattr(self.analyzer, "analyze"):
            return self.analyzer.analyze(scan_result)
        return scan_result
```

2. **L2 Analyzer 인터페이스**:
```python
class BaseAnalyzer:
    def analyze(self, scan_result: ScanResult) -> ScanResult:
        """L1 결과를 분석해서 L2 정보 추가"""
        # scan_result.vuln_records에 설명, 수정안, LLM 분석 추가
        # 새로운 필드: explanation, fix_suggestion_detailed, llm_analysis
        pass
```

3. **L2가 추가할 정보**:
```python
# VulnRecord에 L2 확장 필드 추가
class VulnRecord(BaseModel):
    # L1 필드들...
    explanation: str | None = None          # L2: 왜 취약한지 설명
    fix_suggestion_detailed: str | None = None  # L2: 구체적인 수정안
    llm_analysis: dict | None = None        # L2: LLM 기반 추가 분석
    confidence_score: float | None = None   # L2: 신뢰도 점수
```

#### L2 구현 팁:
- **stateless 유지**: L1처럼 상태 저장하지 말고 입력→출력만
- **에러 처리**: LLM API 실패시에도 L1 결과는 유지
- **비용 최적화**: 모든 취약점에 LLM 호출하지 말고 중요도 기반 필터링
- **캐싱 고려**: 동일 코드 패턴에 대한 분석 결과 캐시

### L3 Layer (Cold Path) - PoC/최종 리포트/SonarQube 연동
L3는 실제 검증과 최종 산출물을 생성합니다.

#### L3 붙이기 쉽게 하는 방법:
1. **AnalysisPipeline 확장**:
```python
def run_l3(self, scan_result: ScanResult) -> ScanResult:
    """L3 최종 처리"""
    if self.reporter and hasattr(self.reporter, "generate"):
        return self.reporter.generate(scan_result)
    return scan_result
```

2. **L3 Reporter 인터페이스**:
```python
class BaseReporter:
    def generate(self, scan_result: ScanResult) -> ScanResult:
        """최종 리포트 생성 및 외부 시스템 연동"""
        # SonarQube 업로드, JIRA 티켓 생성, Slack 알림 등
        pass
```

3. **L3가 추가할 정보**:
```python
# ScanResult에 L3 확장 필드 추가
class ScanResult(BaseModel):
    # 기존 필드들...
    poc_results: list[dict] | None = None      # L3: 실제 PoC 실행 결과
    sonar_uploaded: bool = False               # L3: SonarQube 업로드 여부
    jira_ticket_url: str | None = None         # L3: 생성된 JIRA 티켓
    final_report_path: str | None = None       # L3: 최종 리포트 경로
```

#### L3 구현 팁:
- **격리 실행**: PoC는 샌드박스 환경에서 실행
- **외부 연동**: API 키, 인증 정보 안전하게 관리
- **에러 복원력**: 외부 시스템 실패시에도 로컬 리포트는 생성
- **형식 다양화**: Markdown, PDF, JSON 등 다양한 출력 형식 지원

---

## 📖 사용법 가이드

### 🚀 빠른 시작

#### 1. 설치
```bash
# 의존성 설치
pip install -e .

# Semgrep 설치 (선택사항, 없으면 패턴 fallback 사용)
./scripts/install_semgrep.sh
```

#### 2. 기본 스캔
```bash
# Python 프로젝트 스캔
vsh /path/to/python/project --lang python

# JavaScript 프로젝트 스캔
vsh /path/to/js/project --lang javascript

# 자동 언어 감지 (느림)
vsh /path/to/project
```

> **주의**: CLI는 소스 파일에 직접 주석을 달지 않습니다. 결과는
> `vsh_out/VSH_REPORT.md`에 보고되고, 터미널에 샘플 인라인 주석이 출력될 뿐입니다.
> 코드에 실제 주석을 삽입하려면 프로그래매틱 API를 사용하거나
> `annotate=True` 플래그를 `AnalysisPipeline`에 전달해야 합니다.

```python
# 예: 코드에 주석을 달고 파일로 저장하기
from pathlib import Path
from vsh.core.config import VSHConfig
from pipeline.analysis_pipeline import AnalysisPipeline
from modules.scanner.vsh_l1_scanner import VSHL1Scanner
from vsh.engines.code_annotator import write_annotated_files

cfg = VSHConfig(project_root=Path("./project"), out_dir=Path("vsh_out"), language="python")
scanner = VSHL1Scanner(cfg)
pipeline = AnalysisPipeline(scanner=scanner)
result = pipeline.run_l1(scan_only=False, annotate=True)
write_annotated_files(result.annotated_files, Path("annotated"))
```

#### 3. 고급 옵션
```bash
# SBOM 생성 생략 (빠른 스캔)
vsh /path/to/project --no-syft

# 출력 디렉토리 지정
vsh /path/to/project --out /custom/output/dir
```

### 💻 프로그래매틱 사용

#### 기본 스캔
```python
from pathlib import Path
from vsh.core.config import VSHConfig
from pipeline.analysis_pipeline import AnalysisPipeline
from modules.scanner.vsh_l1_scanner import VSHL1Scanner

# 설정
cfg = VSHConfig(
    project_root=Path("/path/to/project"),
    out_dir=Path("vsh_out"),
    language="python",  # "python" | "javascript"
    use_syft=True
)

# 파이프라인 생성 및 실행
pipeline = AnalysisPipeline(scanner=VSHL1Scanner(cfg))
result = pipeline.run_l1(scan_only=True)

# 결과 확인
print(f"취약점: {len(result.vuln_records)}개")
print(f"패키지: {len(result.package_records)}개")
```

#### 코드에 주석 삽입하기
```python
# 탐지 + 주석 삽입
result = pipeline.run_l1(scan_only=False, annotate=True)

# 주석 삽입된 파일들을 실제 파일로 저장
from vsh.engines.code_annotator import write_annotated_files

output_dir = Path("annotated_code")
written_files = write_annotated_files(result.annotated_files, output_dir)
print(f"주석 삽입된 파일들: {written_files}")
```

#### 리포트 생성하기
```python
from vsh.engines.report_engine import generate_markdown_report

# Markdown 리포트 생성
report_path = generate_markdown_report(result, cfg.out_dir)
print(f"리포트 생성됨: {report_path}")
```

### 🎨 출력 결과 구조

```json
{
  "scan_result": {
    "project": "my_project",
    "score": 75,
    "findings": [...],           // 원본 Finding 객체들
    "dep_vulns": [...],          // OSV 취약점 데이터
    "hallucinated_packages": [...], // 존재하지 않는 패키지들
    "typosquatting_packages": [...], // 타이포스쿼팅 패키지들
    "notes": ["layer=L1", "language=python"]
  },
  "vuln_records": [              // 정규화된 취약점들 (L1/L2/L3 공통)
    {
      "vuln_id": "VSH-20240308-001",
      "source": "L1",
      "detected_at": "2024-03-08T10:30:00Z",
      "file_path": "app.py",
      "line_number": 25,
      "vuln_type": "SQLI",
      "cwe_id": "CWE-89",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "reachability": true,
      "kisa_ref": "입력데이터 검증 및 표현 1항",
      "owasp_ref": "A03:2021",
      "fix_suggestion": "Use parameterized queries",
      "status": "pending",
      "action_at": null
    }
  ],
  "package_records": [           // 정규화된 패키지들
    {
      "package_id": "PKG-001",
      "source": "L1_OSV",
      "detected_at": "2024-03-08T10:30:00Z",
      "name": "requests",
      "version": "2.25.1",
      "ecosystem": "PyPI",
      "cve_id": "CVE-2023-12345",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "license": "Apache-2.0",
      "license_risk": false,
      "status": "upgrade_required",
      "fix_suggestion": "Upgrade to 2.28.0 or later"
    }
  ],
  "annotated_files": {           // 주석 삽입된 파일들 (선택적)
    "app.py": "...주석이 삽입된 코드 내용..."
  }
}
```

### 📋 주석 삽입 예시

#### Python 파일
```python
def search(cursor):
    user_input = request.args.get("q")
    # ⚠️ [VSH-L1] SQLI 탐지
    # Severity: CRITICAL
    # CWE: CWE-89
    # Reachability: true
    # KISA: 입력데이터 검증 및 표현 1항
    # OWASP: A03:2021
    # Fix: query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
```

#### JavaScript 파일
```javascript
function renderUserInput(input) {
    // ⚠️ [VSH-L1] XSS 탐지
    // Severity: HIGH
    // CWE: CWE-79
    // Reachability: true
    // KISA: 입력데이터 검증 및 표현 3항
    // OWASP: A03:2021
    // Fix: innerHTML → textContent 변경
    document.getElementById("output").innerHTML = input;
}
```

---

## ⚠️ 고급 경고 기능

### 함수별 세부 경고 (L1 확장 제안)

현재 L1은 **라이브러리 전체**를 위험하다고 경고하지만, 실제로는 **특정 함수만 위험**한 경우가 많습니다.

#### 현재 방식의 문제점:
```python
# 현재: 전체 라이브러리 경고
import xml.etree.ElementTree as ET  # ⚠️ 위험한 라이브러리!
root = ET.parse("file.xml")         # 안전한 사용
```

#### 함수별 세부 경고 (이미 구현됨)
```python
# L1 엔진은 특정 함수만 위험으로 경고합니다
import xml.etree.ElementTree as ET
root = ET.parse("file.xml")         # ✅ 안전
vulnerable = ET.fromstring(user_input)  # ⚠️ [VSH-L1] XXE 취약점
                                        # fromstring() 함수가 외부 엔티티를 처리할 수 있음
```

이 기능은 다음 방식으로 구현되어 있습니다:
1. **Semgrep 룰 확장**: 함수 호출별 위험 정보를 메타데이터에 포함
2. **패턴 fallback**: Semgrep 미사용 시에도 `_simple_pattern_scan`에서 동일 정보 생성
3. **스키마 정규화 & 주석**: `function_risk`/`safe_alternatives`가 결과와 주석에 표현

##### 적용된 대표 함수 사례:
- **XML 라이브러리**: `fromstring()` (XXE) vs `parse()` (안전)
- **Subprocess**: `run(shell=True)` 및 `os.system()` (명령어 주입)
- **Eval/Exec**: 임의 코드 실행 위험
- **Pickle**: `loads()` 역직렬화 공격

---

## 🌍 지원 언어

현재 VSH는 다음 언어를 지원합니다:

### ✅ 공식 지원
- **Python**: 완전 지원 (Semgrep 룰, 패키지 분석, SBOM)
- **JavaScript/TypeScript**: 완전 지원 (Semgrep 룰, npm 분석)

### 🚧 부분 지원 (확장 가능)
- **Java**: 기본적인 파일 구조 분석 (Semgrep 룰 확장 필요)
- **Go**: 기본적인 파일 구조 분석 (Semgrep 룰 확장 필요)
- **C/C++**: 제한적 지원 (복잡한 빌드 시스템 대응 필요)

### 🔧 새 언어 추가하기
```python
# 1. vsh/rules/semgrep/ 에 새 룰 파일 추가
# 2. vsh/engines/registry_engine.py 에 패키지 레지스트리 추가
# 3. vsh/core/utils.py 의 guess_language() 확장
# 4. 각 엔진에 언어별 처리 로직 추가
```

---

## 🧪 테스트 실행

```bash
# 전체 테스트
pytest

# 특정 테스트만
pytest tests/test_vsh_l1_scanner.py::test_typosquatting_detection

# 커버리지 확인
pytest --cov=vsh
```

---

## 🤝 기여 가이드

### 코드 스타일
- **Black** 포맷팅 사용
- **isort** 임포트 정렬
- **mypy** 타입 힌팅
- **pytest** 테스트 작성

### PR 전 체크리스트
- [ ] 테스트 통과 (`pytest`)
- [ ] 타입 체크 통과 (`mypy`)
- [ ] 포맷팅 완료 (`black`, `isort`)
- [ ] README 업데이트
- [ ] L1/L2/L3 책임 분리 유지

---

## 📄 라이선스

MIT License - 자유롭게 사용 및 수정 가능합니다.

---

## 🆘 문제 해결

### 자주 묻는 질문

**Q: Semgrep이 설치되지 않았어요**  
A: `./scripts/install_semgrep.sh` 실행하거나, `--no-semgrep` 옵션으로 패턴 fallback 사용

**Q: SBOM 생성이 실패해요**  
A: `--no-syft` 옵션으로 requirements.txt 기반 분석으로 fallback

**Q: 특정 언어가 지원되지 않아요**  
A: `vsh/rules/semgrep/`에 룰 추가하고 이슈로 요청해주세요

**Q: 메모리 사용량이 많아요**  
A: 큰 프로젝트는 `--no-sbom`으로 SBOM 생성 생략

---

*VSH - 실시간으로 더 안전한 코딩을 도와드립니다! 🛡️*
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
  --no-syft             # syft 비활성화 (fallback 사용)  --annotate            # 스캔 완료 후 주석 복사본 생성 (파일 수정 아님)
  --annotated-dir <dir> # 주석 복사본을 쓸 디렉토리 (기본: <out>/annotated)
```

`--annotate`를 주면 스캔과 동시에 코드(annotation) 결과를 `annotated_dir`
아래에 복사합니다. 원본 소스는 변경되지 않습니다.

```bash
# 스캔 + 주석 파일 생성
vsh myproj --lang python --annotate

# 주석을 다른 위치에 쓰기
vsh myproj --annotate --annotated-dir annotated_copy```

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

## 🧱 계층형 통합 구조 (L1/L2/L3 대응)

VSH는 계층형 파이프라인에 맞게 아키텍처 호환 L1 스캐너 어댑터를 제공합니다.

- `modules/scanner/base_scanner.py`: L1 스캐너 계약 인터페이스 (`scan() -> ScanResult`)
- `modules/scanner/vsh_l1_scanner.py`: VSH L1 구현체 (Semgrep + SBOM + OSV + 환각 패키지 감지 + Reachability)
- `pipeline/analysis_pipeline.py`: L1/L2/L3 경계를 분리한 오케스트레이션 진입점

### L1 통합 절차

1. `project_root`, `out_dir`, (선택) `language`를 포함한 `VSHConfig`를 구성합니다.
2. `VSHL1Scanner(cfg)` 인스턴스를 생성합니다.
3. `AnalysisPipeline(scanner=...)`에 스캐너를 주입합니다.
4. `pipeline.run_l1()`을 호출합니다. (L2/L3 구성요소가 있으면 `pipeline.run()` 사용)

이 구조를 통해 L1은 상태 비저장(stateless) + 탐지 전용 책임을 유지합니다.

- 리포트 생성 없음
- 파일 출력 없음
- CLI 출력 없음
- LLM 호출 없음

L2(설명/수정 제안)와 L3(리포팅/심화 스캔)는 파이프라인의 analyzer/reporter 인터페이스로 외부 결합할 수 있습니다.
