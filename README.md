# 🛡️ VSH v1.0 – 바이브 시큐어 헬퍼

**VSH (Vibe Secure Helper)**는 정적 코드와 의존성 보안을 빠르게 진단하기 위한
경량 계층형 AppSec 스캐너입니다. 패턴 기반 분석, 공급망 검사, 인라인
주석을 결합해 개발자가 취약점을 신속하게 찾아 수정할 수 있도록 도와줍니다.

---

## 🎯 주요 기능 (L1 핫 패스)

- **Semgrep 기반 코드 패턴 탐지**: SQL 인젝션, XSS, 명령어 삽입 등.
  Semgrep이 없으면 간단한 휴리스틱(패턴 fallback)을 사용.
- **함수 단위 위험 경고**: 위험한 메서드만 경고합니다.
  예: `ET.fromstring()` vs `ET.parse()`, `eval()`,
  `subprocess.run(shell=True)`, `pickle.loads()`, `innerHTML` 할당.
- **의존성 목록 및 OSV 조회**: `syft` SBOM 또는 requirements/lock 파일 파싱.
- **패키지 환각·타이포스쿼팅**: PyPI/npm 레지스트리에서 불러온 패키지 검증.
- **간단한 도달 가능성(Reachability)**: 사용자 입력과 싱크 간 텍스트 근접성.
- **선택적 코드 주석 복사본 생성**: 취약점 코멘트를 삽입한 사본을 만듭니다.
- **Markdown 리포트 출력**: 취약점, 의존성, 환각 결과를 읽기 쉬운 요약으로 생성.

> 🔥 L1은 빠르고(~0.3‑1.0 초) 상태를 보존하지 않습니다. L2/L3는
> `AnalysisPipeline` API를 통해 설명, LLM 분석, PoC, 외부 연동 등을 추가
>할 수 있습니다.

---

## 📁 저장소 구조

```
vsh/                 # 메인 패키지
  core/              # 설정, 모델, 유틸리티
  engines/           # Semgrep, OSV, SBOM 등 엔진
  rules/semgrep/     # Python/JS Semgrep 룰
  demo_targets/      # 데모 취약 코드
modules/scanner/     # 스캐너 인터페이스 + VSHL1Scanner
pipeline/            # AnalysisPipeline (L1/L2/L3 오케스트레이션)
tests/               # pytest 테스트
scripts/             # 유틸리티 스크립트
docker/              # Docker 구성
README.md            # 현재 파일
```

---

## 🚀 빠른 시작

### 1. 설치

```bash
pip install -e .                  # 가상환경에 설치
./scripts/install_semgrep.sh      # 선택사항: Semgrep 설치
```

### 2. CLI 스캔

```bash
# Python 프로젝트
vsh /경로/프로젝트 --lang python

# JavaScript/TypeScript 프로젝트
vsh /경로/프로젝트 --lang javascript
```

요약, 샘플 인라인 주석이 출력되며 `vsh_out/VSH_REPORT.md`가 생성됩니다.

#### 주석 복사본 생성
CLI는 기본적으로 소스를 수정하지 않습니다. 사본을 만들려면:

```bash
vsh /경로/프로젝트 --annotate                # vsh_out/annotated에 저장
vsh /경로/프로젝트 --annotate --annotated-dir 복사_디렉토리
```

(복사본만 생성되며 원본은 변경되지 않습니다.)

---

## 💻 프로그래매틱 API

```python
from pathlib import Path
from vsh.core.config import VSHConfig
from pipeline.analysis_pipeline import AnalysisPipeline
from modules.scanner.vsh_l1_scanner import VSHL1Scanner
from vsh.engines.code_annotator import write_annotated_files

cfg = VSHConfig(project_root=Path("./project"), out_dir=Path("vsh_out"), language="python")
scanner = VSHL1Scanner(cfg)
pipeline = AnalysisPipeline(scanner=scanner)

# 스캔만
result = pipeline.run_l1(scan_only=True)

# 스캔 + 주석 복사본 생성
result = pipeline.run_l1(scan_only=False, annotate=True)
write_annotated_files(result.annotated_files, Path("annotated"))
```

`ScanResult`에는 `findings`, `vuln_records`, `package_records`, 그리고
(선택적으로) `annotated_files`가 포함됩니다.

---

## 🛠 CLI 옵션

```bash
vsh <project_path> [옵션]

--out <dir>           # 출력 디렉토리 (기본값: vsh_out)
--lang <lang>         # python|javascript (생략 시 자동 감지)
--no-syft             # syft SBOM 생성 비활성화
--annotate            # 주석 복사본을 생성
--annotated-dir <dir> # 주석 복사본을 쓸 디렉토리
```

예:
```bash
vsh myapp --lang python --annotate --annotated-dir annotated_copy
```

---

## 🧪 테스트 및 개발

```bash
pytest                     # 전체 테스트 실행
pytest tests/test_vsh_l1_scanner.py::test_typosquatting_detection
```

커밋 전 `black`, `isort`, `mypy`를 실행하세요.

---

## 🌍 언어 지원

- ✅ **Python** – 완전 지원 (룰, SBOM, 의존성 검사, 주석)
- ✅ **JavaScript/TypeScript** – 완전 지원
- 🚧 **Java, Go, C/C++** – 부분 지원; 룰과 레지스트리 로직 추가로 확장 가능.

---

## ⚠️ 주요 기능

### 함수 단위 위험 경고
라이브러리 전체를 경고하지 않고 위험한 함수 호출만 알려줍니다. 예:

```python
import xml.etree.ElementTree as ET
ET.parse("file.xml")          # 안전
ET.fromstring(user_input)       # ⚠️ XXE 위험 – ET.parse()/defusedxml 사용
```

이 기능은 Semgrep과 fallback 패턴 양쪽 모두에서 메타데이터를
생성하며 결과와 주석에 반영됩니다.

### 의존성 및 공급망 검사
- `syft` 또는 requirements/lock 파일로 SBOM 생성
- OSV API를 통해 알려진 CVE 조회
- 레벤슈타인 유사도로 타이포스쿼팅 탐지

### 도달 가능성
간단한 휴리스틱: 같은 파일 내 사용자 입력과 싱크 간 텍스트 근접 여부.

---

## 🏗 L2/L3 확장

`AnalysisPipeline`은 레이어를 분리하여 분석기(L2) 또는 리포터(L3)를
스캔 결과에 쉽게 결합할 수 있도록 합니다. 인터페이스는
`pipeline/analysis_pipeline.py`에 주석으로 설명되어 있습니다.

---

## 🤝 기여 안내

- 테스트가 통과해야 합니다 (`pytest`).
- `black`, `isort`, `mypy`를 실행하세요.
- 기능 추가 시 README를 갱신하세요.
- L1은 상태 비저장과 탐지에만 집중해야 합니다.

---

## 📄 라이선스

MIT – 자유롭게 사용 및 수정 가능합니다.

---

*VSH v1.0 – Vibe Security 팀이 ❤️를 담아 제작* 

