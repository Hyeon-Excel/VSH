# VSH (Vibe Secure Hook)

zip을 받아 바로 시연 가능한 **보안 스캔 데모 패키지**를 목표로 정리한 실행 가이드입니다.

## 1) 압축 해제 후 바로 실행 (Windows 권장)

> **가장 쉬운 방법:** 압축 해제 후 루트에서 `run_vsh.bat` 더블클릭

`run_vsh.bat`는 내부적으로 `setup_and_run.ps1`를 호출하여 아래를 자동 수행합니다.

1. `VSH_Project_MVP` 경로 자동 진입
2. `.venv` 생성
3. `pip install -r requirements.txt`
4. `vsh_desktop`의 `npm install`
5. FastAPI 서버 실행 (`python -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3000`)
6. Electron Desktop 실행

### 수동 PowerShell 실행

```powershell
# 저장소 루트 기준
.\setup_and_run.ps1
```

옵션:

```powershell
# 의존성 설치 생략 (이미 설치된 경우)
.\setup_and_run.ps1 -SkipInstall

# VS Code 확장까지 설치/컴파일
.\setup_and_run.ps1 -RunVsCodeExtension
```

---

## 2) 왜 구조를 이렇게 바꿨는가

기존에는 `VSH_Project_MVP/` 하위로 직접 들어가 여러 명령을 순차 수동 실행해야 했습니다.  
이제는 **루트 실행 엔트리포인트(`run_vsh.bat`, `setup_and_run.ps1`)를 단일화**해서,
- 경로 혼동 방지
- Python/NPM 설치 순서 자동화
- API 선실행 보장
- Desktop 즉시 연결
을 달성합니다.

---

## 3) 프로젝트 트리 (실행 관련 핵심)

```text
VSH/
├─ run_vsh.bat                  # Windows 원클릭 실행
├─ setup_and_run.ps1            # Windows 통합 설치/실행 스크립트
├─ README.md
└─ VSH_Project_MVP/
   ├─ requirements.txt
   ├─ .env.example
   ├─ vsh_api/
   │  └─ main.py
   ├─ vsh_desktop/
   │  ├─ main.ts
   │  └─ src/App.tsx
   └─ vsh_vscode/
```

---

## 4) API 키 / .env 설정

`VSH_Project_MVP/.env.example`를 `.env`로 복사 후 값 입력:

```bash
cd VSH_Project_MVP
cp .env.example .env
```

핵심 변수:

- `LLM_PROVIDER=mock|gemini|openai`
- `GOOGLE_API_KEY=` (Gemini 권장 기본 키 이름)
- `GEMINI_API_KEY=` (하위 호환)
- `OPENAI_API_KEY=`

API 키가 없으면:
- `mock` provider는 동작
- 실 LLM(`gemini`, `openai`)은 Settings/Setup Wizard에서 연결 실패 메시지 표시

---

## 5) Syft 설치 여부

- Desktop `Settings > Analysis Tools > Syft 재검사`로 확인
- 또는 API `POST /settings/check-syft` 호출
- Syft가 없어도 코드 스캔은 가능하지만, SBOM 관련 기능 정확도/범위가 제한될 수 있습니다.

---

## 6) 첫 사용자 시연 순서 (권장)

1. zip 압축 해제
2. 루트에서 `run_vsh.bat` 실행
3. Desktop 최초 실행 시 Setup Wizard 완료
   - Provider 선택
   - API Key 입력 (필요 시)
   - Syft 확인
4. `vuln_project` 폴더 선택
5. `Scan Project` 클릭
6. Findings / Detail / Code Preview 확인

---

## 7) VS Code 확장 (선택 기능)

기본 시연에는 Desktop + API만으로 충분합니다.  
VS Code 확장은 선택으로 분리되어 있으며, 기본 실행 스크립트에서 강제 빌드하지 않습니다.

필요 시:

```bash
cd VSH_Project_MVP/vsh_vscode
npm install
npm run compile
```

또는 PowerShell:

```powershell
.\setup_and_run.ps1 -RunVsCodeExtension
```

---

## 8) 문제 해결

### API 오프라인 배너가 보일 때
- `run_vsh.bat`로 실행했는지 확인
- `VSH_Project_MVP/.vsh_api.log` 확인
- 포트 충돌 시 3000 포트를 점유한 프로세스 종료 후 재실행

### Python 모듈 에러 (`google.genai` 등)
- 반드시 `.venv` 기반으로 `pip install -r requirements.txt` 수행
- `.env`에 `GOOGLE_API_KEY` 또는 `GEMINI_API_KEY` 설정 확인

### 경로에 공백/한글이 있는 경우
- 본 스크립트는 스크립트 위치 기준 절대경로를 사용하므로 PowerShell/CMD 수동 `cd` 오입력 문제를 줄입니다.

