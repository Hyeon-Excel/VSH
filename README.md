# VSH (Vibe Secure Hook)

Windows에서 **zip 압축 해제 후 바로 시연**할 수 있도록 실행 구조를 정리한 가이드입니다.

---

## 0) 권장 설치 위치 (중요)

- ✅ 권장: `C:\VSH` 같은 **OneDrive 바깥 경로**
- ⚠️ 비권장: `C:\Users\...\OneDrive\...`

이유: OneDrive 동기화 경로에서는 `npm install`/Electron 설치 시 `EBUSY`, `EPERM`이 자주 발생합니다.

---

## 1) 사전 설치 요구사항

- Python 3.12+
- Node.js 20+
- npm (Node 설치 시 포함)

확인:

```powershell
python --version
node --version
npm --version
```

---

## 2) zip 해제 후 가장 쉬운 실행 (기본 시연 루트)

1. zip 해제
2. 루트 폴더에서 `run_vsh.bat` 더블클릭

`run_vsh.bat` → `setup_and_run.ps1`가 자동으로 아래를 수행합니다.

- `VSH_Project_MVP` 경로 자동 인식
- `.venv` 생성
- `pip install -r requirements.txt`
- `vsh_desktop`의 `npm install`
- API 서버 실행 (`python -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3000`)
- Desktop 실행 (`npm run electron-dev`)

---

## 3) PowerShell 1-스크립트 실행

```powershell
.\setup_and_run.ps1
```

옵션:

```powershell
# 이미 설치가 끝났다면 설치 단계 건너뛰기
.\setup_and_run.ps1 -SkipInstall

# VS Code 확장까지 함께 설치/컴파일
.\setup_and_run.ps1 -RunVsCodeExtension
```

---

## 4) `.env` 설정 방법

```powershell
cd .\VSH_Project_MVP
copy .env.example .env
```

권장 값:

- `LLM_PROVIDER=gemini` (실 LLM 사용)
- `GOOGLE_API_KEY=...`
- `OPENAI_API_KEY=...` (OpenAI 사용할 때)
- `VITE_API_BASE_URL=http://127.0.0.1:3000`

키가 없으면 `mock` provider로도 기본 시연은 가능합니다.

---

## 5) 수동 실행 방법 (문제 해결용)

### API 수동 실행

```powershell
cd .\VSH_Project_MVP
.\.venv\Scripts\python.exe -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3000
```

> `main:app`가 아니라 **반드시** `vsh_api.main:app`를 사용하세요.

### Desktop 수동 실행

```powershell
cd .\VSH_Project_MVP\vsh_desktop
npm run electron-dev
```

### 브라우저 개발 확인

`npm run dev` 후 `http://localhost:5173` 접속 시, Electron 기능 없이도 기본 UI가 렌더링됩니다.

---

## 6) 기본 시연 순서

1. `run_vsh.bat` 실행
2. Desktop 실행 확인
3. Setup Wizard / Settings에서 API key, Syft 상태 확인
4. 취약 샘플 폴더(`cmd_injection.py`, `path.py`, `rce.py`, `secret.py`, `sqli.py` 포함)를 선택
5. `Scan Project` 클릭
6. Findings / Detail / Code Preview 확인

---

## 7) VS Code 확장 시연 루트 (선택)

기본 시연은 Desktop + API만으로 충분합니다.

확장 시연이 필요할 때만:

```powershell
cd .\VSH_Project_MVP\vsh_vscode
npm install
npm run compile
```

---

## 8) 최종 실행 관련 파일 트리

```text
VSH/
├─ run_vsh.bat
├─ setup_and_run.ps1
├─ README.md
└─ VSH_Project_MVP/
   ├─ requirements.txt
   ├─ .env.example
   ├─ config.py
   ├─ vsh_api/main.py
   ├─ repository/
   │  ├─ fix_repo.py
   │  ├─ knowledge_repo.py
   │  └─ log_repo.py
   └─ vsh_desktop/
      ├─ main.ts
      ├─ preload.ts
      └─ src/App.tsx
```
