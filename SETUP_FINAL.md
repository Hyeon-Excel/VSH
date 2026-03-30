# VSH 최종 작동 가이드

## 🚀 한 줄 실행 (PowerShell)

```powershell
# 터미널에서 이 명령 실행
powershell -NoProfile -ExecutionPolicy Bypass -File "run_vsh_final.ps1"
```

## 📝 단계별 수동 실행 (위 한 줄이 안 되면)

### Step 1: Python 설정
```powershell
cd VSH_Project_MVP
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt
# 완료: [1/5] ✅
```

### Step 2: Node 설정
```powershell
cd ..\VSH_TEST\vsh_desktop
npm cache clean --force 2>&1 | Out-Null
npm install --legacy-peer-deps --no-audit --no-fund --loglevel=error 2>&1 | Out-Null
# 완료: [2/5] ✅
```

### Step 3: API 서버 (포트 3001)
**새 터미널 1**
```powershell
cd c:\VSH_TEST
python -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3001 --log-level warning
# 완료: [3/5] ✅ (실행 중 유지)
```

### Step 4: Vite 개발 서버 (포트 5174)
**새 터미널 2**
```powershell
cd c:\VSH_TEST\vsh_desktop
npm run dev
# 완료: [4/5] ✅ (실행 중 유지)
```

### Step 5: 브라우저 열기
**새 터미널 또는 수동**
```
http://localhost:5174
```

---

## ⚠️ 일반적인 문제와 해결

| 문제 | 해결 |
|------|------|
| `포트 3000/3001 이미 사용 중` | `netstat -ano \| findstr :3000` 후 taskkill /PID |
| `npm install 실패 (Electron)` | OneDrive → C:\VSH_TEST로 복사 (이미 됨) |
| `Vite 포트 5173 사용 중` | 자동으로 5174 할당됨 |
| `API 응답 없음` | 포트 3001 확인, 방화벽 확인 |

---

## 🎯 UI 사용법

### Dashboard 화면
- **Total Findings**: 전체 취약점
- **Critical/High/Medium/Low**: 심각도별 분류
- **Top Risky Files**: 위험도 높은 파일

### 스캔 방법
1. **Scan** 메뉴 클릭
2. 폴더 선택: `VSH_Project_MVP/tests/samples/vuln_project/`
3. **Scan** 버튼 클릭
4. 결과 대기 (L1: 200ms + L2: 3-5s)

---

## 📊 현재 상태

```
✅ Backend API: 포트 3001
✅ Frontend Vite: 포트 5174  
✅ Python 패키지: 설치됨
✅ Node 패키지: 설치됨 (C:\VSH_TEST)
✅ 샘플 취약점: 준비됨
```

---

## 🔗 URL

- Web UI: **http://localhost:5174**
- API Health: **http://127.0.0.1:3001/health**

---

마지막 업데이트: 2026-03-30
