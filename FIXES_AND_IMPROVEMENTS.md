# VSH MVP - Integration & Fix Report
## 목표: "구성요소 모음"에서 "실제로 시연 가능한 제품형 MVP"로 전환

---

## 1. 현재 문제 진단 (Problem Diagnosis)

### 1.1 Watch API와 Watcher 구현 불일치 ❌ → ✅ 해결됨

**문제점:**
- `vsh_api/main.py` `/watch/start` endpoint에서 `for events in watcher:` 시도
- ProjectWatcher 클래스는 iterator protocol를 구현하지 않음
- `stop()` 메서드 없음
- poll_once() 결과 형식과 endpoint 기대값 불일치

**해결책:**
- ProjectWatcher를 완전히 재설계하여 thread-safe한 lifecycle 구현
- `start()`, `stop()`, `is_running()`, `get_last_results()` 메서드 추가
- threading.Lock과 threading.Event 사용하여 안전한 동시성 처리
- debounce 처리로 파일 저장 시 과도한 중복 분석 방지

**수정 파일:** `VSH_Project_MVP/vsh_runtime/watcher.py` (전체 재작성)

---

### 1.2 Watch → Analyze → Store → UI 반영 경로 ❌ → ✅ 해결됨

**문제점:**
- 파일 변경 감지만 하고 실제 결과 저장 및 UI 반영 로직 부재
- endpoint에서 watcher 결과를 제대로 처리할 방법이 없음

**해결책:**
- `/watch/start`에서 백그라운드 결과 처리 스레드 추가
- watcher의 `get_last_results()`를 주기적으로 폴링
- 각 분석 결과를 자동으로 `.vsh/diagnostics.json`과 `.vsh/report.json`에 저장
- 10Hz 업데이트 간격으로 UI가 최신 결과를 빠르게 읽을 수 있게 설정

**수정 파일:** `VSH_Project_MVP/vsh_api/main.py` (/watch/start, /watch/stop 대폭 개선)

---

### 1.3 Annotation API 없음 ❌ → ✅ 완성됨

**문제점:**
- `/annotate/file`, `/annotate/project` endpoint 전혀 없음
- 사용자가 주석이 달린 소스 코드 사본을 생성할 방법이 없음
- code_annotator.py는 존재했으나 runtime 엔진에 통합되지 않음

**해결책:**
1. **VshRuntimeEngine에 annotation 메서드 추가:**
   - `annotate_file(file_path, in_place=False)` 메서드
   - `annotate_project(project_path, in_place=False)` 메서드
   - Vulnerability 객체로 변환하여 layer1의 annotate_files() 함수 활용
   - 결과를 `.vsh/annotated/` 디렉터리에 저장 또는 in-place 수정

2. **API 엔드포인트 추가:**
   - `POST /annotate/file` - 단일 파일 주석 처리
   - `POST /annotate/project` - 프로젝트 전체 주석 처리
   - `in_place=false`일 때 안전하게 복사본 생성

**수정 파일:**
- `VSH_Project_MVP/vsh_runtime/engine.py` (annotate_file, annotate_project 메서드 추가)
- `VSH_Project_MVP/vsh_api/main.py` (AnnotateRequest, /annotate 엔드포인트 추가)

---

### 1.4 L1 → L2 → L3 통합 및 Finding 머지 ✅ 이미 완성됨

**상황:**
- engine의 `_analyze_target()` 메서드에서 L1 → L2 → L3 순서대로 처리
- L2 reasoning을 받아 각 vuln_record에 `reasoning_verdict` 병합
- L3 validation 결과를 각 vuln에 추가
- `normalize_response()` 함수에서 최종 결과 형식화

**확인된 사항:**
- L2 confidence, reasoning verdict ✓
- L3 attack scenario, exploit_possible, confidence ✓
- finding에 모든 필드 포함됨 ✓

**이미 구현되어 있으므로 수정 불필요**

---

### 1.5 실행 스크립트 ✅ 이미 완성됨

- `run_vsh.bat` - Windows batch 진입점 (존재함)
- `setup_and_run.ps1` - PowerShell 메인 스크립트 (존재함)

**스크립트 역할:**
1. Python 3.12+, Node.js 20+ 요구사항 확인
2. `.venv` 생성 및 python dependencies 설치
3. vsh_desktop npm install
4. FastAPI 서버 시작 (포트 3000)
5. Desktop Electron 앱 시작

수정 불필요

---

## 2. 수정한 파일 목록 및 변경점

### 2.1 vsh_runtime/watcher.py ⭐ 완전 재작성

**변경사항:**
- ProjectWatcher 클래스를 thread-safe로 완전 재설계
- `__init__`: 기본 속성 추가 (_stop_event, _thread, _lock, _last_results)
- `_watch_thread_loop()`: 백그라운드 감시 루프 구현
- `start()`: 스레드 안전한 시작 (중복 실행 방지)
- `stop()`: graceful shutdown with timeout (2초)
- `is_running()`: 상태 확인
- `get_last_results()`: 스레드 안전한 결과 조회
- `watch_forever()`: CLI 모드용 blocking 감시
- Error handling: FileNotFoundError, OSError 처리
- Debounce: 파일당 마지막 스캔 시간 추적

**핵심 개선점:**
```python
# 이전 (작동 안 함):
for events in watcher:  # <- watcher는 iterable이 아님

# 개선 후:
watcher.start()  # <- 스레드 안전한 시작
results = watcher.get_last_results()  # <- 결과 수집
watcher.stop()  # <- graceful shutdown
```

**파일 라인 수:** ~130 줄 (기존 50 줄에서 확장)

---

### 2.2 vsh_api/main.py ⭐ 세 가지 주요 개선

#### 2.2.1 Import 추가 (Line 7)
```python
import time
```

#### 2.2.2 AnnotateRequest 모델 추가 (After WatchRequest)
```python
class AnnotateRequest(BaseModel):
    path: str
    in_place: bool = False
```

#### 2.2.3 /watch/start 및 /watch/stop 완전 재작성 (Line 235-289)

**이전 문제:**
- Watcher를 iterable로 취급 (실제로 아님)
- 결과 처리 로직 없음
- 에러 처리 없음

**개선:**
- Watcher lifecycle 제대로 호출
- 백그라운드 스레드에서 결과 수집 및 저장
- `/watch/status` 엔드포인트 추가

#### 2.2.4 /annotate/file 및 /annotate/project 엔드포인트 추가 (Line 148-195)

**기능:**
- 단일 파일 주석 처리
- 프로젝트 전체 주석 처리
- 원본 보존 또는 in-place 수정 선택
- 상세한 응답 반환 (생성된 파일 경로, issue 카운트 등)

---

### 2.3 vsh_runtime/engine.py ⭐ 주석 기능 통합

#### 2.3.1 Import 추가 (Lines 6-7)
```python
from layer1.common import annotate_files
from models.vulnerability import Vulnerability
```

#### 2.3.2 annotate_file() 메서드 추가 (Line 125-186)

**기능:**
1. 파일을 분석
2. vuln_records를 Vulnerability 객체로 변환
3. layer1.common.annotate_files() 호출
4. 결과를 `.vsh/annotated/<filename>` 또는 원본에 저장
5. 생성된 파일 경로 반환

**에러 처리:**
- FileNotFoundError
- Vulnerability 객체 생성 실패 시 warning (분석은 계속)
- 모든 예외를 호출자에게 전파

#### 2.3.3 annotate_project() 메서드 추가 (Line 188-254)

**기능:**
1. 프로젝트 분석
2. 모든 vuln을 Vulnerability 객체로 변환
3. 주석 처리
4. 디렉터리 구조 유지하면서 `.vsh/annotated/` 아래에 저장
5. 상세 결과 반환 (files_annotated, total_issues 등)

---

### 2.4 test_vsh_mvp.py ✨ 신규 작성

**목적:** VSH 시스템의 모든 핵심 기능 검증

**테스트 케이스:**
1. **API Health Check** - 서버 연결 확인
2. **File Scan** - 단일 파일 분석 (findings 검증)
3. **Project Scan** - 폴더 전체 분석
4. **Watch Mode** - start/stop 동작 및 상태 확인
5. **Annotation** - 주석 파일 생성 및 저장 확인
6. **Diagnostics Saving** - .vsh 디렉터리에 결과 저장 확인

**사용법:**
```bash
# 기본 테스트 (기본 test file/directory 자동 선택)
python test_vsh_mvp.py

# 특정 파일 테스트
python test_vsh_mvp.py --test-file C:\path\to\file.py

# 특정 디렉터리 테스트
python test_vsh_mvp.py --test-dir C:\path\to\project

# 다른 API 주소 사용
python test_vsh_mvp.py --api-base http://192.168.1.100:3000
```

**출력:**
- ✓ PASS / ✗ FAIL 표시
- 테스트 요약 (run, passed, failed)
- 상세 로그

---

## 3. 실행 방법 (Windows 기준)

### 3.1 가장 간단한 방법 (권장)

1. **프로젝트 위치:** `C:\VSH` (OneDrive 바깥)로 압축 해제
2. **관리자 권한으로 터미널 열기**
3. **다음 명령 실행:**
   ```cmd
   cd C:\VSH
   run_vsh.bat
   ```
4. **자동으로 다음이 수행됨:**
   - Python .venv 생성
   - pip install -r requirements.txt
   - npm install
   - FastAPI 서버 시작 (http://127.0.0.1:3000)
   - Desktop Electron 앱 시작

---

### 3.2 PowerShell로 직접 실행

```powershell
cd C:\VSH
.\setup_and_run.ps1
```

**옵션:**
```powershell
# 설치 단계 건너뛰기 (이미 설치됨)
.\setup_and_run.ps1 -SkipInstall

# VS Code extension도 함께 빌드
.\setup_and_run.ps1 -RunVsCodeExtension
```

---

### 3.3 수동 실행 (개발용)

```powershell
# 프로젝트 경로로 이동
cd C:\VSH\VSH_Project_MVP

# 가상환경 있으면 활성화
.\.venv\Scripts\Activate.ps1

# API 서버 시작 (터미널 1)
python -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3000

# Desktop 앱 시작 (터미널 2)
cd vsh_desktop
npm run electron-dev
```

---

## 4. 테스트 방법 (End-to-End 검증)

### 시나리오 1: 단일 파일 스캔

```bash
# API 서버가 실행 중인 상태에서
python test_vsh_mvp.py --test-file "C:\VSH\VSH_Project_MVP\tests\fixtures\python_multi_bad.py"
```

**검증 항목:**
- ✅ `/scan/file` 엔드포인트 응답 (4xx/5xx 아님)
- ✅ `findings` 배열 포함 (설령 빈 배열이어도 OK)
- ✅ `summary.total` 존재
- ✅ `.vsh/diagnostics.json` 생성
- ✅ `.vsh/report.json` 생성

---

### 시나리오 2: 프로젝트 전체 스캔

```bash
python test_vsh_mvp.py --test-dir "C:\VSH\VSH_Project_MVP\tests\fixtures"
```

**검증 항목:**
- ✅ `/scan/project` 응답 정상 (30초 타임아웃 이내)
- ✅ 여러 파일 스캔 시 모두 findings 수집
- ✅ `summary.top_risky_files` 상위 5개 반환
- ✅ `.vsh/diagnostics.json` 프로젝트 레벨 저장

---

### 시나리오 3: Watch Mode 저장 시 자동 재분석

```bash
# 터미널 1: API 서버 실행
python -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3000

# 터미널 2: Test 실행
python test_vsh_mvp.py --test-file "test_file.py"

# Step 1: Watch 시작
POST http://127.0.0.1:3000/watch/start
{"path": "C:\\path\\to\\test_file.py"}

# Step 2: 파일 편집 → 저장
# (test_file.py를 에디터에서 수정하고 저장)

# Step 3: 잠시 대기 (debounce 시간 2초)
# Step 4: .vsh/diagnostics.json의 타임스탐프 확인
#        파일 저장 시간보다 최신이면 성공

# Step 5: Watch 중지
POST http://127.0.0.1:3000/watch/stop
{"path": "C:\\path\\to\\test_file.py"}
```

**검증 항목:**
- ✅ `/watch/status`에 watched_paths 포함
- ✅ 파일 저장 후 1-2초 내 진단 갱신
- ✅ 중복 분석 안 일어남 (debounce working)
- ✅ watch stop 후 더 이상 업데이트 없음

---

### 시나리오 4: Annotation 파일 생성

```bash
# 단일 파일 주석 처리 (복사본 생성)
curl -X POST http://127.0.0.1:3000/annotate/file \
  -H "Content-Type: application/json" \
  -d '{"path": "C:\\path\\to\\file.py", "in_place": false}'

# 응답 예시:
{
  "status": "success",
  "file": "C:\\path\\to\\file.py",
  "in_place": false,
  "annotated_files": {
    "C:\\path\\to\\file.py": "C:\\path\\to\\.vsh\\annotated\\file.py"
  },
  "total_issues": 3,
  "message": "Generated annotated version with 3 issue(s) marked"
}

# 프로젝트 전체 주석 처리
curl -X POST http://127.0.0.1:3000/annotate/project \
  -H "Content-Type: application/json" \
  -d '{"path": "C:\\path\\to\\project", "in_place": false}'
```

**검증 항목:**
- ✅ 응답 status = "success"
- ✅ `annotated_files` dict에 original → annotated 매핑
- ✅ annotated 파일이 실제로 존재
- ✅ 파일 내용에 주석 포함 (예: "# ⚠️ [VSH-L1]")
- ✅ in_place=true 사용 시 원본 수정

---

### 시나리오 5: Desktop GUI 연결 확인

```bash
# Desktop 앱 실행 상태에서:
1. "Scan File" 버튼 → 파일 선택 → 분석 결과 표시 확인
2. "Scan Project" 버튼 → 폴더 선택 → 분석 결과 표시 확인
3. "Watch Mode" 토글 → ON 상태에서 파일 저장 → 진단 자동 갱신 확인
4. 설정에서 LLM Provider 변경 하면 "Test Connection" 작동 확인
```

---

### 시나리오 6: VS Code Extension 저장 시 진단

```bash
# 프로젝트를 VS Code에서 열기
# Command Palette (Ctrl+Shift+P): "VSH: Enable"
# 파일 저장 → 진단 창에 findings 표시 확인
```

---

## 5. 핵심 변경 요약

| 항목 | 이전 상태 | 개선 후 | 파일 |
|-----|---------|--------|------|
| Watch lifecycle | ❌ Iterator 없음, stop() 없음 | ✅ Thread-safe, 완전한 lifecycle | watcher.py |
| Watch → Result Save | ❌ 결과 저장 로직 없음 | ✅ 백그라운드 스레드에서 자동 저장 | main.py |
| Annotation API | ❌ 엔드포인트 없음 | ✅ /annotate/file, /annotate/project | main.py, engine.py |
| L1→L2→L3 통합 | ✅ 이미 구현됨 | ✅ 유지 | engine.py |
| 실행 스크립트 | ✅ 이미 있음 | ✅ 유지 | run_vsh.bat, *.ps1 |
| 테스트 자동화 | ❌ 없음 | ✅ 포괄적 테스트 스크립트 | test_vsh_mvp.py |

---

## 6. 남은 이슈 및 제한사항

### 6.1 알려진 제한사항

1. **OneDrive 경로 문제**
   - npm/Electron이 OneDrive 폴더에서 EBUSY, EPERM 에러 발생 가능
   - **해결:** `C:\VSH` 같은 OneDrive 바깥 경로 사용 권장

2. **LLM Provider 모드**
   - 현재 기본값: `mock` (실제 LLM 호출 안 함)
   - 실제 사용하려면 `.env`에 `GOOGLE_API_KEY` 또는 `OPENAI_API_KEY` 설정 필요
   - Mock 모드에서도 L1 기본 스캔은 정상 작동

3. **Syft SBOM 스캔 (선택사항)**
   - Syft 미설치 시 SBOM 스캔 단계 스킵
   - 보안 스캔은 정상 작동

4. **Watch Mode 파일 제한**
   - 추적 대상: `.py`, `.js`, `.ts`, `.jsx`, `.tsx`만 감시
   - 다른 확장자 추가 원할 시 watcher.py의 `_iter_files()` 수정

5. **Annotation에서 object/dict 혼용**
   - Vulnerability 객체 생성 실패 시 경고 출력 (분석은 계속)
   - 모든 최종 결과는 dict 형식으로 통일

6. **Desktop GUI vs VSCode Extension 동기화**
   - 현재 각각 독립적으로 작동
   - 동일 프로젝트를 양쪽에서 watch하면 중복 분석 가능 (성능 이슈, 정확성은 OK)

---

### 6.2 향후 개선 아이디어 (Scope 외)

1. **WebSocket 기반 실시간 업데이트** (현재: polling 기반)
2. **Annotation 버전 관리** (생성 시간, 이전 버전 비교)
3. **CI/CD 통합** (GitHub Actions 등)
4. **성능 최적화** (캐싱, 증분 분석)
5. **멀티 프로젝트 관리** (여러 프로젝트 동시 감시)

---

## 7. 최종 체크리스트

완성도 자가 진단:

- [x] Watch API 정상 작동
- [x] Watch/Analyze/Save/UI 전체 경로 통합
- [x] Annotation API 완성
- [x] L1→L2→L3 통합 검증
- [x] 실행 스크립트 확인
- [x] 포괄적 테스트 스크립트 작성
- [x] 문서화 완료
- [x] Windows 호환성 확인

## 8. 실행 체크리스트

### 첫 시작 전 확인

```
[ ] Python 3.12+ 설치 확인: python --version
[ ] Node.js 20+ 설치 확인: node --version
[ ] npm 설치 확인: npm --version
[ ] 프로젝트를 C:\VSH (OneDrive 바깥)로 압축 해제
[ ] .env 파일 생성 (또는 기본값 사용 가능)
```

### 실행 명령

```
cd C:\VSH
run_vsh.bat
```

### 정상 실행 신호

```
[VSH] Creating Python virtual environment...
[VSH] Installing Python dependencies...
[VSH] Installing Desktop dependencies...
[VSH] Starting FastAPI server (http://127.0.0.1:3000)...
[VSH] API health check: 200
[VSH] Starting Desktop app...
```

### 테스트 실행

```
python test_vsh_mvp.py
```

---

**작성일:** 2026년 3월 29일  
**상태:** ✅ MVP 완성, 실행 가능  
**다음 단계:** 실제 사용자 피드백 수집 및 개선

