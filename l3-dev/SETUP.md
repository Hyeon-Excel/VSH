# VSH L3 — 환경 세팅 가이드

## 1. Python 패키지 (pip)
```bash
pip install -r requirements.txt
```

## 2. syft — Week 2 시작 전 필수

SBOM 생성 CLI 도구. pip로 설치 불가, 별도 설치 필요.

**Windows:**
```powershell
# PowerShell 관리자 권한으로 실행
winget install anchore.syft

# 또는 직접 다운로드
# https://github.com/anchore/syft/releases
# syft_windows_amd64.zip 다운로드 후 PATH 추가
```

**Mac:**
```bash
brew install syft
```

**설치 확인:**
```bash
syft --version
syft . -o cyclonedx-json  # 동작 확인
```

## 3. Docker Desktop — Week 3~4 시작 전 필수

PoC Sandbox 실행 환경.

**Windows:**
```
https://www.docker.com/products/docker-desktop/
→ Docker Desktop for Windows 다운로드 및 설치
→ 설치 후 Docker Desktop 실행 (시스템 트레이에서 확인)
```

**설치 확인:**
```bash
docker --version
docker run hello-world
```

## 4. sonar-scanner — Week 3 시작 전 필수

SonarQube 스캔 실행 CLI.

**Windows:**
```powershell
# 1. SonarQube Docker 먼저 실행
docker run -d --name sonarqube -p 9000:9000 sonarqube:community

# 2. sonar-scanner 설치
# https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/
# Windows ZIP 다운로드 후 PATH 추가

# 3. 기동 확인 (1~2분 소요)
curl http://localhost:9000/api/system/status
# {"status":"UP"} 확인
```

**설치 확인:**
```bash
sonar-scanner --version
```

## 5. 전체 환경 확인 체크리스트
```
Week 1 시작 전:
□ python --version    → 3.13.7
□ pip install -r requirements.txt 완료
□ pytest --version 확인

Week 2 시작 전:
□ syft --version 확인
□ syft . -o cyclonedx-json 동작 확인

Week 3~4 시작 전:
□ Docker Desktop 실행 중 확인
□ docker run hello-world 성공
□ sonar-scanner --version 확인
□ curl http://localhost:9000/api/system/status → "UP"
```
```

---

## 정리
```
바로 실행 가능:
  pip install -r requirements.txt   ← Python 패키지 전부

Week 2 전:
  winget install anchore.syft       ← syft

Week 3~4 전:
  Docker Desktop 설치 + 실행
  sonar-scanner 설치