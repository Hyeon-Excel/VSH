"""
L3 Cold Path — SonarQube 심층 SAST 분석 (구현 예정)

계획:
- SonarQube REST API 연동 (sonar-scanner CLI 또는 Web API)
- 전체 프로젝트 스캔 트리거 및 결과 폴링
- L1 결과와 통합: 중복 제거, 오탐 보완, 심각도 재조정
- 지원 언어: Python, JavaScript, TypeScript, Java, Go, C/C++
- 출력: SonarQube 이슈 → VSH Finding 구조로 정규화

전제 조건:
- SonarQube Community Edition 설치 및 실행 (localhost:9000 기본)
- sonar-scanner CLI 설치
- SONAR_HOST_URL, SONAR_TOKEN 환경변수 설정

TODO: L3 구현 시 아래 의존성 추가 (선택)
  pip install python-sonarqube-api
"""
