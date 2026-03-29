# VSH L3 — 변경 기록

---

## 기록 형식
```
## [날짜] Week X — 작업 제목
### 완료
- 작업 내용
### 영향받은 파일
- 파일 목록
```

---

## 2026-03-09 — 프로젝트 초기 세팅

### 완료
- l3-dev/ 폴더 뼈대 생성 (29개 파일)
- GEMINI.md 작성 (Gemini CLI 컨텍스트)
- RULES.md 작성 (12개 규칙)
- TASK.md 작성 (Week 1 태스크 목록)
- ARCHITECTURE.md 작성 (구조 + 데이터 흐름)
- DB_SCHEMA.md 작성 (VulnRecord / PackageRecord)
- TROUBLESHOOTING.md 작성 (Known Constraints 포함)
- CHANGELOG.md 작성

### 영향받은 파일
- 신규: 위 7개 문서 파일 전체
- 신규: l3/ 하위 빈 파일 전체 (Week 1에 채울 예정)

### 다음 작업
- TASK.md Week 1 태스크 순서대로 진행
- 시작: `l3/schema.py` — VulnRecord / PackageRecord

## [TODO]
- [ ] scan_project() 예외처리 추가
  - 위치: mcp_server.py
  - 시점: Week 3~4 Real 구현 시
  - 내용: pipeline.run(), report_generator.generate() 예외 발생 시 클라이언트에 에러 메시지 반환