# VSH L3 — 트러블슈팅
# 에러 발생 시 여기에 누적 기록

---

## 기록 형식
```
### [날짜] 에러 제목
**증상**: 어떤 에러가 발생했는가
**원인**: 왜 발생했는가
**해결**: 어떻게 해결했는가
**재발 방지**: RULES.md 몇 번 규칙 참조
```

---

## 알고 있는 제약 (Known Constraints)

### syft timeout
- 현상: 대규모 프로젝트에서 120초 초과 가능
- 현재 처리: timeout=120 고정
- 해결 예정: Post-MVP에서 조정

### SonarQube 스캔 polling
- 현상: 스캔 완료까지 최대 120초 대기
- 현재 처리: 5초 간격 polling, 120초 초과 시 scan_error
- 주의: SonarQube Docker가 기동되지 않은 상태에서 스캔 시도 시 scan_error 기록 후 파이프라인 계속 진행

### Docker 미설치 환경
- 현상: M3 PoC 실행 불가
- 현재 처리: FileNotFoundError → poc_skipped 처리
- 파이프라인: M3 건너뜀 후 나머지 계속 진행

---

## 에러 기록 (누적)

(발생 시 아래에 추가)