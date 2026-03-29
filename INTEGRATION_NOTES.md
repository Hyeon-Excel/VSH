# INTEGRATION NOTES

- `rasasoe-integration` 브랜치에서 active codepath를 orchestration 기준으로 단일화.
- `modules/scanner`, 이전 pipeline 구현, 루트 setup.py를 `archive/legacy`로 이동.
- 제거/아카이브 이유: 중복된 실행경로로 인한 인수인계 혼선 제거.
- L3-dev 브랜치는 로컬 저장소에 직접 참조가 없어, 현재 저장소 내 L3 성격 코드(검증/리포트/후처리)를 provider 확장 구조로 재정리.
