# Active Architecture

## 실행 경로
1. CLI/MCP/Watcher 진입
2. L1 `VSHL1Scanner` (fast detection)
3. normalize (`VulnRecord`/`PackageRecord`)
4. L2 `L2ReasoningPipeline` (context-aware reasoning)
5. risk/priority aggregation
6. L3 validation slot (cold path)
7. diagnostics/report output

## 레이어 책임
- L1: 빠른 후보 탐지
- L2: 문맥 기반 취약성 판단 + 설명
- L3: 심층 검증(무거운 검증/PoC)

## IDE 연동
- watcher polling 기반 save-event 감지
- diagnostics JSON 공통 포맷
- non-destructive preview 기본
