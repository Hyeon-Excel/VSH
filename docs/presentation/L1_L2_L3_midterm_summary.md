# L1/L2/L3 중간발표 요약

## L1 통합
- SAST 패턴 + reachability + typosquatting + SBOM을 하나의 L1 scanner 경로로 통합.
- 산출물은 VulnRecord/PackageRecord로 정규화.

## L2 현황
- provider 추상화 기반(Mock/실 provider 확장 구조).
- 설명/수정가이드/검증요약 필드 중심 enrichment.

## L3 현황
- Cold path(후속 정밀검증)로 정의.
- 온라인 검증은 opt-in 확장 포인트.

## 한계/향후 계획
- reachability 및 dependency 검증은 현재 heuristic/mock 비중이 큼.
- 실제 API provider(Registry/OSV/SonarQube) 연결 및 스냅샷 데이터 보강 예정.
