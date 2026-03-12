## 클래스명
L3Pipeline
L3Normalizer
MockSonarQubeProvider / RealSonarQubeProvider
MockSBOMProvider / RealSBOMProvider
MockPoCProvider / RealPoCProvider
MockSharedDB / RealSharedDB
ReportGenerator

## 메서드명
Provider:
  scan(project_path: str)         # SonarQube, SBOM
  verify(record: VulnRecord)      # PoC

Normalizer:
  save(record)                    # M4 저장

Pipeline:
  run(project_path: str)          # 전체 파이프라인 실행

ReportGenerator:
  generate(vuln_records, package_records) # 리포트 생성

SharedDB:
  write(record)
  read_all_vuln()
  read_all_package()

## 변수명
pipeline.py 생성자 파라미터:
  sonarqube: AbstractSonarQubeProvider
  sbom: AbstractSBOMProvider
  poc: AbstractPoCProvider
  normalizer: L3Normalizer

## 로그 형식
[L3 모듈명] 메시지
예시:
  [L3 Pipeline] M1 스캔 완료: 3건
  [L3 Pipeline] M2 스캔 완료: 2건
  [L3 Pipeline] M3 PoC 실행 중: VSH-xxx
  [L3 Pipeline] M3 완료: 3건 처리
  [L3 Pipeline] poc_skipped: {vuln_id} - {e}
  [L3 Normalizer] 저장 완료: VulnRecord
  [L3 Report] 리포트 생성 완료: reports/vsh_report.md

## 리포트 파일명
reports/vsh_report.md
reports/vsh_report.json