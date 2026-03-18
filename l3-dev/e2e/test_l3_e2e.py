# test_l3_e2e.py
import asyncio
from l3.providers.sonarqube.mock import MockSonarQubeProvider
from l3.providers.sbom.mock import MockSBOMProvider
from l3.providers.poc.real import RealPoCProvider
from l3.llm.claude_adapter import ClaudeAdapter
from l3.mock_shared_db import MockSharedDB
from l3.normalizer import L3Normalizer
from l3.pipeline import L3Pipeline
from l3.report_generator import L3ReportGenerator

async def main():
    print("=== VSH L3 E2E 테스트 시작 ===\n")

    # 의존성 조립
    db = MockSharedDB()
    sonarqube = MockSonarQubeProvider()
    sbom = MockSBOMProvider()
    poc = RealPoCProvider(llm=ClaudeAdapter())
    normalizer = L3Normalizer(db)
    report_generator = L3ReportGenerator(db)
    pipeline = L3Pipeline(
        sonarqube=sonarqube,
        sbom=sbom,
        poc=poc,
        normalizer=normalizer
    )

    # 스캔 실행
    project_path = "test_vuln.py"
    print(f"[1] 스캔 대상: {project_path}")
    await pipeline.run(project_path)

    # 결과 확인
    print("\n[2] DB 저장 결과 확인")
    vuln_records = await db.read_all_vuln()
    package_records = await db.read_all_package()

    print(f"  VulnRecord  : {len(vuln_records)}건")
    for r in vuln_records:
        print(f"    - {r.vuln_id} | cwe={r.cwe_id} | status={r.status}")

    print(f"  PackageRecord: {len(package_records)}건")
    for r in package_records:
        print(f"    - {r.name} {r.version} | status={r.status}")

    # 리포트 생성
    print("\n[3] 리포트 생성")
    filepath = await report_generator.generate()
    print(f"  리포트 경로: {filepath}")

    # 최종 판정
    print("\n=== 최종 결과 ===")
    for r in vuln_records:
        status_mark = "✅" if r.status == "poc_verified" else "⚠️"
        print(f"  {status_mark} {r.vuln_id}: {r.status}")

    print("\n=== E2E 테스트 완료 ===")

if __name__ == "__main__":
    asyncio.run(main())