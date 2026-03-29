# test_l3_e2e_real.py
import asyncio
from dotenv import load_dotenv
load_dotenv()
from l3.providers.sonarqube.real import RealSonarQubeProvider
from l3.providers.sbom.real import RealSBOMProvider
from l3.providers.poc.real import RealPoCProvider
from l3.llm.gemini_adapter import GeminiAdapter
from l3.mock_shared_db import MockSharedDB
from l3.normalizer import L3Normalizer
from l3.pipeline import L3Pipeline
from l3.report_generator import L3ReportGenerator

async def main():
    print("=== VSH L3 E2E 테스트 (Real SonarQube) ===\n")

    db = MockSharedDB()
    sonarqube = RealSonarQubeProvider(llm=GeminiAdapter())
    sbom = RealSBOMProvider()
    poc = RealPoCProvider(llm=GeminiAdapter())
    normalizer = L3Normalizer(db)
    report_generator = L3ReportGenerator(db)
    pipeline = L3Pipeline(
        sonarqube=sonarqube,
        sbom=sbom,
        poc=poc,
        normalizer=normalizer
    )

    project_path = "."
    print(f"[1] 스캔 대상: {project_path}")
    print("    (SonarQube Cloud 스캔 중... 수 분 소요될 수 있습니다)")
    await pipeline.run(project_path)

    print("\n[2] DB 저장 결과 확인")
    vuln_records = await db.read_all_vuln()
    package_records = await db.read_all_package()

    print(f"  VulnRecord  : {len(vuln_records)}건")
    for r in vuln_records:
        print(f"    - {r.vuln_id} | cwe={r.cwe_id} | status={r.status}")

    print(f"  PackageRecord: {len(package_records)}건")
    for r in package_records:
        print(f"    - {r.name} {r.version} | status={r.status}")

    print("\n[3] 리포트 생성")
    filepath = await report_generator.generate()
    print(f"  리포트 경로: {filepath}")

    print("\n=== 최종 결과 ===")
    for r in vuln_records:
        status_mark = "✅" if r.status == "poc_verified" else "⚠️"
        print(f"  {status_mark} {r.vuln_id} | cwe={r.cwe_id} | {r.status}")

    print("\n=== E2E 테스트 완료 ===")

if __name__ == "__main__":
    asyncio.run(main())