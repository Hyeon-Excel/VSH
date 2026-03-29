# test_poc_verified.py
import asyncio
from dotenv import load_dotenv
load_dotenv()

from l3.providers.sonarqube.mock import MockSonarQubeProvider
from l3.providers.sbom.mock import MockSBOMProvider
from l3.providers.poc.real import RealPoCProvider
from l3.llm.gemini_adapter import GeminiAdapter
from l3.mock_shared_db import MockSharedDB
from l3.normalizer import L3Normalizer
from l3.pipeline import L3Pipeline
from l3.report_generator import L3ReportGenerator

async def main():
    print("=== poc_verified 확인 테스트 ===\n")

    db = MockSharedDB()
    sonarqube = MockSonarQubeProvider()
    sbom = MockSBOMProvider()
    poc = RealPoCProvider(llm=GeminiAdapter())
    normalizer = L3Normalizer(db)
    report_generator = L3ReportGenerator(db)
    pipeline = L3Pipeline(
        sonarqube=sonarqube,
        sbom=sbom,
        poc=poc,
        normalizer=normalizer
    )

    await pipeline.run("test_vuln.py")

    vuln_records = await db.read_all_vuln()
    print(f"VulnRecord: {len(vuln_records)}건")
    for r in vuln_records:
        status_mark = "✅" if r.status == "poc_verified" else "⚠️"
        print(f"  {status_mark} {r.vuln_id} | cwe={r.cwe_id} | {r.status}")

    filepath = await report_generator.generate()
    print(f"\n리포트: {filepath}")
    print("\n=== 완료 ===")

if __name__ == "__main__":
    asyncio.run(main())