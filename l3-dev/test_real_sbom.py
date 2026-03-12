from l3.providers.sbom.real import SbomProvider
import asyncio

async def main():
    provider = SbomProvider()
    results = await provider.scan("requirements.txt")
    print(f"반환된 PackageRecord 수: {len(results)}개")
    for r in results:
        print(f"  {r.name} {r.version} | {r.cve_id} | {r.severity}")

if __name__ == "__main__":
    asyncio.run(main())