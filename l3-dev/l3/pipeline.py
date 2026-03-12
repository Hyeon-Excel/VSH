from l3.providers.base import (
    AbstractSonarQubeProvider,
    AbstractSBOMProvider,
    AbstractPoCProvider
)
from l3.normalizer import L3Normalizer
from l3.schema import VulnRecord, PackageRecord

class L3Pipeline:
    """M1 → M2 → M3 → M4 순서로 각 Provider를 조율하는 Orchestrator"""

    def __init__(
        self,
        sonarqube: AbstractSonarQubeProvider,
        sbom: AbstractSBOMProvider,
        poc: AbstractPoCProvider,
        normalizer: L3Normalizer
    ):
        """각 Provider를 의존성 주입(DI)으로 받아 초기화한다."""
        self.sonarqube = sonarqube
        self.sbom = sbom
        self.poc = poc
        self.normalizer = normalizer

    async def run(self, project_path: str) -> None:
        """전체 파이프라인(M1~M4)을 순차적으로 실행한다."""
        
        # M1 - SonarQube SAST 스캔
        vuln_records = await self.sonarqube.scan(project_path)
        print(f"[L3 Pipeline] M1 스캔 완료: {len(vuln_records)}건")

        # M2 - SBOM 스캔 → 즉시 M4 저장 (LLM 우회, M3 생략)
        package_records = await self.sbom.scan(project_path)
        for package in package_records:
            await self.normalizer.save(package)
        print(f"[L3 Pipeline] M2 스캔 완료: {len(package_records)}건")

        # M3 - PoC 검증 → M4 저장
        for record in vuln_records:
            print(f"[L3 Pipeline] M3 PoC 실행 중: {record.vuln_id}")
            try:
                record = await self.poc.verify(record)
            except Exception as e:
                record.status = "poc_skipped"
                print(f"[L3 Pipeline] poc_skipped: {record.vuln_id} - {e}")
                
            await self.normalizer.save(record)
            
        print(f"[L3 Pipeline] M3 완료: {len(vuln_records)}건 처리")

        # 완료
        print(f"[L3 Pipeline] 전체 스캔 완료: {project_path}")
