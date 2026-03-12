from l3.providers.base import AbstractSharedDB
from l3.schema import VulnRecord, PackageRecord
import os
from datetime import datetime
from collections import Counter

class L3ReportGenerator:
    """M5: Shared DB의 데이터를 읽어 Markdown 형식의 리포트를 생성한다."""

    def __init__(self, db: AbstractSharedDB):
        """AbstractSharedDB를 의존성 주입(DI)으로 받는다."""
        self.db = db

    async def generate(self) -> str:
        """DB에서 데이터를 읽어 리포트 파일을 생성하고 경로를 반환한다."""
        os.makedirs("reports", exist_ok=True)
        now = datetime.now()
        
        # 예외 발생 시 상위로 전파됨
        vuln_records = await self.db.read_all_vuln()
        package_records = await self.db.read_all_package()
        
        content = "\n\n".join([
            self._format_summary(vuln_records, package_records, now),
            self._format_vuln_section(vuln_records),
            self._format_package_section(package_records)
        ])
        
        filename = now.strftime("%Y%m%d_%H%M%S")
        filepath = f"reports/vsh_report_{filename}.md"
        
        # 파일 저장 (예외 발생 시 상위로 전파됨)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
            
        print(f"[L3 Report] 리포트 생성 완료: {filepath}")
        return filepath

    def _format_summary(self, vuln_records: list[VulnRecord], package_records: list[PackageRecord], now: datetime) -> str:
        """리포트의 요약 및 severity별 집계 섹션을 생성한다."""
        all_records = vuln_records + package_records
        counts = Counter(r.severity for r in all_records)
        
        critical = counts.get("CRITICAL", 0)
        high     = counts.get("HIGH", 0)
        medium   = counts.get("MEDIUM", 0)
        low      = counts.get("LOW", 0)
        
        return f"""# VSH 보안 스캔 리포트
생성 시각: {now.strftime("%Y-%m-%d %H:%M:%S")}

## 1. 스캔 요약
- 코드 취약점: {len(vuln_records)}건
- 패키지 취약점: {len(package_records)}건

severity별 집계 (전체 합산):
- CRITICAL : {critical}건
- HIGH     : {high}건
- MEDIUM   : {medium}건
- LOW      : {low}건"""

    def _format_vuln_section(self, vuln_records: list[VulnRecord]) -> str:
        """코드 취약점 상세 섹션을 생성한다."""
        if not vuln_records:
            return """## 2. 코드 취약점 상세\n코드 취약점이 발견되지 않았습니다."""
            
        section = "## 2. 코드 취약점 상세\n"
        
        for r in vuln_records:
            section += f"""
### {r.vuln_id}
- severity  : {r.severity}
- status    : {r.status}
- file_path : {r.file_path}
- kisa_ref  : {r.kisa_ref}
- fss_ref   : {r.fss_ref}
- fix       : {r.fix_suggestion}"""

        return section

    def _format_package_section(self, package_records: list[PackageRecord]) -> str:
        """패키지 취약점 상세 섹션을 생성한다."""
        if not package_records:
            return """## 3. 패키지 취약점 상세\n패키지 취약점이 발견되지 않았습니다."""
            
        section = "## 3. 패키지 취약점 상세\n"
        
        for r in package_records:
            section += f"""
### {r.name} {r.version}
- package_id   : {r.package_id}
- severity     : {r.severity}
- status       : {r.status}
- cve_id       : {r.cve_id}
- license_risk : {r.license_risk}"""

        return section
