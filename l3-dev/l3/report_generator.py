from l3.providers.base import AbstractSharedDB
from l3.schema import VulnRecord, PackageRecord
import os
import glob
from datetime import datetime
from collections import Counter

class L3ReportGenerator:
    """M5: Shared DB의 데이터를 읽어 Markdown 형식의 리포트를 생성한다."""

    KISA_TOTAL = 26
    FSS_TOTAL = 20

    IMPACT_MAP = {
        "SQLi":    "공격 성공 시 DB 전체 조회 / 삭제 / 변조 가능",
        "XSS":     "악성 스크립트 실행 / 세션 탈취 가능",
        "SSRF":    "내부 네트워크 접근 / 민감 정보 유출 가능",
        "XXE":     "서버 파일 읽기 / SSRF 연계 공격 가능",
        "RCE":     "서버 원격 코드 실행 / 전체 시스템 장악 가능",
        "UNKNOWN": "추가 분석 필요",
    }

    REACHABILITY_LABEL = {
        "reachable":   "✅ 실제 도달 가능",
        "unreachable": "⚠️  오탐 가능성 있음",
        "unknown":     "❓ 분석 중 (도달 가능성 미확인)",
    }

    def __init__(self, db: AbstractSharedDB) -> None:
        """AbstractSharedDB를 의존성 주입(DI)으로 받는다."""
        self.db = db

    async def generate(self) -> str:
        """DB에서 데이터를 읽어 리포트 파일을 생성하고 경로를 반환한다."""
        os.makedirs("reports", exist_ok=True)
        
        vuln_records = await self.db.read_all_vuln()
        package_records = await self.db.read_all_package()
        now = datetime.now()
        
        content = "\n\n".join([
            self._format_header(now),
            self._format_score(vuln_records, package_records),
            self._format_vuln_section(vuln_records),
            self._format_package_section(package_records),
            self._format_action_section(vuln_records),
            self._format_footer()
        ])
        
        filepath = f"reports/vsh_report_{now.strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
            
        print(f"[L3 Report] 리포트 생성 완료: {filepath}")
        return filepath

    def _format_header(self, now: datetime) -> str:
        return f"""🛡️ VSH 보안 진단 리포트
======================================================
진단일시 : {now.strftime("%Y-%m-%d %H:%M")}
진단엔진 : VSH v1.0 (SonarQube + SBOM + PoC Docker)
적용기준 : KISA 시큐어코딩 가이드 | 금융보안원 체크리스트 | OWASP Top 10"""

    def _format_score(self, vuln_records: list[VulnRecord], package_records: list[PackageRecord]) -> str:
        counts = Counter(r.severity for r in vuln_records)
        critical = counts.get("CRITICAL", 0)
        high     = counts.get("HIGH", 0)
        medium   = counts.get("MEDIUM", 0)
        low      = counts.get("LOW", 0)

        deduction = critical*15 + high*10 + medium*5 + low*2
        score = max(0, 100 - deduction)

        kisa_pass = max(0, self.KISA_TOTAL - len(vuln_records))
        kisa_pct  = round(kisa_pass / self.KISA_TOTAL * 100) if self.KISA_TOTAL > 0 else 0

        fss_pass = max(0, self.FSS_TOTAL - len(vuln_records))
        fss_pct  = round(fss_pass / self.FSS_TOTAL * 100) if self.FSS_TOTAL > 0 else 0

        reachable = sum(1 for r in vuln_records if r.reachability_status == "reachable")
        dismissed = sum(1 for r in vuln_records if r.status == "dismissed")
        
        risky = sum(1 for r in package_records if r.status == "upgrade_required")
        violation = sum(1 for r in package_records if r.status == "license_violation")
        violation_str = "있음" if violation > 0 else "없음"

        return f"""📊 종합 보안 점수 : {score} / 100
======================================================
항목                              결과
──────────────────────────────────────────────────────
KISA 시큐어코딩 준수율            {kisa_pass} / {self.KISA_TOTAL} 항목 ({kisa_pct}%)
금융보안원 체크리스트 준수율      {fss_pass} / {self.FSS_TOTAL} 항목 ({fss_pct}%)
탐지된 취약점                     {len(vuln_records)}건 (CRITICAL {critical}, HIGH {high}, MEDIUM {medium}, LOW {low})
Reachability 확인 (실제 위협)     {reachable}건
오탐 처리                         {dismissed}건
사용 라이브러리 총                {len(package_records)}개
위험 라이브러리                   {risky}개
라이선스 위반                     {violation_str}"""

    def _format_vuln_section(self, vuln_records: list[VulnRecord]) -> str:
        if not vuln_records:
            return """🚨 취약점 상세
======================================================
코드 취약점이 발견되지 않았습니다."""

        lines = ["🚨 취약점 상세", "======================================================"]
        for r in vuln_records:
            if r.status == "poc_verified":
                lines.append(self._build_poc_block(r))
            else:
                reachability = self.REACHABILITY_LABEL.get(r.reachability_status, "❓")
                impact = self.IMPACT_MAP.get(r.vuln_type, self.IMPACT_MAP["UNKNOWN"])

                lines.append(f"[{r.severity}] {r.vuln_type} — {r.file_path} {r.line_number}번 라인")
                lines.append(f"  * CWE          : {r.cwe_id}")
                lines.append(f"  * CVSS         : {r.cvss_score if r.cvss_score is not None else 'N/A'}")
                lines.append(f"  * CVE          : {r.cve_id or 'N/A'}")
                lines.append(f"  * Reachability : {reachability}")
                lines.append(f"  * 영향 범위    : {impact}")
                lines.append(f"  * KISA 근거    : {r.kisa_ref}")
                lines.append(f"  * 금융보안원   : {r.fss_ref or 'N/A'}")
                lines.append(f"  * OWASP        : {r.owasp_ref or 'N/A'}")
                lines.append(f"  * 조치         : {r.fix_suggestion}")
                lines.append(f"  * PoC 검증     : {r.status}")
                lines.append("")
        
        return "\n".join(lines).strip()

    def _format_package_section(self, package_records: list[PackageRecord]) -> str:
        if not package_records:
            return """📦 SBOM 요약 (라이브러리 성분표)
======================================================
패키지 취약점이 발견되지 않았습니다."""

        lines = [
            "📦 SBOM 요약 (라이브러리 성분표)",
            "======================================================",
            f"{'라이브러리':<15}{'버전':<11}{'CVE':<19}{'라이선스':<12}상태",
            "──────────────────────────────────────────────────────"
        ]

        for r in package_records:
            cve = r.cve_id or "없음"
            
            if r.status == "upgrade_required":
                status_label = "❌ 업그레이드 필요"
            elif r.status == "safe":
                status_label = "✅ 안전"
            elif r.status == "license_violation":
                status_label = "⚠️  라이선스 위반"
            else:
                status_label = r.status
                
            lines.append(f"{r.name:<15}{r.version:<11}{cve:<19}{r.license or 'N/A':<12}{status_label}")
            
        lines.append("")
        lines.append("권장 조치 : 위험 라이브러리를 최신 버전으로 업그레이드하세요.")
        return "\n".join(lines)

    def _format_action_section(self, vuln_records: list[VulnRecord]) -> str:
        acted = [r for r in vuln_records if r.action_at is not None]
        
        if not acted:
            return """✅ 개발자 조치 내역 (Human-in-the-Loop)
======================================================
개발자 조치 내역이 없습니다."""

        lines = [
            "✅ 개발자 조치 내역 (Human-in-the-Loop)",
            "======================================================",
            f"{'취약점':<20}{'탐지 시각':<13}{'개발자 조치':<15}처리 결과",
            "──────────────────────────────────────────────────────"
        ]
        
        for r in acted:
            if r.status == "accepted":
                action = "Accept"
                result = "수정 완료"
            elif r.status == "dismissed":
                action = "Dismiss"
                result = "오탐 처리"
            else:
                action = "미처리"
                result = "-"
                
            lines.append(f"{r.vuln_type:<20}{r.detected_at:<13}{action:<15}{result}")
            
        return "\n".join(lines)

    def _build_poc_block(self, r: VulnRecord) -> str:
        impact = self.IMPACT_MAP.get(r.vuln_type, self.IMPACT_MAP["UNKNOWN"])
        cvss = r.cvss_score if r.cvss_score is not None else "N/A"
        owasp = r.owasp_ref or "N/A"
        evidence = r.code_snippet or "N/A"

        lines = [
            f"[{r.severity}] {r.cwe_id} — {r.file_path} {r.line_number}번 라인",
            f"  ✅ PoC 검증 완료",
            f"",
            f"  ■ 공격 증거",
            f"    공격 입력 및 결과 : {evidence}",
            f"    테스트 환경       : Docker 격리 샌드박스 (--network none)",
            f"    영향 범위         : {impact}",
            f"",
            f"  ■ 법적 근거",
            f"    KISA  : {r.kisa_ref}",
            f"    OWASP : {owasp}",
            f"    CVSS  : {cvss}",
            f"",
            f"  ■ 조치 방법",
            f"    {r.fix_suggestion}",
            f"",
        ]
        return "\n".join(lines)

    def _format_footer(self) -> str:
        return """======================================================
본 리포트는 보조 도구(VSH)에 의해 자동 생성되었으며,
최종 보안 책임은 개발자에게 있습니다.
======================================================"""