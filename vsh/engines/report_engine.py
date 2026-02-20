from pathlib import Path
from vsh.core.models import ScanResult, Finding, DependencyVuln
from vsh.core.utils import now_kst_str

def calc_score(findings: list[Finding], dep_vulns: list[DependencyVuln], hallucinated: list[str]) -> int:
    score = 100
    for f in findings:
        score -= {"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3,"INFO":1}.get(f.severity,5)
        if f.reachability == "YES":
            score -= 5
    score -= min(20, len(dep_vulns) * 2)
    score -= min(15, len(hallucinated) * 5)
    return max(0, min(100, score))

def make_inline_comment(f: Finding) -> str:
    stars = {"CRITICAL":"★★★★★","HIGH":"★★★★☆","MEDIUM":"★★★☆☆","LOW":"★★☆☆☆","INFO":"★☆☆☆☆"}.get(f.severity,"★★★☆☆")
    cvss = f.cvss if f.cvss is not None else "-"
    cwe = f.cwe or "-"
    cve = f.cve or "-"
    reach = "✅ 실제 도달 가능" if f.reachability=="YES" else ("⚠️ 불명확" if f.reachability=="UNKNOWN" else "❌ 도달 어려움")
    rec = f.recommendation or "(권장 수정안 없음)"
    return (
        f"# ⚠️ [VSH 알림] {f.title}\n"
        f"# ─────────────────────────────────────────────────\n"
        f"# 위험도      : {stars} {f.severity} | CVSS {cvss}\n"
        f"# 취약점      : {cwe}\n"
        f"# CVE         : {cve}\n"
        f"# Reachability: {reach}\n"
        f"#\n"
        f"# 💬 메시지   : {f.message}\n"
        f"#\n"
        f"# 🔧 권장 수정 코드:\n"
        f"# {rec}\n"
    )

def write_markdown_report(out_path: Path, result: ScanResult) -> None:
    lines = []
    lines.append("# 🛡️ VSH 보안 진단 리포트")
    lines.append("")
    lines.append(f"**프로젝트명** : {result.project}")
    lines.append(f"**진단일시**   : {now_kst_str()}")
    lines.append(f"**진단엔진**   : VSH v1.0 (Semgrep + SBOM + OSV + Registry Check)")
    lines.append("")
    lines.append(f"## 📊 종합 보안 점수 : {result.score} / 100")
    lines.append("")
    lines.append("## 🚨 코드 취약점")
    if not result.findings:
        lines.append("- 탐지된 코드 취약점 없음")
    else:
        for f in result.findings:
            lines.append(f"### [{f.severity}] {f.title} — `{f.file}:{f.line}`")
            lines.append(f"- **ID**           : {f.id}")
            if f.cwe: lines.append(f"- **CWE**          : {f.cwe}")
            if f.cve: lines.append(f"- **CVE**          : {f.cve}")
            if f.cvss is not None: lines.append(f"- **CVSS**         : {f.cvss}")
            lines.append(f"- **Reachability** : {f.reachability}")
            lines.append(f"- **메시지**       : {f.message}")
            if f.recommendation:
                lines.append(f"- **조치**         : {f.recommendation}")
            if f.references:
                lines.append(f"- **참고**         : " + ", ".join(f.references[:5]))
            lines.append("")

    lines.append("## 📦 공급망 / 라이브러리 취약점 (OSV)")
    if not result.dep_vulns:
        lines.append("- 탐지된 라이브러리 취약점 없음(또는 조회 실패)")
    else:
        for d in result.dep_vulns[:30]:
            lines.append(f"- **{d.ecosystem}** `{d.name} {d.version}` → `{d.vuln_id}` : {d.summary}")

    lines.append("")
    lines.append("## 🧨 패키지 환각 / 존재성 이상")
    if not result.hallucinated_packages:
        lines.append("- 의심 패키지 없음")
    else:
        for p in result.hallucinated_packages:
            lines.append(f"- ❌ 레지스트리 미존재 의심: `{p}`")

    out_path.write_text("\n".join(lines), encoding="utf-8")
