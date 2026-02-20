import requests
from vsh.core.config import VSHConfig
from vsh.core.models import DependencyVuln

def query_osv(cfg: VSHConfig, ecosystem: str, name: str, version: str | None) -> list[DependencyVuln]:
    # OSV expects ecosystem names like "PyPI", "npm"
    payload = {"package":{"ecosystem": ecosystem, "name": name}}
    if version:
        payload["version"] = version

    try:
        r = requests.post(cfg.osv_url, json=payload, timeout=8)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []

    vulns = []
    for v in data.get("vulns", [])[:20]:
        vid = v.get("id")
        summary = v.get("summary") or (v.get("details","")[:160] if v.get("details") else None)
        refs = [x.get("url") for x in (v.get("references") or []) if x.get("url")]
        vulns.append(DependencyVuln(
            ecosystem=ecosystem,
            name=name,
            version=version or "",
            vuln_id=vid,
            summary=summary,
            severity="MEDIUM",
            references=refs
        ))
    return vulns

def scan_deps_with_osv(cfg: VSHConfig, sbom: dict) -> list[DependencyVuln]:
    dep_vulns: list[DependencyVuln] = []
    for p in sbom.get("packages", []):
        eco = p.get("ecosystem","unknown")
        if eco not in ("PyPI","npm"):
            continue
        dep_vulns.extend(query_osv(cfg, eco, p.get("name",""), p.get("version")))
    # de-dup
    seen=set()
    out=[]
    for d in dep_vulns:
        key=(d.ecosystem,d.name,d.version,d.vuln_id)
        if key in seen: 
            continue
        seen.add(key)
        out.append(d)
    return out
