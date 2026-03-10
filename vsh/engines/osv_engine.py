import json
from urllib import error, request

from vsh.core.config import VSHConfig
from vsh.core.models import DependencyVuln


try:
    import requests  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    requests = None


def _http_post_json(url: str, payload: dict, timeout: int = 8):
    if requests is not None:
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            return r.status_code, r.json() if r.text else {}
        except Exception:
            return 0, {}

    try:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            body = json.loads(resp.read().decode("utf-8") or "{}")
            return status, body
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
        return 0, {}


def query_osv(cfg: VSHConfig, ecosystem: str, name: str, version: str | None) -> list[DependencyVuln]:
    payload = {"package": {"ecosystem": ecosystem, "name": name}}
    if version:
        payload["version"] = version

    status, data = _http_post_json(cfg.osv_url, payload, timeout=8)
    if status != 200:
        return []

    vulns = []
    for v in data.get("vulns", [])[:20]:
        vid = v.get("id")
        summary = v.get("summary") or (v.get("details", "")[:160] if v.get("details") else None)
        refs = [x.get("url") for x in (v.get("references") or []) if x.get("url")]
        vulns.append(
            DependencyVuln(
                ecosystem=ecosystem,
                name=name,
                version=version,
                vuln_id=vid,
                summary=summary,
                severity="HIGH" if vid and str(vid).startswith("CVE-") else "MEDIUM",
                references=refs,
            )
        )
    return vulns


def scan_deps_with_osv(cfg: VSHConfig, sbom: dict) -> list[DependencyVuln]:
    out: list[DependencyVuln] = []
    for p in sbom.get("packages", []):
        eco = p.get("ecosystem", "unknown")
        name = p.get("name")
        ver = p.get("version")
        if not name or eco == "unknown":
            continue
        out.extend(query_osv(cfg, eco, name, ver))

    uniq = {}
    for dep in out:
        key = (dep.ecosystem, dep.name, dep.version, dep.vuln_id)
        uniq[key] = dep
    return list(uniq.values())
