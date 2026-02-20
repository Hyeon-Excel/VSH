import json
from pathlib import Path
from vsh.core.config import VSHConfig
from vsh.core.utils import run_cmd

def generate_sbom(cfg: VSHConfig) -> dict:
    """
    Prefer syft if available.
    Otherwise fallback to parsing requirements.txt or package-lock.json.
    Return a normalized dict with 'packages': [{ecosystem,name,version}]
    """
    if cfg.use_syft:
        cmd = [cfg.syft_bin, str(cfg.project_root), "-o", "json"]
        rc, out, err = run_cmd(cmd, cwd=cfg.project_root, timeout=cfg.timeout_sec)
        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
                pkgs = []
                for a in data.get("artifacts", []):
                    name = a.get("name")
                    ver = a.get("version")
                    # rough ecosystem mapping
                    purl = a.get("purl","")
                    eco = "PyPI" if "pypi" in purl else ("npm" if "npm" in purl else "unknown")
                    if name:
                        pkgs.append({"ecosystem": eco, "name": name, "version": ver})
                return {"source":"syft", "packages": pkgs}
            except Exception:
                pass

    # fallback
    req = cfg.project_root / "requirements.txt"
    if req.exists():
        pkgs = []
        for line in req.read_text().splitlines():
            line=line.strip()
            if not line or line.startswith("#"): 
                continue
            if "==" in line:
                name, ver = line.split("==",1)
                pkgs.append({"ecosystem":"PyPI","name":name.strip(),"version":ver.strip()})
            else:
                pkgs.append({"ecosystem":"PyPI","name":line.strip(),"version":None})
        return {"source":"requirements.txt", "packages": pkgs}

    lock = cfg.project_root / "package-lock.json"
    if lock.exists():
        try:
            data = json.loads(lock.read_text())
            deps = data.get("packages", {}) or {}
            pkgs=[]
            for k,v in deps.items():
                if k in ("","node_modules"): 
                    continue
                name = k.split("node_modules/")[-1]
                ver = v.get("version")
                if name and ver:
                    pkgs.append({"ecosystem":"npm","name":name,"version":ver})
            return {"source":"package-lock.json", "packages": pkgs}
        except Exception:
            pass

    return {"source":"none", "packages": []}
