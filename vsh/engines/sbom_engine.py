import json
from pathlib import Path

from vsh.core.config import VSHConfig
from vsh.core.utils import run_cmd


def _parse_requirements(req: Path) -> list[dict]:
    pkgs = []
    for line in req.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            pkgs.append({"ecosystem": "PyPI", "name": name.strip(), "version": ver.strip()})
        else:
            pkgs.append({"ecosystem": "PyPI", "name": line.strip(), "version": None})
    return pkgs


def _parse_pyproject(pyproject: Path) -> list[dict]:
    text = pyproject.read_text()
    pkgs: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith(("python", "name", "version")):
            continue
        if '"' in line and any(op in line for op in [">=", "~=", "==", "^"]):
            name = line.split("=")[0].strip().strip('"').strip("'")
            ver = line.split("=")[1].strip().strip('"').strip("'")
            if name and name not in {"dependencies", "dev-dependencies"}:
                pkgs.append({"ecosystem": "PyPI", "name": name, "version": ver})
    return pkgs


def _parse_package_json(package_json: Path) -> list[dict]:
    try:
        data = json.loads(package_json.read_text())
    except (json.JSONDecodeError, TypeError, ValueError):
        return []

    pkgs: list[dict] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section, {}) or {}).items():
            pkgs.append({"ecosystem": "npm", "name": name, "version": ver})
    return pkgs


def generate_sbom(cfg: VSHConfig) -> dict:
    """
    Prefer syft if available.
    Fallback to requirements.txt / pyproject.toml / package-lock.json / package.json.
    Return normalized dict with 'packages': [{ecosystem,name,version}]
    """
    if cfg.use_syft:
        cmd = [cfg.syft_bin, str(cfg.project_root), "-o", "json"]
        rc, out, _ = run_cmd(cmd, cwd=cfg.project_root, timeout=cfg.timeout_sec)
        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
                pkgs = []
                for artifact in data.get("artifacts", []):
                    name = artifact.get("name")
                    ver = artifact.get("version")
                    purl = artifact.get("purl", "")
                    eco = "PyPI" if "pypi" in purl else ("npm" if "npm" in purl else "unknown")
                    if name:
                        pkgs.append({"ecosystem": eco, "name": name, "version": ver})
                return {"source": "syft", "packages": pkgs}
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

    req = cfg.project_root / "requirements.txt"
    if req.exists():
        return {"source": "requirements.txt", "packages": _parse_requirements(req)}

    pyproject = cfg.project_root / "pyproject.toml"
    if pyproject.exists():
        pyproject_pkgs = _parse_pyproject(pyproject)
        if pyproject_pkgs:
            return {"source": "pyproject.toml", "packages": pyproject_pkgs}

    lock = cfg.project_root / "package-lock.json"
    if lock.exists():
        try:
            data = json.loads(lock.read_text())
            deps = data.get("packages", {}) or {}
            pkgs = []
            for k, v in deps.items():
                if k in ("", "node_modules"):
                    continue
                name = k.split("node_modules/")[-1]
                ver = v.get("version")
                if name and ver:
                    pkgs.append({"ecosystem": "npm", "name": name, "version": ver})
            return {"source": "package-lock.json", "packages": pkgs}
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    package_json = cfg.project_root / "package.json"
    if package_json.exists():
        npm_pkgs = _parse_package_json(package_json)
        if npm_pkgs:
            return {"source": "package.json", "packages": npm_pkgs}

    return {"source": "none", "packages": []}
