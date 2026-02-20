import re
import requests
from pathlib import Path
from vsh.core.config import VSHConfig
from vsh.core.utils import read_text, iter_source_files

PY_IMPORT_RE = re.compile(r"^\s*import\s+([a-zA-Z0-9_\.]+)", re.M)
PY_FROM_RE   = re.compile(r"^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+", re.M)
JS_IMPORT_RE = re.compile(r"from\s+['\"]([^'\"]+)['\"]|require\(\s*['\"]([^'\"]+)['\"]\s*\)")

def _top_module(name: str) -> str:
    return name.split(".")[0].strip()

def _is_third_party_py(mod: str) -> bool:
    # ignore common stdlib-ish heuristic
    stdish = {"os","sys","re","json","time","pathlib","typing","math","subprocess","threading","asyncio"}
    return mod not in stdish and not mod.startswith("_")

def extract_imports(project_root: Path, language: str) -> set[str]:
    pkgs: set[str] = set()
    if language == "python":
        for f in iter_source_files(project_root, "python"):
            t = read_text(f)
            for m in PY_IMPORT_RE.findall(t):
                pkgs.add(_top_module(m))
            for m in PY_FROM_RE.findall(t):
                pkgs.add(_top_module(m))
        pkgs = {p for p in pkgs if _is_third_party_py(p)}
    else:
        for f in iter_source_files(project_root, "javascript"):
            t = read_text(f)
            for a,b in JS_IMPORT_RE.findall(t):
                name = a or b
                if not name: 
                    continue
                # ignore relative imports
                if name.startswith(".") or name.startswith("/"):
                    continue
                # scoped packages keep @scope/name
                pkgs.add(name)
    return pkgs

def pypi_exists(cfg: VSHConfig, name: str) -> bool:
    url = cfg.pypi_json.format(name=name)
    try:
        r = requests.get(url, timeout=5)
        return r.status_code == 200
    except Exception:
        return True  # fail-open

def npm_exists(cfg: VSHConfig, name: str) -> bool:
    url = cfg.npm_registry.format(name=name)
    try:
        r = requests.get(url, timeout=5)
        return r.status_code == 200
    except Exception:
        return True

def find_hallucinated_packages(cfg: VSHConfig, language: str) -> list[str]:
    imports = extract_imports(cfg.project_root, language)
    hallucinated: list[str] = []
    for p in sorted(imports):
        ok = npm_exists(cfg, p) if language == "javascript" else pypi_exists(cfg, p)
        if not ok:
            hallucinated.append(p)
    return hallucinated
