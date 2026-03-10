import json
import re
from pathlib import Path
from urllib import error, request

from vsh.core.config import VSHConfig
from vsh.core.utils import iter_source_files, read_text

try:
    import requests  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    requests = None


PY_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_\.]+)", re.MULTILINE)
JS_IMPORT_RE = re.compile(r"(?:import\s+.*?from\s+|require\()\s*[\"']([@a-zA-Z0-9_\-/]+)[\"']")


def _http_get_status(url: str, timeout: int = 5) -> int:
    if requests is not None:
        try:
            return requests.get(url, timeout=timeout).status_code
        except Exception:
            return 0

    try:
        req = request.Request(url, method="GET")
        with request.urlopen(req, timeout=timeout) as resp:
            return getattr(resp, "status", 200)
    except error.HTTPError as e:
        return e.code
    except (error.URLError, TimeoutError):
        return 0


def extract_imports(project_root: Path, language: str) -> set[str]:
    imports: set[str] = set()
    for file_path in iter_source_files(project_root, language):
        text = read_text(file_path)
        if language == "python":
            for match in PY_IMPORT_RE.findall(text):
                top = match.split(".")[0]
                if top and not top.startswith("_"):
                    imports.add(top)
        else:
            for match in JS_IMPORT_RE.findall(text):
                if match.startswith("."):
                    continue
                if "/" in match and not match.startswith("@"):
                    match = match.split("/")[0]
                imports.add(match)
    return imports


def _exists_in_registry(pkg: str, language: str, cfg: VSHConfig) -> bool:
    if language == "javascript":
        return _http_get_status(f"https://registry.npmjs.org/{pkg}") == 200
    return _http_get_status(f"https://pypi.org/pypi/{pkg}/json") == 200


def find_hallucinated_packages(cfg: VSHConfig, language: str) -> list[str]:
    hallucinated: list[str] = []
    for pkg in sorted(extract_imports(cfg.project_root, language)):
        if not _exists_in_registry(pkg, language, cfg):
            hallucinated.append(pkg)
    return hallucinated
