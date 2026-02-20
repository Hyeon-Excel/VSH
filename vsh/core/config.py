from dataclasses import dataclass
from pathlib import Path

@dataclass
class VSHConfig:
    project_root: Path
    out_dir: Path
    language: str | None = None  # "python" | "javascript" | None(auto)
    semgrep_bin: str = "semgrep"
    syft_bin: str = "syft"       # optional
    use_syft: bool = True
    timeout_sec: int = 20

    # registry endpoints
    pypi_json: str = "https://pypi.org/pypi/{name}/json"
    npm_registry: str = "https://registry.npmjs.org/{name}"

    # OSV
    osv_url: str = "https://api.osv.dev/v1/query"
