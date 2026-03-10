import subprocess
import time
from pathlib import Path
from typing import Iterable

def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.Popen(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
        try:
            out, err = p.communicate(timeout=timeout)
            return p.returncode, out, err
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            return 124, out, err
    except FileNotFoundError:
        tool = cmd[0] if cmd else "command"
        return 127, "", f"{tool} not found"

def read_text(p: Path, max_bytes: int = 200_000) -> str:
    data = p.read_bytes()
    return data[:max_bytes].decode("utf-8", errors="replace")

def guess_language(project_root: Path) -> str:
    has_js = (project_root / "package.json").exists() or any(project_root.rglob("*.js")) or any(project_root.rglob("*.jsx"))
    has_py = (project_root / "requirements.txt").exists() or any(project_root.rglob("*.py"))

    if has_js and has_py:
        return "python" if (project_root / "requirements.txt").exists() else "javascript"
    if has_js:
        return "javascript"
    if has_py:
        return "python"
    return "python"

def iter_source_files(project_root: Path, language: str) -> Iterable[Path]:
    exts = {"python": [".py"], "javascript": [".js", ".jsx", ".ts", ".tsx"]}
    for p in project_root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts.get(language, [".py"]):
            # skip venv/node_modules
            if any(part in ("venv",".venv","node_modules",".git","dist","build") for part in p.parts):
                continue
            yield p

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def now_kst_str() -> str:
    # keep it simple (no tz lib)
    return time.strftime("%Y-%m-%d %H:%M:%S")
