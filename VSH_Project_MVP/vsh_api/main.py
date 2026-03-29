from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import json
import os
import shutil
from vsh_runtime.engine import VshRuntimeEngine
from vsh_runtime.watcher import ProjectWatcher
import threading

app = FastAPI(title="VSH API", version="1.0.0")

engine = VshRuntimeEngine()
watchers = {}  # path -> watcher instance

CONFIG_DIR = Path.home() / '.vsh'
CONFIG_PATH = CONFIG_DIR / 'config.json'

DEFAULT_CONFIG = {
    "llm": {
        "provider": "mock",
        "gemini_api_key": "",
        "openai_api_key": "",
        "model": "gemini-1.5-pro",
        "enable_l2": True,
        "enable_l3": True
    },
    "tools": {
        "syft_enabled": True,
        "syft_path": "",
        "syft_auto_detect": True
    },
    "scan": {
        "watch_on_save": True,
        "auto_scan_on_select": False,
        "enable_sbom": True,
        "max_files_per_scan": 200,
        "exclude_dirs": [
            ".git",
            "node_modules",
            "venv",
            "__pycache__",
            "dist",
            "build"
        ],
        "include_extensions": [
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx"
        ]
    },
    "output": {
        "export_path": "./exports",
        "save_json": True,
        "save_markdown": True,
        "save_diagnostics": True,
        "auto_open_report_after_scan": False
    },
    "ui": {
        "theme": "dark",
        "show_code_preview": True,
        "show_attack_scenario": True,
        "show_validation_panel": True
    },
    "system": {
        "api_base_url": "http://localhost:3000",
        "config_version": 1
    }
}

class ScanRequest(BaseModel):
    path: str

class WatchRequest(BaseModel):
    path: str

def save_diagnostics(target_path: str, diagnostics: dict):
    if Path(target_path).is_file():
        vsh_dir = Path(target_path).parent / ".vsh"
    else:
        vsh_dir = Path(target_path) / ".vsh"
    vsh_dir.mkdir(exist_ok=True)
    diag_file = vsh_dir / "diagnostics.json"
    with open(diag_file, "w", encoding="utf-8") as f:
        json.dump(diagnostics, f, ensure_ascii=False, indent=2)

def save_report(target_path: str, report: dict):
    if Path(target_path).is_file():
        vsh_dir = Path(target_path).parent / ".vsh"
    else:
        vsh_dir = Path(target_path) / ".vsh"
    vsh_dir.mkdir(exist_ok=True)
    json_file = vsh_dir / "report.json"
    md_file = vsh_dir / "report.md"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    # Markdown은 engine에서 생성된 previews 사용
    if "previews" in report and "markdown" in report["previews"]:
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(report["previews"]["markdown"])


def ensure_config_path():
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not CONFIG_PATH.exists():
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)


def load_config() -> dict:
    ensure_config_path()
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    ensure_config_path()
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

@app.post("/scan/file")
def scan_file(req: ScanRequest):
    if not Path(req.path).is_file():
        raise HTTPException(status_code=400, detail="Invalid file path")
    result = engine.analyze_file(req.path)
    save_diagnostics(req.path, result["diagnostics"])
    save_report(req.path, result)
    return normalize_response(result, "file", req.path)

@app.post("/scan/project")
def scan_project(req: ScanRequest):
    if not Path(req.path).is_dir():
        raise HTTPException(status_code=400, detail="Invalid project path")
    result = engine.analyze_project(req.path)
    save_diagnostics(req.path, result["diagnostics"])
    save_report(req.path, result)
    return normalize_response(result, "project", req.path)

@app.get("/diagnostics")
def get_diagnostics(path: str):
    if Path(path).is_file():
        vsh_dir = Path(path).parent / ".vsh"
    else:
        vsh_dir = Path(path) / ".vsh"
    diag_file = vsh_dir / "diagnostics.json"
    if not diag_file.exists():
        raise HTTPException(status_code=404, detail="Diagnostics not found")
    with open(diag_file, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/settings")
def get_settings():
    return load_config()


@app.post("/settings")
def post_settings(config: dict):
    save_config(config)
    return {"status": "ok", "settings": config}


@app.post("/settings/test-llm")
def test_llm(settings: dict):
    provider = settings.get('provider', 'mock')
    if provider == 'mock':
        return {"provider": provider, "connected": True, "reason": "Mock provider always connected"}

    if provider == 'gemini':
        key = settings.get('gemini_api_key', '')
    elif provider == 'openai':
        key = settings.get('openai_api_key', '')
    else:
        return {"provider": provider, "connected": False, "reason": "Unknown provider"}

    if not key:
        return {"provider": provider, "connected": False, "reason": "API key not configured"}

    # 실제 호출 여부는 환경 의존, 우선 키 존재만 검증
    return {"provider": provider, "connected": True, "reason": "API key set"}


@app.post("/settings/check-syft")
def check_syft(settings: dict):
    syft_path = settings.get('syft_path', '')
    syft_installed = False
    syft_found = ''

    if syft_path:
        if Path(syft_path).exists():
            syft_installed = True
            syft_found = syft_path
    else:
        what = shutil.which('syft')
        if what:
            syft_installed = True
            syft_found = what

    return {
        "syft": {
            "installed": syft_installed,
            "path": syft_found
        }
    }


@app.get("/system/status")
def system_status():
    config = load_config()
    syft_info = check_syft({
        'syft_path': config.get('tools', {}).get('syft_path', '')
    })['syft']
    llm = config.get('llm', {})

    return {
        "api_server": "running",
        "python_core": "ready",
        "syft": syft_info,
        "llm": {
            "provider": llm.get('provider', 'mock'),
            "configured": bool((llm.get('gemini_api_key') or llm.get('openai_api_key'))),
            "connected": llm.get('provider', 'mock') == 'mock' or bool(llm.get('gemini_api_key') or llm.get('openai_api_key'))
        },
        "config_path": str(CONFIG_PATH)
    }

@app.post("/watch/start")
def watch_start(req: WatchRequest):
    if req.path in watchers:
        raise HTTPException(status_code=400, detail="Watcher already running")
    watcher = ProjectWatcher(req.path, debounce_sec=1.0)
    watchers[req.path] = watcher
    def run_watcher():
        for events in watcher:
            for event in events:
                if event["type"] == "modified" and event["path"].endswith(".py"):
                    # Rescan on change
                    result = engine.analyze_file(event["path"])
                    save_diagnostics(event["path"], result["diagnostics"])
                    save_report(event["path"], result)
    thread = threading.Thread(target=run_watcher, daemon=True)
    thread.start()
    return {"status": "started"}

@app.post("/watch/stop")
def watch_stop(req: WatchRequest):
    if req.path not in watchers:
        raise HTTPException(status_code=400, detail="Watcher not running")
    watchers[req.path].stop()
    del watchers[req.path]
    return {"status": "stopped"}

@app.get("/file/content")
def get_file_content(path: str):
    file_path = Path(path)
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")

@app.get("/health")
def health():
    return {"status": "ok"}

def normalize_response(result: dict, mode: str, target: str) -> dict:
    findings = []
    for v in result.get("vuln_records", []):
        finding = {
            "id": v.get("vuln_id"),
            "file": v.get("file_path"),
            "line": v.get("line_number"),
            "end_line": v.get("end_line_number", v.get("line_number")),
            "severity": v.get("severity"),
            "rule_id": v.get("rule_id"),
            "message": v.get("evidence"),
            "evidence": v.get("evidence"),
            "reachability_status": v.get("reachability_status"),
            "reachability_confidence": v.get("reachability_confidence", 0.0),
            "l2_reasoning": {
                "is_vulnerable": v.get("is_vulnerable", False),
                "confidence": v.get("l2_confidence", 0.0),
                "reasoning": v.get("reasoning_verdict", ""),
                "attack_scenario": v.get("l3_attack_scenario", ""),
                "fix_suggestion": v.get("fix_suggestion", "")
            },
            "l3_validation": {
                "validated": v.get("l3_validated", False),
                "exploit_possible": v.get("exploit_possible", False),
                "confidence": v.get("l3_confidence", 0.0),
                "evidence": v.get("evidence", ""),
                "recommended_fix": v.get("fix_suggestion", "")
            }
        }
        findings.append(finding)
    
    summary = result.get("aggregate_summary", {})
    top_risky_files = sorted(
        [(f, len([v for v in result.get("vuln_records", []) if v.get("file_path") == f])) for f in set(v.get("file_path") for v in result.get("vuln_records", []))],
        key=lambda x: x[1], reverse=True
    )[:5]
    
    return {
        "target": target,
        "mode": mode,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": summary.get("risk_distribution", {}).get("P1", 0),
            "high": summary.get("risk_distribution", {}).get("P2", 0),
            "medium": summary.get("risk_distribution", {}).get("P3", 0),
            "low": summary.get("risk_distribution", {}).get("P4", 0) + summary.get("risk_distribution", {}).get("INFO", 0),
            "top_risky_files": top_risky_files
        }
    }