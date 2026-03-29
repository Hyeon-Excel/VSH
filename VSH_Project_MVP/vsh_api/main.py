from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import json
import os
from vsh_runtime.engine import VshRuntimeEngine
from vsh_runtime.watcher import ProjectWatcher
import threading

app = FastAPI(title="VSH API", version="1.0.0")

engine = VshRuntimeEngine()
watchers = {}  # path -> watcher instance

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
    vsh_dir = Path(path).parent / ".vsh"
    diag_file = vsh_dir / "diagnostics.json"
    if not diag_file.exists():
        raise HTTPException(status_code=404, detail="Diagnostics not found")
    with open(diag_file, "r", encoding="utf-8") as f:
        return json.load(f)

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