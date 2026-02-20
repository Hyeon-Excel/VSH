from pathlib import Path
from vsh.core.models import Finding
from vsh.core.utils import read_text, clamp

# very lightweight heuristic:
# if file contains known source markers and sink markers in proximity -> YES
PY_SOURCES = ["request.", "flask.request", "input(", "sys.argv", "os.environ"]
PY_SINKS   = ["execute(", "cursor.execute", "eval(", "subprocess.", "os.system("]

JS_SOURCES = ["req.body", "req.query", "location.", "document.URL", "window.location"]
JS_SINKS   = ["innerHTML", "eval(", "Function(", "dangerouslySetInnerHTML"]

def annotate_reachability(project_root: Path, language: str, findings: list[Finding]) -> list[Finding]:
    for f in findings:
        p = project_root / f.file
        if not p.exists():
            continue
        text = read_text(p)
        sources = JS_SOURCES if language == "javascript" else PY_SOURCES
        sinks   = JS_SINKS   if language == "javascript" else PY_SINKS

        has_source = any(s in text for s in sources)
        has_sink   = any(s in text for s in sinks)

        if has_source and has_sink:
            # extra: if finding line near any source or sink line -> YES
            lines = text.splitlines()
            idx = clamp(f.line-1, 0, max(0,len(lines)-1))
            window = "\n".join(lines[clamp(idx-20,0,len(lines)): clamp(idx+20,0,len(lines))])
            if any(s in window for s in sources) and any(s in window for s in sinks):
                f.reachability = "YES"
            else:
                f.reachability = "UNKNOWN"
        else:
            f.reachability = "NO"
    return findings
