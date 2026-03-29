from __future__ import annotations

import argparse
import json

from vsh_runtime.engine import VshRuntimeEngine
from vsh_runtime.watcher import ProjectWatcher


def _print(payload: dict, fmt: str):
    if fmt == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif fmt == "markdown":
        print(payload.get("previews", {}).get("markdown", ""))
    else:
        print(payload.get("previews", {}).get("inline", ""))


def main() -> None:
    parser = argparse.ArgumentParser(prog="vsh")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sf = sub.add_parser("scan-file")
    sf.add_argument("file")
    sf.add_argument("--format", choices=["json", "markdown", "summary"], default="summary")

    sp = sub.add_parser("scan-project")
    sp.add_argument("dir")
    sp.add_argument("--format", choices=["json", "markdown", "summary"], default="summary")

    dg = sub.add_parser("diagnostics")
    dg.add_argument("target")

    wt = sub.add_parser("watch")
    wt.add_argument("dir")
    wt.add_argument("--debounce", type=float, default=1.0)

    args = parser.parse_args()
    engine = VshRuntimeEngine()

    if args.cmd == "scan-file":
        _print(engine.analyze_file(args.file), args.format)
    elif args.cmd == "scan-project":
        _print(engine.analyze_project(args.dir), args.format)
    elif args.cmd == "diagnostics":
        print(json.dumps(engine.get_diagnostics(args.target), ensure_ascii=False, indent=2))
    elif args.cmd == "watch":
        ProjectWatcher(args.dir, debounce_sec=args.debounce).watch_forever()


if __name__ == "__main__":
    main()
