#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.service import L1Service


LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def detect_language(path: Path, override: str | None) -> str:
    if override:
        return override.strip().lower()
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "auto")


def request_file_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run L1 scan and export per-file findings JSON.")
    parser.add_argument(
        "--files",
        nargs="+",
        required=True,
        help="Target source files to scan.",
    )
    parser.add_argument(
        "--language",
        default=None,
        help="Optional language override (python/javascript/typescript/auto).",
    )
    parser.add_argument(
        "--mode",
        choices=["snippet", "file"],
        default="file",
        help="L1 scan mode.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(ROOT_DIR / "artifacts" / "test-results" / "l1" / "findings"),
        help="Directory to write JSON outputs.",
    )
    parser.add_argument(
        "--include-patch",
        action="store_true",
        help="Include annotation patch content in output JSON.",
    )
    return parser.parse_args()


def to_output_path(output_dir: Path, file_path: Path, root_dir: Path) -> Path:
    if file_path.is_absolute():
        try:
            rel = file_path.relative_to(root_dir)
        except ValueError:
            rel = file_path.relative_to(file_path.anchor)
    else:
        rel = file_path
    return output_dir / rel.with_suffix(rel.suffix + ".l1.json")


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    mode = ScanMode.FILE if args.mode == "file" else ScanMode.SNIPPET

    service = L1Service()
    total_findings = 0
    scanned = 0

    for raw_path in args.files:
        source_path = Path(raw_path).expanduser()
        if not source_path.is_absolute():
            source_path = (Path.cwd() / source_path).resolve()
        if not source_path.exists() or not source_path.is_file():
            print(f"[SKIP] file not found: {source_path}")
            continue

        code = source_path.read_text(encoding="utf-8")
        language = detect_language(source_path, args.language)
        request = L1ScanAnnotateRequest(
            code=code,
            language=language,
            file_path=request_file_path(source_path),
            mode=mode,
        )
        response = service.scan_annotate(request)
        payload = response.model_dump(mode="json")
        if not args.include_patch:
            payload["annotation_patch"] = ""

        out_path = to_output_path(output_dir=output_dir, file_path=source_path, root_dir=ROOT_DIR)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        findings_count = len(response.findings)
        total_findings += findings_count
        scanned += 1
        print(
            f"[OK] {source_path} -> {out_path} | language={language} findings={findings_count} errors={len(response.errors)}"
        )

    print(f"[DONE] scanned_files={scanned} total_findings={total_findings} output_dir={output_dir}")
    return 0 if scanned > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
