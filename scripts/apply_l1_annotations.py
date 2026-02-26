#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vsh.common.models import L1ScanAnnotateRequest, ScanMode
from vsh.l1_hot.patch_apply import PatchApplyError, apply_unified_patch
from vsh.l1_hot.service import L1Service


LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run L1 scan and apply annotation patch to files.")
    parser.add_argument("--files", nargs="+", required=True, help="Target source files to annotate.")
    parser.add_argument("--language", default=None, help="Optional language override.")
    parser.add_argument("--mode", choices=["snippet", "file"], default="file", help="L1 scan mode.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write files. Only print summary and optional patch preview.",
    )
    parser.add_argument(
        "--print-patch",
        action="store_true",
        help="Print generated patch content for each file.",
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Write *.bak backup before applying patch.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero when any file has L1 errors or patch apply error.",
    )
    return parser.parse_args()


def detect_language(path: Path, override: str | None) -> str:
    if override:
        return override.strip().lower()
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "auto")


def request_file_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def main() -> int:
    args = parse_args()
    mode = ScanMode.FILE if args.mode == "file" else ScanMode.SNIPPET

    service = L1Service()
    scanned = 0
    modified = 0
    findings_total = 0
    failed = 0

    for raw_path in args.files:
        source_path = Path(raw_path).expanduser()
        if not source_path.is_absolute():
            source_path = (Path.cwd() / source_path).resolve()
        if not source_path.exists() or not source_path.is_file():
            failed += 1
            print(f"[ERROR] file not found: {source_path}")
            continue

        code = source_path.read_text(encoding="utf-8")
        language = detect_language(source_path, args.language)
        response = service.scan_annotate(
            L1ScanAnnotateRequest(
                code=code,
                language=language,
                file_path=request_file_path(source_path),
                mode=mode,
            )
        )

        scanned += 1
        findings_count = len(response.findings)
        findings_total += findings_count

        if response.errors:
            print(f"[WARN] {source_path} L1 errors: {response.errors}")
            if args.strict:
                failed += 1

        patch = response.annotation_patch
        if not patch.strip():
            print(f"[SKIP] {source_path} findings={findings_count} patch=empty")
            continue

        if args.print_patch:
            print(f"--- PATCH {source_path} ---")
            print(patch)

        try:
            patched_code = apply_unified_patch(code, patch)
        except PatchApplyError as exc:
            failed += 1
            print(f"[ERROR] patch apply failed: {source_path} ({exc})")
            continue

        if patched_code == code:
            print(f"[SKIP] {source_path} findings={findings_count} patch=no-change")
            continue

        if args.dry_run:
            modified += 1
            print(f"[DRY-RUN] {source_path} findings={findings_count} would_write=yes")
            continue

        if args.backup:
            backup_path = source_path.with_suffix(source_path.suffix + ".bak")
            backup_path.write_text(code, encoding="utf-8")
            print(f"[BACKUP] {backup_path}")

        source_path.write_text(patched_code, encoding="utf-8")
        modified += 1
        print(f"[APPLIED] {source_path} findings={findings_count}")

    print(
        f"[DONE] scanned={scanned} modified={modified} total_findings={findings_total} failed={failed} dry_run={args.dry_run}"
    )

    if args.strict and failed > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
