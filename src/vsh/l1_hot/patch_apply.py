"""Apply unified diff patches for L1 annotation flow."""

from __future__ import annotations

import re


class PatchApplyError(RuntimeError):
    """Raised when unified diff patch cannot be applied safely."""


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified_patch(original_text: str, patch_text: str) -> str:
    """Apply a unified diff patch against original_text and return patched text.

    This function expects a standard unified diff with `---`, `+++`, and one or more
    `@@` hunks. It validates context lines and fails fast on mismatch.
    """
    if not patch_text.strip():
        return original_text

    patch_lines = patch_text.splitlines()
    if len(patch_lines) < 3 or not patch_lines[0].startswith("--- ") or not patch_lines[1].startswith("+++ "):
        raise PatchApplyError("Invalid unified diff header.")

    source_lines = original_text.splitlines()
    output_lines: list[str] = []
    source_index = 0
    line_index = 2

    while line_index < len(patch_lines):
        header = patch_lines[line_index]
        if not header.startswith("@@ "):
            line_index += 1
            continue
        match = _HUNK_HEADER_RE.match(header)
        if not match:
            raise PatchApplyError(f"Invalid hunk header: {header}")

        old_start = int(match.group(1))
        old_start_index = old_start - 1
        if old_start_index < source_index:
            raise PatchApplyError("Overlapping or out-of-order hunks are not supported.")

        output_lines.extend(source_lines[source_index:old_start_index])
        source_index = old_start_index
        line_index += 1

        while line_index < len(patch_lines):
            hunk_line = patch_lines[line_index]
            if hunk_line.startswith("@@ "):
                break
            if not hunk_line:
                prefix = " "
                payload = ""
            else:
                prefix = hunk_line[0]
                payload = hunk_line[1:]

            if prefix == " ":
                _assert_source_line(source_lines, source_index, payload)
                output_lines.append(payload)
                source_index += 1
            elif prefix == "-":
                _assert_source_line(source_lines, source_index, payload)
                source_index += 1
            elif prefix == "+":
                output_lines.append(payload)
            elif hunk_line.startswith("\\ No newline at end of file"):
                pass
            else:
                raise PatchApplyError(f"Unsupported hunk line prefix: {prefix}")
            line_index += 1

    output_lines.extend(source_lines[source_index:])

    patched = "\n".join(output_lines)
    if original_text.endswith("\n"):
        patched += "\n"
    return patched


def _assert_source_line(source_lines: list[str], index: int, expected: str) -> None:
    if index >= len(source_lines):
        raise PatchApplyError("Patch references line beyond source length.")
    actual = source_lines[index]
    if actual != expected:
        raise PatchApplyError(
            f"Patch context mismatch at line {index + 1}: expected={expected!r}, actual={actual!r}"
        )
