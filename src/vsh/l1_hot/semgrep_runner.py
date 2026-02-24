"""Semgrep runner for L1 scanning."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class L1ScanError(RuntimeError):
    """Base error for L1 scan failures."""


class L1TimeoutError(L1ScanError):
    """Raised when semgrep invocation times out."""


class L1ToolMissingError(L1ScanError):
    """Raised when semgrep binary is unavailable."""


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    message: str
    severity: str
    cwe: list[str]
    owasp: list[str]
    kisa_key: str | None
    fsec_key: str | None


class SemgrepRunner:
    """Thin wrapper around semgrep CLI with deterministic fallback scanner."""

    _LANG_EXT = {
        "python": ".py",
        "py": ".py",
        "javascript": ".js",
        "js": ".js",
        "typescript": ".ts",
        "ts": ".ts",
        "c": ".c",
        "cpp": ".cpp",
        "c++": ".cpp",
        "iac": ".yaml",
        "auto": ".txt",
    }
    _DEFAULT_TIMEOUT_SEC = 2.0
    _RULESET_VERSION = "l1-rules-v1"

    def run_semgrep(self, code: str, language: str) -> dict[str, Any]:
        if not code.strip():
            return {"results": [], "errors": []}

        normalized_language = language.strip().lower()
        extension = self._LANG_EXT.get(normalized_language, ".txt")
        root = Path(__file__).resolve().parents[3]
        rules_path = root / "rules" / "l1"

        with tempfile.TemporaryDirectory(prefix="vsh_l1_") as temp_dir:
            source_path = Path(temp_dir) / f"snippet{extension}"
            source_path.write_text(code, encoding="utf-8")

            if rules_path.is_dir():
                try:
                    return self._run_semgrep_cli(
                        target_path=source_path,
                        rules_path=rules_path,
                        temp_dir=Path(temp_dir),
                        timeout_sec=self._DEFAULT_TIMEOUT_SEC,
                    )
                except L1ToolMissingError:
                    return self._run_fallback(source_path=source_path, language=normalized_language)
                except L1TimeoutError:
                    return self._run_fallback(source_path=source_path, language=normalized_language)
                except L1ScanError:
                    return self._run_fallback(source_path=source_path, language=normalized_language)

            return self._run_fallback(source_path=source_path, language=normalized_language)

    @classmethod
    def ruleset_version(cls) -> str:
        return cls._RULESET_VERSION

    @staticmethod
    def _run_semgrep_cli(
        target_path: Path,
        rules_path: Path,
        temp_dir: Path,
        timeout_sec: float,
    ) -> dict[str, Any]:
        semgrep_bin = SemgrepRunner._resolve_semgrep_binary()
        if semgrep_bin is None:
            raise L1ToolMissingError("L1_TOOL_MISSING: semgrep CLI not found.")

        command = [
            semgrep_bin,
            "--metrics",
            "off",
            "--disable-version-check",
            "--config",
            str(rules_path),
            "--json",
            "--no-git-ignore",
            "--quiet",
            str(target_path),
        ]
        env = SemgrepRunner._build_semgrep_env(temp_dir=temp_dir)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=timeout_sec,
            )
        except FileNotFoundError as exc:
            raise L1ToolMissingError("L1_TOOL_MISSING: semgrep CLI not found.") from exc
        except subprocess.TimeoutExpired as exc:
            raise L1TimeoutError(f"L1_TIMEOUT: semgrep exceeded {timeout_sec:.1f}s.") from exc

        stdout = completed.stdout.strip()
        if completed.returncode not in (0, 1):
            stderr = completed.stderr.strip()
            raise L1ScanError(f"L1_SCAN_FAILED: semgrep exit={completed.returncode} {stderr}".strip())
        if not stdout:
            return {"results": [], "errors": []}
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise L1ScanError("L1_SCAN_FAILED: semgrep returned invalid JSON.") from exc
        if isinstance(payload, dict):
            payload.setdefault("engine", "semgrep-cli")
            return payload
        raise L1ScanError("L1_SCAN_FAILED: semgrep output was not a JSON object.")

    @staticmethod
    def _resolve_semgrep_binary() -> str | None:
        env_bin = os.getenv("SEMGREP_BIN")
        if env_bin:
            return env_bin

        direct = shutil.which("semgrep")
        if direct:
            return direct

        root = Path(__file__).resolve().parents[3]
        local = root / ".venv" / "bin" / "semgrep"
        if local.exists():
            return str(local)
        return None

    @staticmethod
    def _build_semgrep_env(temp_dir: Path) -> dict[str, str]:
        env = os.environ.copy()
        env["SEMGREP_SETTINGS_FILE"] = str(temp_dir / "semgrep.settings.yml")
        env["SEMGREP_LOG_FILE"] = str(temp_dir / "semgrep.log")
        env["XDG_CONFIG_HOME"] = str(temp_dir / "xdg")
        env["SEMGREP_VERSION_CACHE_PATH"] = str(temp_dir / "semgrep.version.cache")
        env["SEMGREP_SEND_METRICS"] = "off"
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        certifi_path = SemgrepRunner._certifi_bundle_path()
        if certifi_path:
            env.setdefault("SSL_CERT_FILE", certifi_path)
        return env

    @staticmethod
    def _certifi_bundle_path() -> str | None:
        try:
            import certifi

            return str(certifi.where())
        except Exception:
            return None

    @staticmethod
    def _run_fallback(source_path: Path, language: str) -> dict[str, Any]:
        source_text = source_path.read_text(encoding="utf-8")
        lines = source_text.splitlines()
        results: list[dict[str, Any]] = []

        sqli_meta = RuleMetadata(
            rule_id="vsh.python.sqli.fstring",
            message="Potential SQL injection via string interpolation.",
            severity="HIGH",
            cwe=["CWE-89"],
            owasp=["A03"],
            kisa_key="INPUT_VALIDATION_1",
            fsec_key="WEB_3_1",
        )
        xss_meta = RuleMetadata(
            rule_id="vsh.js.xss.innerhtml",
            message="Potential XSS via innerHTML assignment.",
            severity="HIGH",
            cwe=["CWE-79"],
            owasp=["A03"],
            kisa_key="OUTPUT_ENCODING_1",
            fsec_key="WEB_3_2",
        )
        secret_meta = RuleMetadata(
            rule_id="vsh.common.secret.hardcoded",
            message="Potential hardcoded secret detected.",
            severity="HIGH",
            cwe=["CWE-798"],
            owasp=["A02"],
            kisa_key="SECRETS_MANAGEMENT_1",
            fsec_key="COMMON_1_1",
        )

        if language in {"python", "py", "auto"}:
            query_line = None
            execute_line = None
            for index, line in enumerate(lines, start=1):
                if re.search(r"f[\"'].*SELECT.*\{.+\}.*[\"']", line, re.IGNORECASE):
                    query_line = index
                if re.search(r"\.execute\(\s*query\b", line):
                    execute_line = index
            if query_line and execute_line:
                results.append(
                    SemgrepRunner._build_result(
                        source_path=source_path,
                        line_no=query_line,
                        line_text=lines[query_line - 1],
                        metadata=sqli_meta,
                    )
                )

        if language in {"javascript", "js", "typescript", "ts", "auto"}:
            for index, line in enumerate(lines, start=1):
                if re.search(r"\.innerHTML\s*=", line):
                    results.append(
                        SemgrepRunner._build_result(
                            source_path=source_path,
                            line_no=index,
                            line_text=line,
                            metadata=xss_meta,
                        )
                    )

        for index, line in enumerate(lines, start=1):
            if re.search(
                r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",
                line,
            ):
                results.append(
                    SemgrepRunner._build_result(
                        source_path=source_path,
                        line_no=index,
                        line_text=line,
                        metadata=secret_meta,
                    )
                )

        return {"results": results, "errors": [], "engine": "fallback"}

    @staticmethod
    def _build_result(source_path: Path, line_no: int, line_text: str, metadata: RuleMetadata) -> dict[str, Any]:
        end_col = max(1, len(line_text) + 1)
        return {
            "check_id": metadata.rule_id,
            "path": str(source_path),
            "start": {"line": line_no, "col": 1, "offset": 0},
            "end": {"line": line_no, "col": end_col, "offset": 0},
            "extra": {
                "message": metadata.message,
                "metadata": {
                    "severity": metadata.severity,
                    "cwe": metadata.cwe,
                    "owasp": metadata.owasp,
                    "kisa_key": metadata.kisa_key,
                    "fsec_key": metadata.fsec_key,
                    "category": "CODE",
                },
            },
        }
