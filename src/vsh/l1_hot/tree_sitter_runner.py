"""Tree-sitter based import extraction for L1 supply-chain candidates."""

from __future__ import annotations

import re
from typing import Any

from vsh.common.models import SupplyChainCandidate

try:
    from tree_sitter_languages import get_parser
except Exception:  # pragma: no cover - optional dependency
    try:
        from tree_sitter_language_pack import get_parser
    except Exception:
        get_parser = None  # type: ignore[assignment]


class TreeSitterRunnerError(RuntimeError):
    """Raised when Tree-sitter scanning fails unexpectedly."""


class TreeSitterRunner:
    _LANGUAGE_MAP = {
        "python": "python",
        "py": "python",
        "javascript": "javascript",
        "js": "javascript",
        "typescript": "typescript",
        "ts": "typescript",
    }

    def run_tree_sitter(self, code: str, language: str) -> list[SupplyChainCandidate]:
        if not code.strip():
            return []

        normalized_language = language.strip().lower()
        ts_language = self._LANGUAGE_MAP.get(normalized_language)
        if ts_language is None:
            return self._run_regex_fallback(code=code, language=normalized_language)

        parser = self._build_parser(ts_language)
        if parser is None:
            return self._run_regex_fallback(code=code, language=normalized_language)

        try:
            code_bytes = code.encode("utf-8")
            tree = parser.parse(code_bytes)
            return self._extract_candidates_from_tree(
                root_node=tree.root_node,
                code_bytes=code_bytes,
                language=ts_language,
            )
        except Exception as exc:  # pragma: no cover - defensive path
            raise TreeSitterRunnerError(f"L1_TREE_SITTER_FAILED: {exc}") from exc

    @staticmethod
    def _build_parser(language: str) -> Any | None:
        if get_parser is None:
            return None
        try:
            return get_parser(language)
        except Exception:
            return None

    def _extract_candidates_from_tree(
        self,
        root_node: Any,
        code_bytes: bytes,
        language: str,
    ) -> list[SupplyChainCandidate]:
        if language == "python":
            return self._extract_python_candidates_from_tree(root_node, code_bytes)
        if language in {"javascript", "typescript"}:
            return self._extract_jsts_candidates_from_tree(root_node, code_bytes)
        return []

    def _extract_python_candidates_from_tree(
        self,
        root_node: Any,
        code_bytes: bytes,
    ) -> list[SupplyChainCandidate]:
        packages: dict[str, SupplyChainCandidate] = {}
        for node in self._walk(root_node):
            if node.type not in {"import_statement", "import_from_statement"}:
                continue
            statement = code_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")
            line = node.start_point[0] + 1 if node.start_point else None
            for package in self._parse_python_import_statement(statement):
                packages.setdefault(
                    package,
                    SupplyChainCandidate(
                        package_name=package,
                        line=line,
                        source_type="import",
                        extraction_method="tree-sitter",
                    ),
                )
        return sorted(packages.values(), key=lambda item: item.package_name)

    def _extract_jsts_candidates_from_tree(
        self,
        root_node: Any,
        code_bytes: bytes,
    ) -> list[SupplyChainCandidate]:
        packages: dict[str, SupplyChainCandidate] = {}
        for node in self._walk(root_node):
            if node.type not in {"import_statement", "call_expression"}:
                continue
            statement = code_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")
            line = node.start_point[0] + 1 if node.start_point else None
            for package in self._parse_jsts_import_statement(statement):
                packages.setdefault(
                    package,
                    SupplyChainCandidate(
                        package_name=package,
                        line=line,
                        source_type="import",
                        extraction_method="tree-sitter",
                    ),
                )
        return sorted(packages.values(), key=lambda item: item.package_name)

    @staticmethod
    def _walk(root_node: Any) -> list[Any]:
        stack = [root_node]
        nodes: list[Any] = []
        while stack:
            node = stack.pop()
            nodes.append(node)
            children = getattr(node, "children", [])
            if children:
                stack.extend(reversed(children))
        return nodes

    @staticmethod
    def _parse_python_import_statement(statement: str) -> list[str]:
        statement = statement.strip()
        if statement.startswith("import "):
            modules = statement[len("import ") :].split(",")
            packages = []
            for module in modules:
                root = module.strip().split(" as ")[0].strip().split(".")[0]
                if root:
                    packages.append(root)
            return packages
        if statement.startswith("from "):
            module = statement[len("from ") :].split(" import ", maxsplit=1)[0].strip()
            root = module.split(".")[0]
            return [root] if root else []
        return []

    @staticmethod
    def _parse_jsts_import_statement(statement: str) -> list[str]:
        packages = []
        for pattern in (
            r"""from\s+["']([^"']+)["']""",
            r"""import\s+["']([^"']+)["']""",
            r"""require\(\s*["']([^"']+)["']\s*\)""",
        ):
            packages.extend(re.findall(pattern, statement))
        return [package for package in packages if package]

    def _run_regex_fallback(self, code: str, language: str) -> list[SupplyChainCandidate]:
        candidates: dict[str, SupplyChainCandidate] = {}
        lines = code.splitlines()

        if language in {"python", "py", "auto"}:
            for line_no, line in enumerate(lines, start=1):
                for package in self._parse_python_import_statement(line.strip()):
                    candidates.setdefault(
                        package,
                        SupplyChainCandidate(
                            package_name=package,
                            line=line_no,
                            source_type="import",
                            extraction_method="regex-fallback",
                        ),
                    )

        if language in {"javascript", "js", "typescript", "ts", "auto"}:
            for line_no, line in enumerate(lines, start=1):
                for package in self._parse_jsts_import_statement(line.strip()):
                    candidates.setdefault(
                        package,
                        SupplyChainCandidate(
                            package_name=package,
                            line=line_no,
                            source_type="import",
                            extraction_method="regex-fallback",
                        ),
                    )

        return sorted(candidates.values(), key=lambda item: item.package_name)
