from .mock_semgrep_scanner import MockSemgrepScanner as SemgrepScanner
from .sbom_scanner import SBOMScanner

__all__ = [
    "SemgrepScanner",
    "TreeSitterScanner",
    "SBOMScanner",
]


def __getattr__(name: str):
    if name == "TreeSitterScanner":
        from .treesitter_scanner import TreeSitterScanner

        return TreeSitterScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
