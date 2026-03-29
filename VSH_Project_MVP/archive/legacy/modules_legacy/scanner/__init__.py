from layer1.scanner import SBOMScanner
from layer1.scanner import SemgrepScanner

__all__ = [
    "SemgrepScanner",
    "VSHL1Scanner",
    "TreeSitterScanner",
    "SBOMScanner",
]


def __getattr__(name: str):
    if name == "VSHL1Scanner":
        from layer1.scanner import VSHL1Scanner

        return VSHL1Scanner
    if name == "TreeSitterScanner":
        from layer1.scanner import TreeSitterScanner

        return TreeSitterScanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
