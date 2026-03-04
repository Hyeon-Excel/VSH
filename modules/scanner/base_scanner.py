from __future__ import annotations

from abc import ABC, abstractmethod

from vsh.core.models import ScanResult


class BaseScanner(ABC):
    """Base contract for all scanners used in the analysis pipeline."""

    @abstractmethod
    def scan(self) -> ScanResult:
        """Run scanner and return structured scan results."""
        raise NotImplementedError
