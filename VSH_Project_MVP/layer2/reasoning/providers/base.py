from __future__ import annotations

from abc import ABC, abstractmethod


class ReasoningProvider(ABC):
    name = "base"
    model_name = None

    @abstractmethod
    def reason(self, vuln_record: dict, context: dict) -> dict:
        raise NotImplementedError
