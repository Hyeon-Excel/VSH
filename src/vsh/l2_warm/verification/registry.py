"""Package registry verification adapter."""

from __future__ import annotations

from vsh.common.models import VerificationRecord, VerificationState


class RegistryVerifier:
    """Checks package existence in package registries.

    TODO:
    - Add adapter for PyPI and npm
    - Batch check package candidates
    """

    def check(self, package_names: list[str]) -> list[VerificationRecord]:
        return [
            VerificationRecord(subject=name, state=VerificationState.UNKNOWN, details="Not implemented.")
            for name in package_names
        ]
