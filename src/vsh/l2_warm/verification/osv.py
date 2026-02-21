"""OSV verification adapter."""

from __future__ import annotations

from vsh.common.models import VerificationRecord, VerificationState


class OsvVerifier:
    """Queries OSV for known vulnerabilities.

    TODO:
    - Implement querybatch payload build
    - Parse response into normalized records
    """

    def check(self, package_purls: list[str]) -> list[VerificationRecord]:
        return [
            VerificationRecord(subject=purl, state=VerificationState.UNKNOWN, details="Not implemented.")
            for purl in package_purls
        ]
