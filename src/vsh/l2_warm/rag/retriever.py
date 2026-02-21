"""Evidence retrieval abstraction."""

from __future__ import annotations


class EvidenceRetriever:
    """Retrieves policy evidence by keys and tags.

    TODO:
    - Add ChromaDB client
    - Implement key-priority retrieval
    """

    def lookup(self, kisa_key: str | None, fsec_key: str | None) -> list[str]:
        del kisa_key, fsec_key
        return []
