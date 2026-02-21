"""External verification adapters for L2."""

from .osv import OsvVerifier
from .registry import RegistryVerifier

__all__ = ["OsvVerifier", "RegistryVerifier"]
