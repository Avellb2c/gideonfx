"""Shared low-level helpers used by the desktop application.

Standalone Agent/Gateway deployables intentionally keep tiny local fallbacks so
an already-installed endpoint never depends on the whole desktop package.
"""

from .clock import now_iso
from .hashing import sha256_file
from .process import windows_hidden_kwargs

__all__ = ["now_iso", "sha256_file", "windows_hidden_kwargs"]
