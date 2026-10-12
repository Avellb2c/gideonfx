"""Content-addressed static asset URLs for the WebAdmin UI.

The WebAdmin HTML is deliberately never cached.  This helper lets only files
whose content has been fingerprinted receive immutable browser caching, which
prevents an older JavaScript bundle from being used with newly deployed HTML.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
from pathlib import Path
from urllib.parse import quote


class StaticAssetUrls:
    """Resolve package-owned static files to safe fingerprinted URLs."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self._cache: dict[str, tuple[int, int, str]] = {}
        self._lock = threading.Lock()

    def url(self, asset_name: str) -> str:
        clean_name, target = self._target(asset_name)
        if target is None:
            # The caller is a package-controlled template.  A missing optional
            # file remains revalidated instead of being cached indefinitely.
            return "/static/" + quote(clean_name, safe="/")
        return "/static/" + quote(clean_name, safe="/") + "?v=" + self._fingerprint(clean_name, target)

    def matches(self, asset_name: str, fingerprint: str) -> bool:
        """Return whether an immutable-cache query belongs to current bytes.

        Do not give a manually invented 16-character query an immutable cache
        lifetime.  This protects a deployment from an accidental old URL even
        when an operator bookmarks a static file directly.
        """
        try:
            clean_name, target = self._target(asset_name)
        except ValueError:
            return False
        if target is None:
            return False
        return hmac.compare_digest(self._fingerprint(clean_name, target), str(fingerprint or ""))

    def _target(self, asset_name: str) -> tuple[str, Path | None]:
        clean_name = str(asset_name or "").replace("\\", "/").lstrip("/")
        if not clean_name or ".." in Path(clean_name).parts:
            raise ValueError("Activo estático inválido.")
        target = (self.root / clean_name).resolve()
        if self.root not in target.parents or not target.is_file():
            return clean_name, None
        return clean_name, target

    def _fingerprint(self, clean_name: str, target: Path) -> str:
        stat = target.stat()
        cached = self._cache.get(clean_name)
        if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
            return cached[2]
        else:
            fingerprint = hashlib.sha256(target.read_bytes()).hexdigest()[:16]
            with self._lock:
                self._cache[clean_name] = (stat.st_mtime_ns, stat.st_size, fingerprint)
        return fingerprint
