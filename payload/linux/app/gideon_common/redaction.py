from __future__ import annotations

"""Secret redaction helpers shared by GIDEON runtimes and Web diagnostics.

The diagnostic surface intentionally reports operational detail, but it must
never expose reusable credentials.  These helpers are dependency-free so they
can travel inside every standalone Agent package.
"""

import re
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***REDACTED***"

# Key matching is deliberately broad.  False positives are preferable to a
# bearer/bootstrap/private key leaking into a copied diagnostic bundle.
_SENSITIVE_KEY_PARTS = (
    "password", "passwd", "passphrase", "secret", "token", "authorization",
    "cookie", "api_key", "apikey", "private_key", "privatekey", "credential",
    "bearer", "bootstrap", "totp", "mfa_code", "recovery_code", "client_key",
)

# Common text forms observed in JSON, env/config output and HTTP traces.
_BEARER_RE = re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+\-/=]{8,}")
_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:\s*).*$"
)
_ASSIGN_RE = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|credential|"
    r"enrollment[_-]?secret|bootstrap[_-]?(?:token|grant)|totp|mfa[_-]?code|recovery[_-]?code|client[_-]?key)\b\s*[=:]\s*)"
    r"([^\s,;]+|\"[^\"]*\"|'[^']*')"
)
_JSON_RE = re.compile(
    r"(?i)(\"(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|credential|"
    r"enrollment[_-]?secret|bootstrap[_-]?(?:token|grant)|totp|mfa[_-]?code|recovery[_-]?code|client[_-]?key)\"\s*:\s*)"
    r"(\"(?:\\.|[^\"])*\"|null|true|false|-?\d+(?:\.\d+)?)"
)
_PEM_PRIVATE_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.I | re.S,
)


def is_sensitive_key(key: Any) -> bool:
    low = str(key or "").strip().lower().replace("-", "_")
    return any(part in low for part in _SENSITIVE_KEY_PARTS)


def redact_url(value: str) -> str:
    """Remove userinfo/query/fragment from a URL while preserving routing data."""
    raw = str(value or "")
    try:
        parsed = urlsplit(raw)
    except Exception:
        return raw
    if not parsed.scheme or not parsed.netloc:
        return raw
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, host + port, parsed.path, "", ""))


def redact_text(value: Any) -> str:
    text = str(value if value is not None else "")
    text = _PEM_PRIVATE_RE.sub(REDACTED, text)
    text = _BEARER_RE.sub(r"\1 " + REDACTED, text)
    text = _HEADER_RE.sub(r"\1" + REDACTED, text)
    text = _JSON_RE.sub(lambda m: m.group(1) + '"' + REDACTED + '"', text)
    text = _ASSIGN_RE.sub(lambda m: m.group(1) + REDACTED, text)
    return text


def redact(value: Any, key: Any = "") -> Any:
    if is_sensitive_key(key):
        if value in (None, "", [], {}):
            return value
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): redact(v, k) for k, v in value.items()}
    if isinstance(value, tuple):
        return [redact(v, key) for v in value]
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        # URLs are useful diagnostics, but credentials/query strings are not.
        if value.lower().startswith(("http://", "https://")):
            value = redact_url(value)
        return redact_text(value)
    return value


def redact_error(value: Any, *, max_chars: int = 16000) -> str:
    text = redact_text(value)
    if len(text) > max_chars:
        return text[: max_chars - 32] + "\n...[TRUNCATED BY GIDEON]..."
    return text


__all__ = ["REDACTED", "is_sensitive_key", "redact", "redact_error", "redact_text", "redact_url"]
