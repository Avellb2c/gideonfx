from __future__ import annotations

"""TLS helpers for GIDEON private PKI.

GIDEON does not import its private CA into the operating-system trust store.  Older
GIDEON roots issued before RC17 do not contain all RFC 5280 identifier extensions
that OpenSSL 3.5 / Python 3.14 expects when X509_STRICT is enabled by
``create_default_context``.  The compatibility context below still enforces CA
trust, certificate signatures, validity, hostname verification and TLS >= 1.2;
it only disables the optional X509_STRICT extension-profile check for GIDEON's
private CA.  Public-PKI contexts must continue to use normal strict defaults.
"""

import ssl
from pathlib import Path
from typing import Optional


def _clear_x509_strict(context: ssl.SSLContext) -> ssl.SSLContext:
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    if strict:
        try:
            context.verify_flags = context.verify_flags & ~strict
        except (AttributeError, ValueError):
            pass
    return context


def gideon_private_ca_context(
    ca_file: str | Path,
    *,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
) -> ssl.SSLContext:
    """Return a verified TLS client context for the GIDEON private CA.

    This is deliberately *not* an unverified context.  It preserves certificate
    chain validation and hostname checks while allowing legacy GIDEON certificates
    that predate SKI/AKI hardening.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(Path(ca_file)))
    _clear_x509_strict(context)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_cert:
        context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key) if client_key else None)
    return context


__all__ = ["gideon_private_ca_context"]
