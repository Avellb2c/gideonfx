from __future__ import annotations

"""TLS lifecycle and verification for the GIDEON Agent Gateway.

The root CA is intentionally long lived and stable.  Normal host/IP changes only
re-issue the server certificate; they never rotate the root trust anchor.  This
prevents already-deployed agents from losing trust when the Gateway endpoint is
reconfigured.

The module contains no Qt code and no process-management code (SRP).  It owns
only certificate material, chain validation and network TLS probes.
"""

from dataclasses import dataclass
import datetime as dt
import hashlib
import ipaddress
import logging
import os
from pathlib import Path
import socket
import ssl
from typing import Iterable
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CA_CERT_NAME = "gideon_gateway_ca.pem"
CA_KEY_NAME = "gideon_gateway_ca.key"
SERVER_CERT_NAME = "gideon_gateway_server.pem"
SERVER_KEY_NAME = "gideon_gateway_server.key"
TRUST_BUNDLE_NAME = "gideon_gateway_trust_bundle.pem"
TLS_STATE_NAME = "tls-state.json"


@dataclass(frozen=True)
class TLSMaterial:
    ca_file: str
    cert_file: str
    key_file: str
    trust_bundle_file: str
    ca_fingerprint: str
    cert_fingerprint: str
    ca_created: bool = False
    cert_reissued: bool = False


@dataclass(frozen=True)
class TLSProbe:
    ok: bool
    category: str
    detail: str
    peer_fingerprint: str = ""
    protocol: str = ""
    cipher: str = ""


_LOG = logging.getLogger(__name__)

def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex().upper()


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _not_before(cert: x509.Certificate) -> dt.datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert.not_valid_before.replace(tzinfo=dt.timezone.utc)


def _not_after(cert: x509.Certificate) -> dt.datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _public_key_bytes(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _key_matches_cert(key, cert: x509.Certificate) -> bool:
    try:
        return _public_key_bytes(key.public_key()) == _public_key_bytes(cert.public_key())
    except Exception:
        return False


def _verify_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        public_key = issuer.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:
        return False


def _valid_ca_pair(cert: x509.Certificate, key) -> bool:
    try:
        if cert.issuer != cert.subject:
            return False
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not basic.ca:
            return False
        if not _key_matches_cert(key, cert):
            return False
        if not _verify_signed_by(cert, cert):
            return False
        now = _now_utc()
        return _not_before(cert) <= now < _not_after(cert)
    except Exception:
        return False


def _host_matches_san(cert: x509.Certificate, host: str) -> bool:
    host = str(host or "").strip().strip("[]")
    if not host:
        return False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        expected_ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        expected_ip = None
    if expected_ip is not None:
        return expected_ip in san.get_values_for_type(x509.IPAddress)
    expected_dns = host.rstrip(".").casefold()
    for value in san.get_values_for_type(x509.DNSName):
        if value.rstrip(".").casefold() == expected_dns:
            return True
    return False


def _valid_server_pair(
    cert: x509.Certificate,
    key,
    ca_cert: x509.Certificate,
    host: str,
    *,
    renew_before_days: int = 30,
) -> bool:
    try:
        if cert.issuer != ca_cert.subject:
            return False
        if not _verify_signed_by(cert, ca_cert):
            return False
        if not _key_matches_cert(key, cert):
            return False
        if not _host_matches_san(cert, host):
            return False
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if basic.ca:
            return False
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            return False
        now = _now_utc()
        if not (_not_before(cert) <= now < _not_after(cert)):
            return False
        if _not_after(cert) <= now + dt.timedelta(days=max(1, int(renew_before_days))):
            return False
        return True
    except Exception:
        return False


def _atomic_bytes(path: Path, data: bytes, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_bytes(data)
    if mode is not None:
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
    os.replace(tmp, path)
    if mode is not None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _unique_names(names: Iterable[x509.GeneralName]) -> list[x509.GeneralName]:
    result: list[x509.GeneralName] = []
    seen: set[tuple[str, str]] = set()
    for item in names:
        key = (type(item).__name__, str(item.value))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


class GatewayTLSLifecycle:
    """Stable-root certificate lifecycle for the Gateway."""

    def __init__(self, tls_dir: str | Path) -> None:
        self.tls_dir = Path(tls_dir).resolve()
        self.ca_cert_path = self.tls_dir / CA_CERT_NAME
        self.ca_key_path = self.tls_dir / CA_KEY_NAME
        self.server_cert_path = self.tls_dir / SERVER_CERT_NAME
        self.server_key_path = self.tls_dir / SERVER_KEY_NAME
        self.trust_bundle_path = self.tls_dir / TRUST_BUNDLE_NAME
        self.previous_dir = self.tls_dir / "previous-ca"

    def _create_ca(self) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        now = _now_utc()
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GIDEON Remote Control"),
                x509.NameAttribute(NameOID.COMMON_NAME, "GIDEON Agent Gateway Root CA"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        _atomic_bytes(
            self.ca_key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
            mode=0o600,
        )
        _atomic_bytes(self.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM))
        return cert, key

    def _archive_existing_ca(self) -> None:
        if not self.ca_cert_path.is_file():
            return
        try:
            cert = _load_cert(self.ca_cert_path)
            fp = cert_fingerprint(cert)[:16]
            self.previous_dir.mkdir(parents=True, exist_ok=True)
            target = self.previous_dir / f"gideon_gateway_ca_{fp}.pem"
            if not target.exists():
                target.write_bytes(self.ca_cert_path.read_bytes())
        except Exception as exc:
            _LOG.warning("No se pudo archivar la CA anterior: %s", exc)

    def _load_or_create_ca(self, *, rotate_ca: bool = False) -> tuple[x509.Certificate, object, bool]:
        self.tls_dir.mkdir(parents=True, exist_ok=True)
        if rotate_ca:
            self._archive_existing_ca()
            cert, key = self._create_ca()
            return cert, key, True

        cert_exists = self.ca_cert_path.is_file()
        key_exists = self.ca_key_path.is_file()
        if cert_exists and key_exists:
            try:
                cert = _load_cert(self.ca_cert_path)
                key = _load_private_key(self.ca_key_path)
                if _valid_ca_pair(cert, key):
                    return cert, key, False
            except Exception as exc:
                _LOG.warning("La CA persistente no pudo validarse: %s", exc)
            raise RuntimeError(
                "TLS_CA_INVALID: la CA persistente existe pero su certificado/clave no forman "
                "un par valido. GIDEON no rotara la CA automaticamente porque invalidaria la "
                "confianza de agentes ya instalados. Restaure el respaldo de la CA o ejecute "
                "una rotacion explicita y redistribuya la nueva confianza."
            )

        if cert_exists != key_exists:
            missing = "clave privada" if cert_exists else "certificado raiz"
            raise RuntimeError(
                f"TLS_CA_INCOMPLETE: falta {missing} de la CA persistente. GIDEON no creara una "
                "CA nueva automaticamente porque invalidaria agentes existentes. Restaure el "
                "par original o realice una rotacion explicita controlada."
            )

        # Clean installation only: neither part of the trust anchor exists yet.
        cert, key = self._create_ca()
        return cert, key, True

    def _issue_server(
        self,
        *,
        host: str,
        ca_cert: x509.Certificate,
        ca_key,
        local_addresses: Iterable[str] = (),
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        now = _now_utc()
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        host_clean = str(host or "").strip().strip("[]")
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GIDEON Remote Control"),
                x509.NameAttribute(NameOID.COMMON_NAME, host_clean),
            ]
        )
        names: list[x509.GeneralName] = []
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host_clean.split("%", 1)[0])))
        except ValueError:
            names.append(x509.DNSName(host_clean))
        for value in local_addresses:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(str(value).split("%", 1)[0])))
            except ValueError:
                continue
        names.extend([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        names = _unique_names(names)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        _atomic_bytes(
            self.server_key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
            mode=0o600,
        )
        _atomic_bytes(self.server_cert_path, cert.public_bytes(serialization.Encoding.PEM))
        return cert, key

    def _write_trust_bundle(self, current_ca: x509.Certificate) -> None:
        # Current root first.  Previous roots are retained only so newly generated
        # transition packages can still diagnose/communicate with a stale runtime
        # while it is being restarted.  Normal leaf renewal never adds a new root.
        parts = [current_ca.public_bytes(serialization.Encoding.PEM)]
        if self.previous_dir.is_dir():
            for path in sorted(self.previous_dir.glob("*.pem"), reverse=True)[:2]:
                try:
                    old = _load_cert(path)
                    if cert_fingerprint(old) != cert_fingerprint(current_ca):
                        parts.append(old.public_bytes(serialization.Encoding.PEM))
                except Exception:
                    continue
        _atomic_bytes(self.trust_bundle_path, b"".join(parts))

    def ensure(
        self,
        host: str,
        *,
        force_leaf: bool = False,
        rotate_ca: bool = False,
        local_addresses: Iterable[str] = (),
    ) -> TLSMaterial:
        host_clean = str(host or "").strip().strip("[]")
        if not host_clean:
            raise ValueError("Gateway TLS requires a host/IP")
        ca_cert, ca_key, ca_created = self._load_or_create_ca(rotate_ca=rotate_ca)

        cert_reissued = False
        server_cert = None
        server_key = None
        if self.server_cert_path.is_file() and self.server_key_path.is_file():
            try:
                server_cert = _load_cert(self.server_cert_path)
                server_key = _load_private_key(self.server_key_path)
            except Exception:
                server_cert = None
                server_key = None
        valid_leaf = bool(
            server_cert
            and server_key
            and _valid_server_pair(server_cert, server_key, ca_cert, host_clean)
        )
        if force_leaf or ca_created or not valid_leaf:
            server_cert, server_key = self._issue_server(
                host=host_clean,
                ca_cert=ca_cert,
                ca_key=ca_key,
                local_addresses=local_addresses,
            )
            cert_reissued = True

        assert server_cert is not None
        self._write_trust_bundle(ca_cert)
        return TLSMaterial(
            # Agents and health checks pin the single active root CA.  A transition
            # trust bundle is maintained separately for controlled CA rotations,
            # but it must never become the default trust anchor because a stale
            # bundle can make a healthy leaf look unrelated to the configured CA.
            ca_file=str(self.ca_cert_path),
            cert_file=str(self.server_cert_path),
            key_file=str(self.server_key_path),
            trust_bundle_file=str(self.trust_bundle_path),
            ca_fingerprint=cert_fingerprint(ca_cert),
            cert_fingerprint=cert_fingerprint(server_cert),
            ca_created=ca_created,
            cert_reissued=cert_reissued,
        )

    def validate_material(self, host: str) -> TLSProbe:
        try:
            ca = _load_cert(self.ca_cert_path)
            ca_key = _load_private_key(self.ca_key_path)
            server = _load_cert(self.server_cert_path)
            server_key = _load_private_key(self.server_key_path)
        except FileNotFoundError as exc:
            return TLSProbe(False, "TLS_FILE_MISSING", f"Falta material TLS: {exc.filename}")
        except Exception as exc:
            return TLSProbe(False, "TLS_FILE_INVALID", f"No se pudo leer material TLS: {type(exc).__name__}: {exc}")
        if not _valid_ca_pair(ca, ca_key):
            return TLSProbe(False, "TLS_CA_INVALID", "La CA raíz o su clave privada no forman un par válido.")
        if not _valid_server_pair(server, server_key, ca, host, renew_before_days=1):
            return TLSProbe(False, "TLS_SERVER_INVALID", "El certificado servidor no coincide con la CA, la clave, el host/SAN o su vigencia.")
        return TLSProbe(
            True,
            "OK",
            f"CA {cert_fingerprint(ca)[:16]}… · servidor {cert_fingerprint(server)[:16]}…",
            peer_fingerprint=cert_fingerprint(server),
        )


def probe_tls_peer(base_url: str, *, timeout: float = 3.0) -> TLSProbe:
    """Inspect the live leaf certificate without trusting it.

    This is diagnostics-only.  It never authorizes an agent or API request.  Its
    purpose is to distinguish "the live process serves a stale certificate" from
    "the configured CA cannot validate the configured certificate".
    """
    try:
        parsed = urlparse(str(base_url or "").strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return TLSProbe(False, "TLS_URL", "El Gateway debe usar una URL https:// válida.")
        host = str(parsed.hostname)
        port = int(parsed.port or 443)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                fp = hashlib.sha256(der or b"").hexdigest().upper() if der else ""
                cipher = tls.cipher()
                return TLSProbe(
                    True,
                    "UNVERIFIED",
                    f"Peer TLS {tls.version()} · cert {fp[:16]}… (solo diagnóstico; no confiado)",
                    peer_fingerprint=fp,
                    protocol=str(tls.version() or ""),
                    cipher=str(cipher[0] if cipher else ""),
                )
    except (ConnectionError, TimeoutError, OSError) as exc:
        return TLSProbe(False, "TLS_CONNECTIVITY", f"{type(exc).__name__}: {exc}")
    except Exception as exc:
        return TLSProbe(False, "TLS_ERROR", f"{type(exc).__name__}: {exc}")


def probe_tls_endpoint(base_url: str, *, ca_file: str | Path, timeout: float = 3.0) -> TLSProbe:
    """Verify the live Gateway endpoint using the exact trust bundle shipped to agents."""
    try:
        parsed = urlparse(str(base_url or "").strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return TLSProbe(False, "TLS_URL", "El Gateway debe usar una URL https:// válida.")
        host = str(parsed.hostname)
        port = int(parsed.port or 443)
        ca_path = Path(ca_file)
        if not ca_path.is_file():
            return TLSProbe(False, "TLS_CA_MISSING", f"No existe la CA/bundle: {ca_path}")
        # Private-PKI validation uses only the exact GIDEON CA file.  No import into
        # the OS Trusted Root store is required for GIDEON Remote Control or its agents.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(ca_path))
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                fp = hashlib.sha256(der or b"").hexdigest().upper() if der else ""
                cipher = tls.cipher()
                return TLSProbe(
                    True,
                    "OK",
                    f"TLS {tls.version()} · {cipher[0] if cipher else '-'} · cert {fp[:16]}…",
                    peer_fingerprint=fp,
                    protocol=str(tls.version() or ""),
                    cipher=str(cipher[0] if cipher else ""),
                )
    except ssl.SSLCertVerificationError as exc:
        message = str(exc)
        lower = message.casefold()
        if "issuer" in lower or "local issuer" in lower:
            category = "TLS_ISSUER_MISMATCH"
        elif "hostname" in lower or "ip address mismatch" in lower:
            category = "TLS_HOST_MISMATCH"
        elif "expired" in lower:
            category = "TLS_EXPIRED"
        else:
            category = "TLS_CERTIFICATE"
        return TLSProbe(False, category, message)
    except (ConnectionError, TimeoutError, OSError) as exc:
        return TLSProbe(False, "TLS_CONNECTIVITY", f"{type(exc).__name__}: {exc}")
    except Exception as exc:
        return TLSProbe(False, "TLS_ERROR", f"{type(exc).__name__}: {exc}")
