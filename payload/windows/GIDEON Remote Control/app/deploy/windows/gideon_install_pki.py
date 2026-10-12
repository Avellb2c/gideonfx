from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _public_key_bytes(value) -> bytes:
    return value.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_pair(cert_path: Path, key_path: Path, label: str) -> tuple[x509.Certificate, object] | None:
    cert_exists = cert_path.is_file()
    key_exists = key_path.is_file()
    if not cert_exists and not key_exists:
        return None
    if cert_exists != key_exists:
        raise RuntimeError(
            f"PKI_INCOMPLETE: {label} requiere certificado y clave existentes juntos; "
            "no se rotará automáticamente."
        )
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except Exception as exc:
        raise RuntimeError(f"PKI_INVALID: no se pudo cargar {label}: {exc}") from exc
    if _public_key_bytes(cert) != _public_key_bytes(key):
        raise RuntimeError(f"PKI_MISMATCH: certificado y clave no coinciden para {label}.")
    return cert, key


def _load_or_create_ca(cert_path: Path, key_path: Path, cn: str) -> tuple[x509.Certificate, object]:
    existing = _load_pair(cert_path, key_path, cn)
    if existing is not None:
        return existing
    now = dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GIDEON CORP S.A."),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(key_path, _pem_key(key))
    return cert, key


def _san(host: str) -> list[x509.GeneralName]:
    values: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    raw = str(host or "").strip().strip("[]")
    if raw:
        try:
            values.append(x509.IPAddress(ipaddress.ip_address(raw.split("%", 1)[0])))
        except ValueError:
            values.append(x509.DNSName(raw))
    unique = []
    seen = set()
    for item in values:
        key = (type(item).__name__, str(item.value).casefold())
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _issue_server(
    ca: x509.Certificate,
    ca_key,
    host: str,
    cn: str,
    cert_path: Path,
    key_path: Path,
    *,
    rotate: bool = False,
) -> bool:
    existing = _load_pair(cert_path, key_path, cn)
    if existing is not None and not rotate:
        # Reinstalls/upgrades preserve the service identity byte-for-byte. A
        # certificate rotation is a separate privileged operation, never an
        # implicit side effect of OneClick.
        return False
    now = dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GIDEON CORP S.A."),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_san(host)), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(key_path, _pem_key(key))
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="GIDEON Windows private PKI bootstrap")
    ap.add_argument("--root", required=True)
    ap.add_argument("--web-host", required=True)
    ap.add_argument("--gateway-host", required=True)
    ap.add_argument(
        "--rotate-server-certs",
        action="store_true",
        help="Rotación explícita de certificados/keys Web y Gateway. No usar durante upgrade normal.",
    )
    ns = ap.parse_args()
    root = Path(ns.root).resolve()
    root_ca, root_key = _load_or_create_ca(
        root / "root" / "gideon-root-ca.pem",
        root / "root" / "gideon-root-ca.key",
        "GIDEON Remote Control Private Root CA",
    )
    _issue_server(
        root_ca, root_key, ns.web_host, "GIDEON Remote Control Web Admin",
        root / "web" / "web.crt", root / "web" / "web.key",
        rotate=ns.rotate_server_certs,
    )
    _issue_server(
        root_ca, root_key, ns.gateway_host, "GIDEON Remote Control Agent Gateway",
        root / "gateway" / "gateway.crt", root / "gateway" / "gateway.key",
        rotate=ns.rotate_server_certs,
    )
    _load_or_create_ca(
        root / "agent-ca" / "agent-client-ca.pem",
        root / "agent-ca" / "agent-client-ca.key",
        "GIDEON Agent Client CA",
    )
    print(root / "root" / "gideon-root-ca.pem")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
