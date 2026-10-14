from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


APP = Path(__file__).resolve().parents[2] / "payload" / "windows" / "GIDEON Remote Control" / "app"
import sys

sys.path.insert(0, str(APP))
from deploy.windows import gideon_windows_acme as acme  # noqa: E402


class WindowsAcmeTests(unittest.TestCase):
    def test_public_fqdn_validation(self) -> None:
        self.assertTrue(acme._host_is_valid("admin.example.com"))
        self.assertFalse(acme._host_is_valid("localhost"))
        self.assertFalse(acme._host_is_valid("192.0.2.10"))

    def test_status_without_configuration_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = acme.status(directory)
            self.assertFalse(result["enabled"])
            self.assertFalse(result["configured"])
            self.assertEqual("not-found", result["renewal_task"]["status"])

    def test_validate_state_requires_client_and_public_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "config" / acme.STATE_NAME
            state_path.parent.mkdir(parents=True)
            state_path.write_text(json.dumps({"enabled": True, "web_host": "localhost", "gateway_host": "agents.example.com"}), encoding="utf-8")
            result = acme.validate_state(root)
            self.assertFalse(result["valid"])
            self.assertIn("FQDN WebAdmin inválido o no público", result["errors"])
            self.assertIn("wacs.exe ausente", result["errors"])

    def test_patch_preserves_private_mtls_ca(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            certs = root / "acme" / "certs"
            config.mkdir(parents=True)
            certs.mkdir(parents=True)
            (config / "web_admin.json").write_text(json.dumps({"tls_certfile": "old.crt", "tls_keyfile": "old.key"}), encoding="utf-8")
            (config / "gateway.json").write_text(json.dumps({"listen_port": 29443, "ca_file": "private-ca.pem", "client_ca_file": "agent-ca.pem"}), encoding="utf-8")
            (certs / "gideon-public-chain.pem").write_text("chain", encoding="utf-8")
            (certs / "gideon-public-key.pem").write_text("key", encoding="utf-8")
            web, gateway = acme._patch_configurations(root, {"gateway_host": "agents.example.com"}, acme._certificate_paths({"certificate_dir": str(certs)}, root))
            self.assertEqual(str(certs / "gideon-public-chain.pem"), web["tls_certfile"])
            self.assertEqual("private-ca.pem", gateway["ca_file"])
            self.assertEqual("https://agents.example.com:29443", gateway["advertised_endpoint"])

    def test_certificate_and_private_key_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certs = root / "acme" / "certs"
            certs.mkdir(parents=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin.example.com")])
            certificate = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("admin.example.com"), x509.DNSName("agents.example.com")]), critical=False)
                .sign(key, hashes.SHA256())
            )
            cert_path = certs / "gideon-public-crt.pem"
            key_path = certs / "gideon-public-key.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            summary = acme._validate_certificate({"web_host": "admin.example.com", "gateway_host": "agents.example.com"}, {"crt": cert_path, "chain": certs / "missing.pem", "key": key_path, "chain_only": certs / "missing-chain.pem"})
            self.assertIn(summary["days_left"], {29, 30})


if __name__ == "__main__":
    unittest.main()
