"""Repair GIDEON-owned private CA extensions without changing the signing key."""
from pathlib import Path
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def ensure_ca(cert_path, key_path):
    path = Path(cert_path)
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), None)
    cert_public = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert.subject != cert.issuer or cert_public != key_public:
        raise ValueError('Solo se admite una CA privada GIDEON autofirmada con su clave correspondiente.')
    required = {
        x509.ExtensionOID.BASIC_CONSTRAINTS: (x509.BasicConstraints(ca=True, path_length=None), True),
        x509.ExtensionOID.KEY_USAGE: (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
        x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER: (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
    }
    if all(any(e.oid == oid and e.value == value and e.critical == critical for e in cert.extensions)
           for oid, (value, critical) in required.items()):
        return False
    builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
               .public_key(key.public_key()).serial_number(cert.serial_number)
               .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc))
    for ext in cert.extensions:
        if ext.oid not in required:
            builder = builder.add_extension(ext.value, ext.critical)
    for value, critical in required.values():
        builder = builder.add_extension(value, critical)
    temporary = path.with_suffix('.pem.new')
    temporary.write_bytes(builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    temporary.chmod(0o644)
    temporary.replace(path)
    return True


if __name__ == '__main__':
    if ensure_ca(*sys.argv[1:]):
        print('GIDEON_CA_EXTENSIONS=UPDATED (clave y sujeto preservados; redistribuya el certificado CA si ya lo utilizaba)')
    else:
        print('GIDEON_CA_EXTENSIONS=PASS')
