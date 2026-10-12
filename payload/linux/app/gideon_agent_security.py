from __future__ import annotations

try:
    from gideon_common.observability import best_effort_warning
except ModuleNotFoundError:
    # Standalone/self-heal fallback: an older installation may be missing the
    # shared desktop package.  The new installer still ships gideon_common, but
    # this keeps network/security startup alive long enough to repair it.
    import logging
    def best_effort_warning(context, exc, *args):
        if args:
            context = str(context).format(*args)
        logging.getLogger("gideon.agent").warning("%s: %s", context, exc)
import base64, hashlib
from pathlib import Path
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:
    serialization=None; Ed25519PrivateKey=None
class SecurityDependencyError(RuntimeError): pass

def sha256_bytes(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
def ensure_ed25519_keypair(private_path:Path,public_path:Path):
    if Ed25519PrivateKey is None or serialization is None: raise SecurityDependencyError('cryptography es requerido para Ed25519')
    private_path=Path(private_path); public_path=Path(public_path); private_path.parent.mkdir(parents=True,exist_ok=True); public_path.parent.mkdir(parents=True,exist_ok=True)
    if private_path.exists() and public_path.exists(): return private_path,public_path
    private=Ed25519PrivateKey.generate(); public=private.public_key()
    private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    public_path.write_bytes(public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    try: private_path.chmod(0o600)
    except Exception as exc: best_effort_warning(f"No se pudo aplicar chmod 0600 a {private_path}", exc)
    return private_path,public_path
def sign_file_bytes(path:Path,private_key_pem:bytes)->str:
    if serialization is None: raise SecurityDependencyError('cryptography es requerido para Ed25519')
    private=serialization.load_pem_private_key(bytes(private_key_pem),password=None)
    return base64.b64encode(private.sign(Path(path).read_bytes())).decode('ascii')

def sign_file(path:Path,private_key_path:Path)->str:
    return sign_file_bytes(path,Path(private_key_path).read_bytes())
def verify_file(path:Path,signature_b64:str,public_key_path:Path)->bool:
    if serialization is None: raise SecurityDependencyError('cryptography es requerido para Ed25519')
    public=serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    try: public.verify(base64.b64decode(signature_b64),Path(path).read_bytes()); return True
    except Exception: return False

def sign_file_sha256(path:Path,private_key_path:Path,*,domain:bytes)->str:
    """Sign a domain-separated streaming SHA-256 digest, not whole file bytes."""
    return sign_sha256_digest(sha256_file(Path(path)),private_key_path,domain=domain)

def sign_sha256_digest(sha256_hex:str,private_key_path:Path,*,domain:bytes)->str:
    """Sign an already-computed SHA-256 digest with domain separation."""
    if serialization is None: raise SecurityDependencyError('cryptography es requerido para Ed25519')
    if not isinstance(domain,bytes) or not domain: raise ValueError('signature domain requerido')
    digest=str(sha256_hex or '').strip().casefold()
    if len(digest)!=64 or any(ch not in '0123456789abcdef' for ch in digest): raise ValueError('sha256 inválido')
    private=serialization.load_pem_private_key(Path(private_key_path).read_bytes(),password=None)
    message=domain+bytes.fromhex(digest)
    return base64.b64encode(private.sign(message)).decode('ascii')

def verify_file_sha256(path:Path,signature_b64:str,public_key_path:Path,*,domain:bytes)->bool:
    """Verify a domain-separated signature using streaming file hashing."""
    return verify_sha256_digest(sha256_file(Path(path)),signature_b64,public_key_path,domain=domain)

def verify_sha256_digest(sha256_hex:str,signature_b64:str,public_key_path:Path,*,domain:bytes)->bool:
    """Verify an Ed25519 signature over an already-computed SHA-256 digest."""
    if serialization is None: raise SecurityDependencyError('cryptography es requerido para Ed25519')
    if not isinstance(domain,bytes) or not domain: return False
    digest=str(sha256_hex or '').strip().casefold()
    if len(digest)!=64 or any(ch not in '0123456789abcdef' for ch in digest): return False
    public=serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    try:
        signature=base64.b64decode(signature_b64,validate=True)
        public.verify(signature,domain+bytes.fromhex(digest))
        return True
    except Exception:
        return False
