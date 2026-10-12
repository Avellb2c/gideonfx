from __future__ import annotations

from dataclasses import dataclass
import glob
import os
from pathlib import Path
import re
import shutil

from gideon_branding import BrandProfile
from gideon_infrastructure.subprocess_utils import run_hidden


@dataclass(frozen=True)
class SigningResult:
    signed: bool
    verified: bool
    status: str
    detail: str
    tool: str = ""
    certificate_subject: str = ""


class WindowsCodeSigningService:
    """Authenticode signer isolated from packaging/UI.

    Production signing uses SignTool from the Windows SDK.  The implementation
    never creates or embeds a private key and never persists a PFX password.
    Store-backed/non-exportable certificates are preferred because they work
    with enterprise/EV code-signing identities.
    """

    @staticmethod
    def signtool_executable() -> str | None:
        explicit = os.environ.get("SIGNTOOL_PATH") or os.environ.get("GIDEON_SIGNTOOL_PATH")
        if explicit and Path(explicit).is_file():
            return str(Path(explicit).resolve())
        found = shutil.which("signtool.exe") or shutil.which("signtool")
        if found:
            return found
        if os.name != "nt":
            return None
        roots = [
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramFiles", r"C:\Program Files"),
        ]
        candidates: list[str] = []
        for root in roots:
            pattern = str(Path(root) / "Windows Kits" / "10" / "bin" / "*" / "x64" / "signtool.exe")
            candidates.extend(glob.glob(pattern))
        if not candidates:
            return None

        def key(path: str) -> tuple[int, ...]:
            parts = re.findall(r"\d+", str(Path(path).parent.parent.name))
            return tuple(int(x) for x in parts) if parts else (0,)

        return max(candidates, key=key)

    @staticmethod
    def _resolve_pfx(profile: BrandProfile, app_root: Path) -> Path | None:
        raw = os.path.expandvars(profile.signing.pfx_path or "").strip()
        if not raw:
            return None
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = Path(app_root) / path
        return path.resolve() if path.is_file() else None

    @staticmethod
    def _certificate_subject(path: Path) -> str:
        if os.name != "nt":
            return ""
        # Get-AuthenticodeSignature is used only after signing and runs hidden.
        escaped = str(path).replace("'", "''")
        script = (
            "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "';"
            "if($s.SignerCertificate){$s.SignerCertificate.Subject}"
        )
        try:
            proc = run_hidden(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                check=False, capture_output=True, text=True, timeout=30,
            )
            return (proc.stdout or "").strip().splitlines()[-1] if (proc.stdout or "").strip() else ""
        except Exception:
            return ""

    def readiness(self, profile: BrandProfile, app_root: Path) -> SigningResult:
        if os.name != "nt":
            return SigningResult(False, False, "not-applicable", "Authenticode solo aplica al build Windows.")
        if profile.signing.disabled:
            return SigningResult(False, False, "disabled", "Firma Authenticode deshabilitada por configuración.")
        tool = self.signtool_executable()
        if not tool:
            detail = "Falta SignTool (Windows SDK)."
            return SigningResult(False, False, "missing-tool", detail)
        thumb = profile.signing.certificate_thumbprint.strip()
        pfx = self._resolve_pfx(profile, app_root)
        provider = profile.signing.provider.casefold()
        if provider == "store" and not thumb:
            return SigningResult(False, False, "missing-certificate", "Provider=store requiere certificate_thumbprint.", tool=tool)
        if provider == "pfx" and not pfx:
            return SigningResult(False, False, "missing-certificate", "Provider=pfx requiere un archivo PFX válido.", tool=tool)
        if provider == "auto" and not thumb and not pfx:
            return SigningResult(False, False, "missing-certificate", "Configure thumbprint del almacén o PFX. La clave privada nunca se incluye en el proyecto.", tool=tool)
        source = "almacén de certificados" if thumb and provider in {"auto", "store"} else str(pfx)
        return SigningResult(False, False, "ready", f"SignTool listo · certificado: {source}", tool=tool)

    def sign(self, path: Path, profile: BrandProfile, app_root: Path) -> SigningResult:
        target = Path(path).resolve()
        if not target.is_file():
            raise FileNotFoundError(target)
        if profile.signing.disabled:
            return SigningResult(False, False, "disabled", "Firma deshabilitada por configuración.")

        ready = self.readiness(profile, app_root)
        if ready.status != "ready":
            if profile.signing.required:
                raise RuntimeError(
                    "La política exige firma Authenticode, pero el entorno no está listo: " + ready.detail
                )
            return ready

        tool = ready.tool
        digest = profile.signing.digest_algorithm.upper()
        cmd = [tool, "sign", "/fd", digest]
        timestamp = profile.signing.timestamp_url.strip()
        if timestamp:
            cmd += ["/tr", timestamp, "/td", digest]
        if profile.agent_product_name:
            cmd += ["/d", profile.agent_product_name]
        if profile.website_url:
            cmd += ["/du", profile.website_url]

        thumb = profile.signing.certificate_thumbprint.strip()
        pfx = self._resolve_pfx(profile, app_root)
        provider = profile.signing.provider.casefold()
        if thumb and provider in {"auto", "store"}:
            cmd += ["/sha1", thumb]
        elif pfx:
            cmd += ["/f", str(pfx)]
            env_name = profile.signing.pfx_password_env.strip() or "GIDEON_SIGNING_PFX_PASSWORD"
            password = os.environ.get(env_name)
            if password:
                cmd += ["/p", password]
        else:
            raise RuntimeError("No hay certificado de firma configurado.")
        cmd.append(str(target))

        proc = run_hidden(cmd, check=False, capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            detail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if profile.signing.required:
                raise RuntimeError("SignTool no pudo firmar el EXE.\n" + detail[-5000:])
            return SigningResult(False, False, "sign-failed", detail[-4000:], tool=tool)

        verified = False
        verify_detail = ""
        if profile.signing.verify_after_sign:
            verify = run_hidden(
                [tool, "verify", "/pa", "/all", "/v", str(target)],
                check=False, capture_output=True, text=True, timeout=120,
            )
            verified = verify.returncode == 0
            verify_detail = ((verify.stdout or "") + "\n" + (verify.stderr or "")).strip()
            if not verified and profile.signing.required:
                raise RuntimeError("El EXE fue firmado, pero la verificación Authenticode falló.\n" + verify_detail[-5000:])

        subject = self._certificate_subject(target)
        expected = profile.signing.expected_publisher.strip().casefold()
        publisher_ok = not expected or expected in subject.casefold()
        status = "signed-verified" if verified and publisher_ok else "signed-warning"
        detail = "Firma Authenticode aplicada"
        if verified:
            detail += " y verificada"
        if subject:
            detail += f" · certificado: {subject}"
        if expected and subject and not publisher_ok:
            detail += f" · ADVERTENCIA: el certificado no contiene el editor esperado '{profile.signing.expected_publisher}'"
            if profile.signing.required:
                raise RuntimeError(detail)
        return SigningResult(True, verified, status, detail, tool=tool, certificate_subject=subject)
