"""Windows ACME integration for the GIDEON WebAdmin and Agent Gateway.

The Windows installer uses win-acme as the ACME protocol client and keeps the
GIDEON-specific part deliberately small: certificates are written to a private
data directory, the existing WebAdmin/Gateway JSON files are updated atomically,
and only the two allow-listed GIDEON services are restarted by the renewal hook.
Linux keeps its independent Certbot/TLS-manager implementation.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from typing import Any


SCHEMA_VERSION = 1
STATE_NAME = "windows-letsencrypt.json"
DEFAULT_CERTIFICATE_NAME = "gideon-public"
WEB_SERVICE = "GIDEONRemoteControlWebAdmin"
GATEWAY_SERVICE = "GIDEONRemoteControlGateway"
SERVICE_NAMES = (WEB_SERVICE, GATEWAY_SERVICE)
TASK_HINT = "win-acme"


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _json_path(data_root: Path) -> Path:
    return data_root / "config" / STATE_NAME


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if value is not None else default
    except (OSError, ValueError, TypeError):
        return default


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    fd, name = tempfile.mkstemp(prefix="gideon-acme-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _host_is_valid(host: str) -> bool:
    value = _safe_text(host).casefold().rstrip(".")
    if not value or value in {"localhost", "127.0.0.1", "::1"}:
        return False
    if ":" in value and not re.fullmatch(r"[0-9a-f:]+", value):
        return False
    if re.fullmatch(r"[0-9.]+", value):
        return False
    if len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    return all(0 < len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)


def _certificate_paths(state: dict[str, Any], data_root: Path) -> dict[str, Path]:
    directory = Path(_safe_text(state.get("certificate_dir")) or str(data_root / "acme" / "certs"))
    name = _safe_text(state.get("certificate_name")) or DEFAULT_CERTIFICATE_NAME
    return {
        "crt": directory / f"{name}-crt.pem",
        "key": directory / f"{name}-key.pem",
        "chain": directory / f"{name}-chain.pem",
        "chain_only": directory / f"{name}-chain-only.pem",
    }


def _decode_certificate(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Certificado ACME ausente: {path}")
    decoded = ssl._ssl._test_decode_cert(str(path))
    not_after = str(decoded.get("notAfter") or "").strip()
    if not_after:
        expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    else:
        raise ValueError("El certificado ACME no contiene fecha de expiración.")
    sans = [str(value) for kind, value in decoded.get("subjectAltName", ()) if kind == "DNS"]
    ips = [str(value) for kind, value in decoded.get("subjectAltName", ()) if kind == "IP Address"]
    return {
        "expires": expires.isoformat(),
        "days_left": int((expires - _utc_now()).total_seconds() // 86400),
        "subject": str(decoded.get("subject") or ""),
        "sans": sans + ips,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _validate_certificate(state: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    leaf = paths["crt"] if paths["crt"].is_file() else paths["chain"]
    summary = _decode_certificate(leaf)
    if summary["days_left"] < 0:
        raise ValueError("El certificado ACME está vencido.")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

        cert_data = ssl.PEM_cert_to_DER_cert(leaf.read_text(encoding="utf-8"))
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(cert_data)
        private_key = serialization.load_pem_private_key(paths["key"].read_bytes(), password=None)
        public = certificate.public_key()
        key_public = private_key.public_key()
        if isinstance(public, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            if public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise ValueError("La clave privada ACME no corresponde al certificado.")
    except ImportError:
        # The bundled runtime normally includes cryptography.  Keep a clear
        # failure if an operator uses a stripped Python runtime.
        raise RuntimeError("El runtime Python no incluye cryptography para validar la clave ACME.")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"No se pudo validar la clave privada ACME: {type(exc).__name__}") from exc

    hosts = [_safe_text(state.get("web_host")), _safe_text(state.get("gateway_host"))]
    for host in dict.fromkeys(host for host in hosts if host):
        normalized = host.casefold().rstrip(".")
        covered = False
        for candidate in summary["sans"]:
            candidate_norm = candidate.casefold().rstrip(".")
            if normalized == candidate_norm:
                covered = True
                break
            if candidate_norm.startswith("*."):
                suffix = candidate_norm[1:]
                if normalized.endswith(suffix) and normalized.count(".") == suffix.count("."):
                    covered = True
                    break
        if not covered:
            raise ValueError(f"El certificado ACME no cubre el host configurado: {host}")
    return summary


def _task_status() -> dict[str, Any]:
    if os.name != "nt":
        return {"present": False, "status": "unsupported", "name": ""}
    try:
        cp = subprocess.run(["schtasks.exe", "/Query", "/FO", "CSV", "/V", "/NH"], text=True, capture_output=True, timeout=20, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if cp.returncode != 0:
            return {"present": False, "status": "unavailable", "name": ""}
        matches: list[dict[str, str]] = []
        for row in csv.reader(io.StringIO(cp.stdout or "")):
            text = " ".join(row)
            if TASK_HINT.casefold() not in text.casefold() and "wacs.exe" not in text.casefold():
                continue
            # schtasks /FO CSV /V has TaskName and Status in stable positions
            name = row[0] if row else ""
            status = next((item for item in row if item in {"Running", "Ready", "Disabled", "Could not start"}), "unknown")
            matches.append({"name": name, "status": status})
        if matches:
            return {"present": True, "status": matches[0]["status"], "name": matches[0]["name"], "matches": matches[:3]}
    except (OSError, subprocess.SubprocessError):
        pass
    return {"present": False, "status": "not-found", "name": ""}


def status(data_root: str | Path) -> dict[str, Any]:
    root = Path(data_root).expanduser().resolve()
    state_path = _json_path(root)
    state = _read_json(state_path, {})
    if not isinstance(state, dict):
        state = {}
    client_dir = Path(_safe_text(state.get("client_dir")) or str(root.parent / "tools" / "win-acme"))
    client_path = client_dir / "wacs.exe"
    paths = _certificate_paths(state, root)
    certificate: dict[str, Any]
    try:
        certificate = _validate_certificate(state, paths) if paths["key"].is_file() else {"error": "Certificado aún no emitido."}
    except Exception as exc:
        certificate = {"error": str(exc)[:300]}
    return {
        "enabled": bool(state.get("enabled")),
        "configured": state_path.is_file(),
        "state_path": str(state_path),
        "client_installed": client_path.is_file(),
        "client_path": str(client_path),
        "environment": _safe_text(state.get("environment")) or "production",
        "web_host": _safe_text(state.get("web_host")),
        "gateway_host": _safe_text(state.get("gateway_host")),
        "certificate": certificate,
        "certificate_paths": {key: str(value) for key, value in paths.items()},
        "renewal_task": _task_status(),
        "last_hook_utc": _safe_text(state.get("last_hook_utc")),
        "last_error": _safe_text(state.get("last_error")),
    }


def _run_sc(action: str, service: str) -> None:
    cp = subprocess.run(["sc.exe", action, service], text=True, capture_output=True, timeout=45, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if cp.returncode not in (0, 1060):
        detail = ((cp.stdout or "") + " " + (cp.stderr or "")).strip()
        raise RuntimeError(f"SCM {action} {service} falló rc={cp.returncode}: {detail[:300]}")


def _service_running(service: str) -> bool:
    cp = subprocess.run(["sc.exe", "query", service], text=True, capture_output=True, timeout=20, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return cp.returncode == 0 and bool(re.search(r":\s*4\s+", (cp.stdout or "")))


def _restart_services() -> None:
    for service in SERVICE_NAMES:
        _run_sc("stop", service)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and any(_service_running(service) for service in SERVICE_NAMES):
        time.sleep(1)
    for service in SERVICE_NAMES:
        _run_sc("start", service)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if all(_service_running(service) for service in SERVICE_NAMES):
            return
        time.sleep(1)
    raise RuntimeError("WebAdmin/Gateway no quedaron en estado Running tras renovar el certificado ACME.")


def _config_paths(data_root: Path) -> tuple[Path, Path]:
    return data_root / "config" / "web_admin.json", data_root / "config" / "gateway.json"


def _patch_configurations(data_root: Path, state: dict[str, Any], paths: dict[str, Path]) -> tuple[dict[str, Any], dict[str, Any]]:
    web_path, gateway_path = _config_paths(data_root)
    web = _read_json(web_path)
    gateway = _read_json(gateway_path)
    if not isinstance(web, dict) or not isinstance(gateway, dict):
        raise ValueError("No se encontraron las configuraciones Windows de WebAdmin/Gateway.")
    cert_path = paths["chain"] if paths["chain"].is_file() else paths["crt"]
    key_path = paths["key"]
    web["tls_certfile"] = str(cert_path)
    web["tls_keyfile"] = str(key_path)
    gateway["tls_certfile"] = str(cert_path)
    gateway["tls_keyfile"] = str(key_path)
    gateway_port = int(gateway.get("listen_port") or 29443)
    gateway_host = _safe_text(state.get("gateway_host"))
    if gateway_host:
        gateway["public_host"] = gateway_host
        gateway["public_url"] = f"https://{gateway_host}:{gateway_port}"
        gateway["advertised_endpoint"] = gateway["public_url"]
        web["gateway_public_url"] = gateway["public_url"]
    return web, gateway


def renew_hook(data_root: str | Path, *, install_root: str | Path | None = None) -> dict[str, Any]:
    root = Path(data_root).expanduser().resolve()
    state_path = _json_path(root)
    state = _read_json(state_path, {})
    if not isinstance(state, dict) or not bool(state.get("enabled")):
        raise ValueError("La integración Let’s Encrypt de Windows no está configurada.")
    paths = _certificate_paths(state, root)
    summary = _validate_certificate(state, paths)
    web_path, gateway_path = _config_paths(root)
    backup_dir = root / "acme" / "backups" / _utc_now().strftime("%Y%m%dT%H%M%SZ")
    backup_dir.mkdir(parents=True, exist_ok=True)
    originals: dict[Path, bytes] = {}
    for path in (web_path, gateway_path):
        originals[path] = path.read_bytes()
        shutil.copy2(path, backup_dir / path.name)
    web, gateway = _patch_configurations(root, state, paths)
    try:
        _write_json_atomic(web_path, web)
        _write_json_atomic(gateway_path, gateway)
        _restart_services()
    except Exception:
        for path, content in originals.items():
            path.write_bytes(content)
        try:
            _restart_services()
        except Exception:
            pass
        state["last_error"] = "No se pudo activar el certificado ACME; se restauró la configuración anterior."
        _write_json_atomic(state_path, state)
        raise
    state["last_hook_utc"] = _utc_now().isoformat()
    state["last_certificate_sha256"] = summary.get("sha256", "")
    state["last_error"] = ""
    state["last_backup"] = str(backup_dir)
    _write_json_atomic(state_path, state)
    return {"certificate": summary, "backup": str(backup_dir), "services": list(SERVICE_NAMES)}


def validate_state(data_root: str | Path) -> dict[str, Any]:
    result = status(data_root)
    errors: list[str] = []
    if not result["configured"]:
        errors.append("windows-letsencrypt.json ausente")
    for label, host in (("WebAdmin", result.get("web_host")), ("Gateway", result.get("gateway_host"))):
        if result["enabled"] and not _host_is_valid(str(host or "")):
            errors.append(f"FQDN {label} inválido o no público")
    if result["enabled"] and not result["client_installed"]:
        errors.append("wacs.exe ausente")
    if result["enabled"] and result["certificate"].get("error"):
        errors.append(str(result["certificate"]["error"]))
    result["valid"] = not errors
    result["errors"] = errors
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GIDEON Windows ACME helper")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "validate"):
        command = sub.add_parser(name)
        command.add_argument("--data-root", required=True)
    hook = sub.add_parser("renew-hook")
    hook.add_argument("--data-root", required=True)
    hook.add_argument("--install-root", default="")
    args = parser.parse_args(argv)
    try:
        result = status(args.data_root) if args.command == "status" else validate_state(args.data_root) if args.command == "validate" else renew_hook(args.data_root, install_root=args.install_root)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"GIDEON_ACME_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
