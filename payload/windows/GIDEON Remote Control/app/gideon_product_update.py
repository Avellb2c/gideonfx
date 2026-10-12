from __future__ import annotations

"""Transactional updater for GIDEON Remote Control application code.

The updater intentionally supports a small set of GIDEON-owned destinations.  It
never accepts arbitrary absolute paths or arbitrary service names from an update
package.  Configuration, identities, databases, PKI, logs, releases and backups
are outside the writable target map and therefore survive code updates.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from gideon_update_lock import UpdateExecutionLock, UpdateLockBusy
from gideon_update_security import SIGNATURE_FILE, UpdateSignatureError, verify_manifest_bytes
from gideon_update_transaction import PlannedFile, TransactionError, UpdateTransaction, recover_incomplete_transactions

UPDATE_SCHEMA = "gideon-product-update/v1"
PRODUCT_NAME = "GIDEON Remote Control"
MAX_FILES = 1000
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024

GIDEON_UNIT_ALLOWLIST = frozenset(
    {
        "gideon-agent-gateway.service",
        "gideon-web-admin.service",
        "gideon-backup.service",
        "gideon-backup.timer",
        "gideon-update.service",
        "gideon-update.path",
        "gideon-remote-control.target",
        "gideon-diagnostics.service",
        "gideon-coordinator.service",
    }
)

WINDOWS_SERVICE_ALLOWLIST = frozenset(
    {
        "GIDEONRemoteControl",
        "GIDEONRemoteControlGateway",
        "GIDEONRemoteControlWebAdmin",
        "GIDEONRemoteControlBackup",
        "GIDEONRemoteControlUpdater",
        "GIDEONRemoteControlDiagnostics",
    }
)

PROTECTED_APP_PREFIXES = (
    "config/",
    "data/",
    "logs/",
    "backups/",
    "gateway-data/",
    "web-data/",
    "scripts/",
    "releases/",
    "uploads/",
    "quarantine/",
    ".ssh/",
    "pki/",
)


class UpdateError(RuntimeError):
    pass


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:([-+])([A-Za-z0-9._-]+))?$")


def _parse_product_version(value: str) -> tuple[tuple[int, int, int], str | None, str | None]:
    """Parse the GIDEON product version without adding a runtime dependency.

    Build metadata (``+...``) does not affect precedence. A ``-...`` suffix is
    treated as a prerelease and therefore sorts before the matching stable
    release. This is intentionally small but deterministic for the version
    grammar already accepted by the updater.
    """
    text = str(value or "").strip()
    match = _VERSION_RE.fullmatch(text)
    if not match:
        raise UpdateError(f"Versión de producto inválida: {value!r}")
    core = tuple(int(match.group(i)) for i in (1, 2, 3))
    marker = match.group(4)
    suffix = match.group(5)
    prerelease = suffix if marker == "-" else None
    build = suffix if marker == "+" else None
    return core, prerelease, build


def _prerelease_key(value: str | None) -> tuple[tuple[int, object], ...]:
    if value is None:
        # Stable release sorts after every prerelease of the same core.
        return ((2, ""),)
    rows: list[tuple[int, object]] = []
    for token in re.split(r"[._-]", value):
        rows.append((0, int(token)) if token.isdigit() else (1, token.lower()))
    return tuple(rows) or ((0, 0),)


def compare_product_versions(left: str, right: str) -> int:
    """Return -1/0/1 using GIDEON product-version precedence."""
    left_core, left_pre, _left_build = _parse_product_version(left)
    right_core, right_pre, _right_build = _parse_product_version(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    lk = _prerelease_key(left_pre)
    rk = _prerelease_key(right_pre)
    if lk == rk:
        return 0
    return -1 if lk < rk else 1


def validate_update_transition(
    current: str,
    target: str,
    allowed_from: Iterable[str],
    *,
    force: bool = False,
    allow_downgrade: bool = False,
) -> str:
    """Validate only the version transition policy.

    This function is shared by WebAdmin and the privileged updater so the same
    rule is enforced before queueing and again before touching files. ``force``
    may bypass a source-version allowlist mismatch, but it never silently turns
    into downgrade permission. Downgrades require the distinct
    ``allow_downgrade`` capability and are intentionally unavailable in the Web
    workflow.
    """
    current = str(current or "").strip()
    target = str(target or "").strip()
    _parse_product_version(target)
    allowed = [str(item).strip() for item in allowed_from if str(item).strip()]
    for item in allowed:
        _parse_product_version(item)

    if current:
        _parse_product_version(current)
        if current == target:
            return "ALREADY_APPLIED"
        if compare_product_versions(target, current) < 0 and not allow_downgrade:
            raise UpdateError(
                f"Downgrade bloqueado: versión instalada={current}, destino={target}. "
                "Use una operación de downgrade explícita y controlada; --force no la habilita."
            )

    if not force and allowed and current not in allowed:
        raise UpdateError(
            f"Versión instalada {current or '<desconocida>'} no admitida. Esperadas: {allowed}"
        )
    return "APPLICABLE"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def default_update_root() -> Path:
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA") or str(Path.home())
        return Path(base) / "GIDEON Remote Control" / "updates"
    return Path("/var/lib/gideon/updates")


def default_update_trust_dir(state_root: Path | None = None) -> Path:
    return Path(state_root or default_update_root()) / "trust" / "update-signing"


def _verify_package_signature(root: Path, state_root: Path) -> dict[str, Any]:
    manifest_path = Path(root) / "manifest.json"
    signature_path = Path(root) / SIGNATURE_FILE
    if not manifest_path.is_file():
        raise UpdateError("El paquete no contiene manifest.json.")
    if not signature_path.is_file():
        raise UpdateError(f"SIGNATURE_REQUIRED: falta {SIGNATURE_FILE}.")
    try:
        return verify_manifest_bytes(
            manifest_path.read_bytes(),
            signature_path.read_bytes(),
            default_update_trust_dir(state_root),
        )
    except UpdateSignatureError as exc:
        raise UpdateError(str(exc)) from exc


def windows_registry_app_root() -> Path | None:
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\GIDEON\RemoteControl") as key:
            value, _ = winreg.QueryValueEx(key, "AppRoot")
        path = Path(str(value)).resolve()
        return path if path.is_dir() else None
    except (OSError, ValueError):
        return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(value: str) -> PurePosixPath:
    raw = str(value or "").replace("\\", "/").strip()
    p = PurePosixPath(raw)
    if not raw or p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        raise UpdateError(f"Ruta relativa inválida: {value!r}")
    return p


def _is_protected_app_rel(rel: PurePosixPath) -> bool:
    text = rel.as_posix().lower()
    return any(text == prefix[:-1] or text.startswith(prefix) for prefix in PROTECTED_APP_PREFIXES)


def _read_manifest(root: Path) -> dict[str, Any]:
    path = Path(root) / "manifest.json"
    if not path.is_file():
        raise UpdateError("El paquete no contiene manifest.json.")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise UpdateError(f"manifest.json inválido: {exc}") from exc
    if not isinstance(value, dict):
        raise UpdateError("manifest.json debe contener un objeto JSON.")
    if value.get("schema") != UPDATE_SCHEMA:
        raise UpdateError(f"Schema de actualización no soportado: {value.get('schema')!r}")
    if value.get("product") != PRODUCT_NAME:
        raise UpdateError("El paquete no pertenece a GIDEON Remote Control.")
    files = value.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise UpdateError("La lista de archivos del paquete es inválida o excede el límite.")
    to_version = str(value.get("to_version") or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?", to_version):
        raise UpdateError("to_version inválido.")
    baseline = value.get("from_release_manifest_sha256")
    if baseline not in (None, [], ""):
        values = [baseline] if isinstance(baseline, str) else baseline
        if not isinstance(values, list) or not values or any(not re.fullmatch(r"[0-9a-fA-F]{64}", str(x or "").strip()) for x in values):
            raise UpdateError("from_release_manifest_sha256 inválido.")
    return value


def _validate_package_files(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    for index, raw in enumerate(manifest.get("files") or []):
        if not isinstance(raw, dict):
            raise UpdateError(f"files[{index}] debe ser un objeto.")
        source_rel = _safe_rel(str(raw.get("source") or ""))
        if source_rel.parts[0] != "payload":
            raise UpdateError(f"files[{index}] debe apuntar dentro de payload/.")
        source = Path(root, *source_rel.parts)
        if not source.is_file():
            raise UpdateError(f"Falta archivo del payload: {source_rel.as_posix()}")
        expected = str(raw.get("sha256") or "").lower().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise UpdateError(f"SHA-256 inválido para {source_rel.as_posix()}.")
        actual = _sha256(source)
        if actual != expected:
            raise UpdateError(f"SHA-256 no coincide para {source_rel.as_posix()}.")
        targets = raw.get("targets")
        if not isinstance(targets, list) or not targets:
            raise UpdateError(f"Sin targets para {source_rel.as_posix()}.")
        allowed_targets = {"windows_app", "windows_service_host", "linux_web", "linux_gateway", "linux_updater", "linux_systemd"}
        normalized_targets = [str(x) for x in targets]
        unknown = set(normalized_targets) - allowed_targets
        if unknown:
            raise UpdateError(f"Targets no soportados para {source_rel.as_posix()}: {sorted(unknown)}")
        validated.append({**raw, "_source_rel": source_rel, "_source": source, "_targets": normalized_targets})
    return validated


def _extract_app_rel(source_rel: PurePosixPath) -> PurePosixPath:
    if len(source_rel.parts) < 3 or source_rel.parts[:2] != ("payload", "app"):
        raise UpdateError(f"Payload de aplicación inválido: {source_rel.as_posix()}")
    rel = PurePosixPath(*source_rel.parts[2:])
    if _is_protected_app_rel(rel):
        raise UpdateError(f"El paquete intenta modificar estado/configuración protegida: {rel.as_posix()}")
    return rel


def _destination_for(target: str, source_rel: PurePosixPath, *, app_root: Path | None) -> tuple[Path, str]:
    if target in {"windows_app", "linux_web", "linux_gateway"}:
        rel = _extract_app_rel(source_rel)
        if target == "windows_app":
            if app_root is None:
                raise UpdateError("Windows requiere --app-root.")
            return Path(app_root, *rel.parts), f"windows_app/{rel.as_posix()}"
        if target == "linux_web":
            return Path("/opt/gideon/web/app", *rel.parts), f"linux_web/{rel.as_posix()}"
        return Path("/opt/gideon/gateway/app", *rel.parts), f"linux_gateway/{rel.as_posix()}"

    if target == "windows_service_host":
        if app_root is None:
            raise UpdateError("Windows requiere --app-root para actualizar el service host.")
        if len(source_rel.parts) < 3 or source_rel.parts[:2] != ("payload", "windows_service"):
            raise UpdateError(f"Payload Windows service host inválido: {source_rel.as_posix()}")
        rel = PurePosixPath(*source_rel.parts[2:])
        if any(part.lower() in {"..", "config", "data", "secrets"} for part in rel.parts):
            raise UpdateError("Ruta Windows service host inválida.")
        # The Windows SCM host is a stable GIDEONServiceHost.exe built by the BASE.
        # Incremental service-support updates land only in the GIDEON app deploy tree;
        # no files are injected into Python's global/venv site-packages anymore.
        service_support = Path(app_root).resolve() / "deploy" / "windows"
        return service_support.joinpath(*rel.parts), f"windows_service_host/{rel.as_posix()}"

    if target == "linux_updater":
        if len(source_rel.parts) < 3 or source_rel.parts[:2] != ("payload", "updater"):
            raise UpdateError(f"Payload updater inválido: {source_rel.as_posix()}")
        rel = PurePosixPath(*source_rel.parts[2:])
        return Path("/opt/gideon/updater", *rel.parts), f"linux_updater/{rel.as_posix()}"

    if target == "linux_systemd":
        if len(source_rel.parts) != 3 or source_rel.parts[:2] != ("payload", "systemd"):
            raise UpdateError(f"Payload systemd inválido: {source_rel.as_posix()}")
        name = source_rel.parts[-1]
        if name not in GIDEON_UNIT_ALLOWLIST:
            raise UpdateError(f"Unidad systemd fuera del allowlist GIDEON: {name}")
        return Path("/etc/systemd/system") / name, f"linux_systemd/{name}"

    raise UpdateError(f"Target no soportado: {target}")


def _detect_version(path: Path) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    match = re.search(r'^PRODUCT_VERSION\s*=\s*["\']([^"\']+)["\']', text, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def current_product_version(platform_name: str, app_root: Path | None = None) -> str:
    if platform_name == "windows":
        if app_root is None:
            return ""
        return _detect_version(Path(app_root) / "gideon_version.py")
    if app_root is not None:
        return _detect_version(Path(app_root) / "gideon_version.py")
    return _detect_version(Path("/opt/gideon/web/app/gideon_version.py"))


def _installed_app_root(platform_name: str, app_root: Path | None = None) -> Path | None:
    if app_root is not None:
        return Path(app_root).resolve()
    if platform_name == "linux":
        return Path("/opt/gideon/web/app")
    return None


def current_release_manifest_sha256(platform_name: str, app_root: Path | None = None) -> str:
    """Return the installed canonical release-manifest digest when available."""
    root = _installed_app_root(platform_name, app_root)
    if root is None:
        return ""
    candidate = root / "RELEASE-MANIFEST.json"
    return _sha256(candidate) if candidate.is_file() else ""


def current_install_integrity_manifest_sha256(platform_name: str, app_root: Path | None = None) -> str:
    root = _installed_app_root(platform_name, app_root)
    if root is None:
        return ""
    candidate = root / "INSTALL-INTEGRITY-MANIFEST.json"
    return _sha256(candidate) if candidate.is_file() else ""


def verify_installed_immutable_baseline(platform_name: str, app_root: Path | None = None) -> dict[str, Any]:
    """Verify every immutable file declared by the installed integrity manifest.

    Runtime config/data are intentionally absent from this manifest. This check
    therefore detects code drift without rejecting legitimate mutable state.
    """
    root = _installed_app_root(platform_name, app_root)
    if root is None:
        raise UpdateError("INTEGRITY_BASELINE_MISSING: no se pudo resolver el app root instalado.")
    manifest_path = root / "INSTALL-INTEGRITY-MANIFEST.json"
    if not manifest_path.is_file():
        raise UpdateError("INTEGRITY_BASELINE_MISSING: no existe INSTALL-INTEGRITY-MANIFEST.json instalado.")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise UpdateError(f"INTEGRITY_BASELINE_INVALID: manifest de integridad ilegible: {exc}") from exc
    rows = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise UpdateError("INTEGRITY_BASELINE_INVALID: files debe ser una lista no vacía.")
    verified = 0
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UpdateError(f"INTEGRITY_BASELINE_INVALID: files[{index}] no es objeto.")
        rel_raw = str(row.get("path") or "")
        try:
            rel = _safe_rel(rel_raw)
        except Exception as exc:
            raise UpdateError(f"INTEGRITY_BASELINE_INVALID: ruta insegura {rel_raw!r}.") from exc
        rel_text = rel.as_posix()
        if rel_text in seen:
            raise UpdateError(f"INTEGRITY_BASELINE_INVALID: ruta duplicada {rel_text}.")
        seen.add(rel_text)
        target = root.joinpath(*rel.parts)
        if not target.is_file():
            raise UpdateError(f"INTEGRITY_BASELINE_MISMATCH: falta archivo inmutable {rel_text}.")
        expected_size = int(row.get("size_bytes") or -1)
        if target.stat().st_size != expected_size:
            raise UpdateError(f"INTEGRITY_BASELINE_MISMATCH: tamaño distinto {rel_text}.")
        expected_sha = str(row.get("sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha) or _sha256(target) != expected_sha:
            raise UpdateError(f"INTEGRITY_BASELINE_MISMATCH: SHA-256 distinto {rel_text}.")
        verified += 1
    return {"verified_files": verified, "manifest_sha256": _sha256(manifest_path)}


def validate_release_baseline(
    manifest: dict[str, Any],
    *,
    platform_name: str,
    app_root: Path | None = None,
) -> dict[str, Any]:
    """Validate optional release + immutable-tree source baseline attestations.

    Neither attestation is bypassed by ``--force``. Narrow/delta updates should
    provide both fields. The immutable manifest excludes runtime state.
    """
    def allowed_hashes(field: str) -> list[str]:
        raw = manifest.get(field)
        if raw in (None, [], ""):
            return []
        values = [raw] if isinstance(raw, str) else raw
        if not isinstance(values, list) or not values:
            raise UpdateError(f"{field} debe ser un SHA-256 o una lista no vacía.")
        result: list[str] = []
        for value in values:
            digest = str(value or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise UpdateError(f"{field} contiene un SHA-256 inválido.")
            if digest not in result:
                result.append(digest)
        return result

    release_allowed = allowed_hashes("from_release_manifest_sha256")
    integrity_allowed = allowed_hashes("from_install_integrity_manifest_sha256")
    if not release_allowed and not integrity_allowed:
        return {"required": False, "verified": False, "sha256": ""}

    result: dict[str, Any] = {"required": True, "verified": True}
    if release_allowed:
        current = current_release_manifest_sha256(platform_name, app_root)
        if not current:
            raise UpdateError("BASELINE_ATTESTATION_MISSING: no existe RELEASE-MANIFEST.json instalado para validar el origen.")
        if current.lower() not in release_allowed:
            raise UpdateError(
                "BASELINE_MISMATCH: el RELEASE-MANIFEST instalado no corresponde al baseline permitido por este paquete. "
                f"actual={current.lower()} esperados={release_allowed}"
            )
        result.update({"sha256": current.lower(), "release_manifest_sha256": current.lower(), "allowed": release_allowed})

    if integrity_allowed:
        current_integrity = current_install_integrity_manifest_sha256(platform_name, app_root)
        if not current_integrity:
            raise UpdateError("INTEGRITY_BASELINE_MISSING: no existe INSTALL-INTEGRITY-MANIFEST.json instalado.")
        if current_integrity.lower() not in integrity_allowed:
            raise UpdateError(
                "INTEGRITY_BASELINE_MISMATCH: INSTALL-INTEGRITY-MANIFEST no corresponde al baseline permitido. "
                f"actual={current_integrity.lower()} esperados={integrity_allowed}"
            )
        tree = verify_installed_immutable_baseline(platform_name, app_root)
        result.update({
            "install_integrity_manifest_sha256": current_integrity.lower(),
            "install_integrity_allowed": integrity_allowed,
            "immutable_files_verified": int(tree.get("verified_files") or 0),
        })
    return result



def _ensure_linux_update_state(root: Path) -> None:
    """Create only GIDEON updater state with permissions needed by gideonweb/root."""
    root = Path(root)
    if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        import grp
        import pwd
        web = pwd.getpwnam("gideonweb")
        web_gid = grp.getgrnam("gideonweb").gr_gid
    except Exception:
        web = None
        web_gid = 0
    specs = (
        (root, 0, web_gid, 0o750),
        (root / "inbox", web.pw_uid if web else 0, web_gid, 0o750),
        (root / "staging", 0, web_gid, 0o750),
        (root / "status", 0, web_gid, 0o750),
        (root / "archive", 0, web_gid, 0o750),
        (root / "archive" / "success", 0, web_gid, 0o750),
        (root / "archive" / "failed", 0, web_gid, 0o750),
        (root / "rollback", 0, web_gid, 0o750),
        (root / "transactions", 0, web_gid, 0o750),
        (root / "trust", 0, web_gid, 0o750),
        (root / "trust" / "update-signing", 0, web_gid, 0o750),
    )
    for directory, uid, gid, mode in specs:
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(directory, uid, gid)
            os.chmod(directory, mode)
        except OSError:
            pass

def _run_systemctl(args: Iterable[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = ["systemctl", *list(args)]
    return subprocess.run(cmd, text=True, capture_output=True, timeout=90, check=check)


def _validate_units(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise UpdateError("La lista de unidades debe ser un array.")
    result: list[str] = []
    for raw in values:
        unit = str(raw or "").strip()
        if unit not in GIDEON_UNIT_ALLOWLIST:
            raise UpdateError(f"Unidad no permitida por GIDEON updater: {unit}")
        if unit not in result:
            result.append(unit)
    return result


def _validate_windows_services(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise UpdateError("La lista de servicios Windows debe ser un array.")
    result: list[str] = []
    for raw in values:
        service = str(raw or "").strip()
        if service not in WINDOWS_SERVICE_ALLOWLIST:
            raise UpdateError(f"Servicio Windows no permitido por GIDEON updater: {service}")
        if service not in result:
            result.append(service)
    return result


def _run_sc(args: Iterable[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = ["sc.exe", *list(args)]
    return subprocess.run(
        cmd, text=True, capture_output=True, timeout=90, check=check,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _windows_service_state(service: str) -> str:
    cp = _run_sc(["query", service])
    text = ((cp.stdout or "") + "\n" + (cp.stderr or "")).upper()
    if "RUNNING" in text:
        return "RUNNING"
    if "STOPPED" in text:
        return "STOPPED"
    if cp.returncode != 0:
        return "MISSING"
    return "OTHER"


def _wait_windows_service(service: str, expected: str, timeout_seconds: int = 45) -> None:
    import time
    deadline = time.monotonic() + max(5, timeout_seconds)
    while time.monotonic() < deadline:
        if _windows_service_state(service) == expected:
            return
        time.sleep(0.5)
    raise UpdateError(f"Servicio {service} no alcanzó estado {expected}.")


def _windows_webadmin_http_health(app_root: Path, timeout_seconds: int = 25) -> None:
    """Require an actual local /healthz response after a WebAdmin update.

    SCM RUNNING is not enough: a Python process can be alive while the ASGI app
    failed during startup.  The probe is loopback-only, reads no credentials and
    accepts the local service certificate without hostname validation solely for
    this post-update readiness check.
    """
    import json as _json
    import ssl as _ssl
    import time as _time
    import urllib.request as _urllib_request

    root = Path(app_root).resolve()
    cfg_path = root / "config" / "web_admin.json"
    try:
        cfg = _json.loads(cfg_path.read_text(encoding="utf-8-sig")) if cfg_path.is_file() else {}
    except Exception:
        cfg = {}
    port = int(cfg.get("listen_port") or 28443)
    cert = str(cfg.get("tls_certfile") or "").strip()
    key = str(cfg.get("tls_keyfile") or "").strip()
    scheme = "https" if cert and key else "http"
    url = f"{scheme}://127.0.0.1:{port}/healthz"
    context = _ssl._create_unverified_context() if scheme == "https" else None
    deadline = _time.monotonic() + max(5, int(timeout_seconds))
    last_error = "sin respuesta"
    while _time.monotonic() < deadline:
        try:
            with _urllib_request.urlopen(url, timeout=2.5, context=context) as response:
                payload = _json.loads(response.read(65536).decode("utf-8-sig"))
                if int(getattr(response, "status", 200)) == 200 and payload.get("Ok") is True and payload.get("Service") == "GIDEON Web Admin":
                    return
                last_error = f"respuesta healthz inválida: {payload!r}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        _time.sleep(0.75)
    raise UpdateError(f"WebAdmin no alcanzó readiness HTTP en {url}: {last_error}")


def _restart_windows_service(service: str) -> None:
    if service == "GIDEONRemoteControlUpdater":
        raise UpdateError("El aplicador no puede reiniciar su propio servicio durante la transacción.")
    state = _windows_service_state(service)
    if state == "MISSING":
        raise UpdateError(f"Servicio GIDEON no instalado: {service}")
    if state == "RUNNING":
        cp = _run_sc(["stop", service])
        if cp.returncode not in {0, 1062}:
            raise UpdateError((cp.stderr or cp.stdout or f"No se pudo detener {service}").strip())
        _wait_windows_service(service, "STOPPED")
    cp = _run_sc(["start", service])
    if cp.returncode not in {0, 1056}:
        raise UpdateError((cp.stderr or cp.stdout or f"No se pudo iniciar {service}").strip())
    _wait_windows_service(service, "RUNNING")



def _apply_extracted_update_locked(
    package_root: Path,
    *,
    platform_name: str,
    app_root: Path | None = None,
    state_root: Path | None = None,
    force: bool = False,
    allow_downgrade: bool = False,
    manage_services: bool = True,
) -> dict[str, Any]:
    root = Path(package_root).resolve()
    platform_name = platform_name.lower().strip()
    if platform_name not in {"windows", "linux"}:
        raise UpdateError("platform_name debe ser windows o linux.")

    if state_root is None:
        if platform_name == "linux":
            state_root = Path("/var/lib/gideon/updates")
        else:
            base = Path(app_root or Path.cwd())
            state_root = base / ".gideon-updates"
    state_root = Path(state_root).resolve()
    if platform_name == "linux":
        _ensure_linux_update_state(state_root)

    signature_info = _verify_package_signature(root, state_root)
    manifest = _read_manifest(root)
    files = _validate_package_files(root, manifest)
    current = current_product_version(platform_name, app_root)
    target_version = str(manifest["to_version"])
    allowed_from = [str(x) for x in (manifest.get("from_versions") or [])]
    transition = validate_update_transition(
        current, target_version, allowed_from, force=force, allow_downgrade=allow_downgrade
    )
    if transition == "ALREADY_APPLIED":
        return {
            "ok": True,
            "status": "ALREADY_APPLIED",
            "from_version": current,
            "to_version": target_version,
            "package_id": manifest.get("package_id"),
            "changed": 0,
            "signature": signature_info,
            "at": _utc_now(),
        }

    baseline_info = validate_release_baseline(manifest, platform_name=platform_name, app_root=app_root)

    if platform_name == "linux" and os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise UpdateError("La actualización Linux debe ejecutarse como root/sudo.")

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    relevant_targets = {"windows_app", "windows_service_host"} if platform_name == "windows" else {
        "linux_web", "linux_gateway", "linux_updater", "linux_systemd"
    }
    plan: list[PlannedFile] = []
    seen_destinations: set[Path] = set()
    for item in files:
        source_rel: PurePosixPath = item["_source_rel"]
        for target in item["_targets"]:
            if target not in relevant_targets:
                continue
            destination, backup_key = _destination_for(target, source_rel, app_root=app_root)
            destination = destination.resolve()
            if destination in seen_destinations:
                raise UpdateError(f"Destino duplicado en paquete: {destination}")
            seen_destinations.add(destination)
            plan.append(PlannedFile(item["_source"], destination, backup_key))
    if not plan:
        raise UpdateError("El paquete no contiene archivos aplicables a esta plataforma.")

    restart_units = _validate_units(manifest.get("restart_units")) if platform_name == "linux" else []
    enable_units = _validate_units(manifest.get("enable_units")) if platform_name == "linux" else []
    health_units = _validate_units(manifest.get("health_units")) if platform_name == "linux" else []
    restart_services = _validate_windows_services(manifest.get("restart_services")) if platform_name == "windows" else []
    health_services = _validate_windows_services(manifest.get("health_services")) if platform_name == "windows" else []

    systemd_changed = False
    tx_id = f"{stamp}-{uuid.uuid4().hex[:10]}-{target_version}"
    try:
        tx = UpdateTransaction(
            state_root / "transactions",
            tx_id=tx_id,
            from_version=current or "unknown",
            to_version=target_version,
            package_id=str(manifest.get("package_id") or ""),
        )
        tx.prepare(plan)

        def apply_mode(destination: Path) -> None:
            nonlocal systemd_changed
            if destination.parent == Path("/etc/systemd/system"):
                destination.chmod(0o644)
                systemd_changed = True
            elif str(destination).startswith("/opt/gideon/updater/"):
                destination.chmod(0o644)

        changed = tx.commit(mode_hook=apply_mode)

        if platform_name == "linux" and manage_services:
            if systemd_changed:
                cp = _run_systemctl(["daemon-reload"], check=False)
                if cp.returncode != 0:
                    raise UpdateError((cp.stderr or cp.stdout or "systemctl daemon-reload falló").strip())
            for unit in enable_units:
                cp = _run_systemctl(["enable", unit], check=False)
                if cp.returncode != 0:
                    raise UpdateError((cp.stderr or cp.stdout or f"No se pudo habilitar {unit}").strip())
            for unit in enable_units:
                if unit.endswith(".path") or unit.endswith(".target"):
                    _run_systemctl(["start", unit], check=False)
            for unit in restart_units:
                cp = _run_systemctl(["restart", unit], check=False)
                if cp.returncode != 0:
                    raise UpdateError((cp.stderr or cp.stdout or f"No se pudo reiniciar {unit}").strip())
            for unit in health_units:
                cp = _run_systemctl(["is-active", "--quiet", unit], check=False)
                if cp.returncode != 0:
                    raise UpdateError(f"Health check systemd falló: {unit} no está activo.")

        if platform_name == "windows" and manage_services:
            for service in restart_services:
                _restart_windows_service(service)
            for service in health_services:
                if _windows_service_state(service) != "RUNNING":
                    raise UpdateError(f"Health check Windows falló: {service} no está RUNNING.")
                if service == "GIDEONRemoteControlWebAdmin":
                    _windows_webadmin_http_health(Path(app_root or Path.cwd()))

        result = {
            "ok": True,
            "status": "APPLIED",
            "package_id": manifest.get("package_id"),
            "from_version": current,
            "to_version": target_version,
            "changed": changed,
            "transaction_id": tx_id,
            "transaction_dir": str(tx.root),
            "rollback_dir": str(tx.backups),
            "signature": signature_info,
            "baseline": baseline_info,
            "at": _utc_now(),
        }
        tx.mark_applied(result)
        return result
    except Exception as exc:
        rollback_errors: list[str] = []
        tx_obj = locals().get("tx")
        if isinstance(tx_obj, UpdateTransaction):
            try:
                rollback_errors = tx_obj.rollback(reason=f"{type(exc).__name__}: {exc}")
            except Exception as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        if platform_name == "linux" and manage_services:
            if systemd_changed:
                _run_systemctl(["daemon-reload"], check=False)
            for unit in restart_units:
                _run_systemctl(["restart", unit], check=False)
        if platform_name == "windows" and manage_services:
            for service in restart_services:
                if service != "GIDEONRemoteControlUpdater":
                    try:
                        _restart_windows_service(service)
                    except Exception:
                        rollback_errors.append(f"No se pudo recuperar servicio {service}")
        detail = f"{type(exc).__name__}: {exc}"
        if rollback_errors:
            detail += " | Rollback errors: " + " ; ".join(rollback_errors)
        failure = {
            "ok": False,
            "status": "ROLLED_BACK" if not rollback_errors else "ROLLBACK_PARTIAL",
            "package_id": manifest.get("package_id"),
            "from_version": current,
            "to_version": target_version,
            "transaction_id": tx_id,
            "error": detail,
            "at": _utc_now(),
        }
        if isinstance(tx_obj, UpdateTransaction):
            (tx_obj.root / "FAILED.json").write_text(json.dumps(failure, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        raise UpdateError(detail) from exc


def apply_extracted_update(
    package_root: Path,
    *,
    platform_name: str,
    app_root: Path | None = None,
    state_root: Path | None = None,
    force: bool = False,
    allow_downgrade: bool = False,
    manage_services: bool = True,
) -> dict[str, Any]:
    platform_name = platform_name.lower().strip()
    if platform_name not in {"windows", "linux"}:
        raise UpdateError("platform_name debe ser windows o linux.")
    if state_root is None:
        state_root = Path("/var/lib/gideon/updates") if platform_name == "linux" else Path(app_root or Path.cwd()) / ".gideon-updates"
    resolved_state_root = Path(state_root).resolve()
    if platform_name == "linux":
        _ensure_linux_update_state(resolved_state_root)
    try:
        with UpdateExecutionLock(resolved_state_root / "update.lock", timeout_seconds=0):
            recovered = recover_incomplete_transactions(resolved_state_root / "transactions")
            result = _apply_extracted_update_locked(
                package_root,
                platform_name=platform_name,
                app_root=app_root,
                state_root=resolved_state_root,
                force=force,
                allow_downgrade=allow_downgrade,
                manage_services=manage_services,
            )
            if recovered:
                result["recovered_transactions"] = recovered
            return result
    except (UpdateLockBusy, TransactionError) as exc:
        raise UpdateError(str(exc)) from exc


def safe_extract_zip(package: Path, destination: Path) -> None:
    package = Path(package)
    destination = Path(destination)
    with zipfile.ZipFile(package) as zf:
        infos = zf.infolist()
        if not infos or len(infos) > MAX_FILES + 50:
            raise UpdateError("Cantidad de entradas ZIP inválida.")
        total = sum(max(0, int(info.file_size)) for info in infos)
        if total > MAX_UNCOMPRESSED_BYTES:
            raise UpdateError("El ZIP excede el máximo descomprimido permitido.")
        for info in infos:
            rel = _safe_rel(info.filename.rstrip("/")) if info.filename.rstrip("/") else None
            if rel is None:
                continue
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                raise UpdateError(f"No se permiten symlinks en actualizaciones: {info.filename}")
            target = destination.joinpath(*rel.parts).resolve()
            dest_resolved = destination.resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise UpdateError(f"ZIP traversal detectado: {info.filename}")
        zf.extractall(destination)


def _write_status(root: Path, name: str, payload: dict[str, Any]) -> Path:
    status_dir = root / "status"
    status_dir.mkdir(parents=True, exist_ok=True)
    path = status_dir / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o640)
        if os.name != "nt":
            import grp
            gid = grp.getgrnam("gideonweb").gr_gid
            os.chown(path, 0, gid)
    except (OSError, KeyError):
        # Status contents remain valid even if an optional ownership adjustment
        # is unavailable (for example in a container without the gideonweb group).
        return path
    return path


def _process_inbox_locked(
    root: Path | None = None,
    *,
    platform_name: str | None = None,
    app_root: Path | None = None,
) -> int:
    platform_name = (platform_name or ("windows" if os.name == "nt" else "linux")).lower().strip()
    if platform_name not in {"windows", "linux"}:
        raise UpdateError("Plataforma de inbox no soportada.")
    if platform_name == "linux":
        if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise UpdateError("--process-inbox Linux solo puede ejecutarse como root.")
    else:
        if os.name != "nt":
            raise UpdateError("--process-inbox Windows debe ejecutarse en Windows.")
        if app_root is None:
            app_root = windows_registry_app_root()
        if app_root is None:
            raise UpdateError("No se pudo resolver AppRoot de GIDEON Remote Control en Windows.")

    root = Path(root or default_update_root())
    if platform_name == "linux":
        _ensure_linux_update_state(root)
    inbox = root / "inbox"
    staging = root / "staging"
    success_dir = root / "archive" / "success"
    failed_dir = root / "archive" / "failed"
    for directory in (inbox, staging, success_dir, failed_dir, root / "status"):
        directory.mkdir(parents=True, exist_ok=True)

    ready_files = sorted(inbox.glob("*.ready"), key=lambda p: p.stat().st_mtime)
    if not ready_files:
        return 0
    overall = 0
    for ready in ready_files:
        name = ready.stem
        package_name = ""
        try:
            package_name = ready.read_text(encoding="utf-8-sig").strip()
            if Path(package_name).name != package_name or not package_name.lower().endswith(".zip"):
                raise UpdateError("Marcador .ready inválido.")
            package = inbox / package_name
            if not package.is_file():
                raise UpdateError(f"Paquete encolado no existe: {package_name}")
            with tempfile.TemporaryDirectory(prefix="gideon-update-", dir=str(staging)) as tmp:
                extracted = Path(tmp) / "package"
                extracted.mkdir(parents=True)
                safe_extract_zip(package, extracted)
                result = _apply_extracted_update_locked(
                    extracted,
                    platform_name=platform_name,
                    app_root=app_root,
                    state_root=root,
                    manage_services=True,
                )
            result["queued_file"] = package_name
            _write_status(root, name, result)
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.move(str(package), str(success_dir / f"{stamp}-{package.name}"))
            ready.unlink(missing_ok=True)
        except Exception as exc:
            overall = 1
            failure = {
                "ok": False,
                "status": "FAILED",
                "queued_file": package_name,
                "error": f"{type(exc).__name__}: {exc}",
                "at": _utc_now(),
            }
            _write_status(root, name, failure)
            try:
                package = inbox / package_name if package_name else None
                if package is not None and package.is_file():
                    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                    shutil.move(str(package), str(failed_dir / f"{stamp}-{package.name}"))
            except OSError as archive_exc:
                failure["archive_error"] = f"{type(archive_exc).__name__}: {archive_exc}"
                _write_status(root, name, failure)
            ready.unlink(missing_ok=True)
    return overall


def process_inbox(
    root: Path | None = None,
    *,
    platform_name: str | None = None,
    app_root: Path | None = None,
) -> int:
    platform_name = (platform_name or ("windows" if os.name == "nt" else "linux")).lower().strip()
    resolved_root = Path(root or default_update_root()).resolve()
    if platform_name == "linux":
        _ensure_linux_update_state(resolved_root)
    try:
        with UpdateExecutionLock(resolved_root / "update.lock", timeout_seconds=0):
            recover_incomplete_transactions(resolved_root / "transactions")
            return _process_inbox_locked(resolved_root, platform_name=platform_name, app_root=app_root)
    except (UpdateLockBusy, TransactionError) as exc:
        raise UpdateError(str(exc)) from exc


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GIDEON Remote Control product updater")
    parser.add_argument("--process-inbox", action="store_true")
    parser.add_argument("--package-dir")
    parser.add_argument("--platform", choices=["windows", "linux"])
    parser.add_argument("--app-root")
    parser.add_argument("--state-root")
    parser.add_argument("--force", action="store_true", help="Bypass only from_versions mismatch; never permits downgrade.")
    parser.add_argument(
        "--allow-downgrade", action="store_true",
        help="Explicit console-only downgrade capability. Never exposed by WebAdmin/inbox processing.",
    )
    parser.add_argument("--no-services", action="store_true")
    ns = parser.parse_args(argv)
    try:
        if ns.process_inbox:
            detected = ns.platform or ("windows" if os.name == "nt" else "linux")
            return process_inbox(
                Path(ns.state_root).resolve() if ns.state_root else default_update_root(),
                platform_name=detected,
                app_root=Path(ns.app_root).resolve() if ns.app_root else None,
            )
        if not ns.package_dir or not ns.platform:
            parser.error("Use --process-inbox o indique --package-dir y --platform.")
        result = apply_extracted_update(
            Path(ns.package_dir),
            platform_name=ns.platform,
            app_root=Path(ns.app_root).resolve() if ns.app_root else None,
            state_root=Path(ns.state_root).resolve() if ns.state_root else None,
            force=ns.force,
            allow_downgrade=ns.allow_downgrade,
            manage_services=not ns.no_services,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
