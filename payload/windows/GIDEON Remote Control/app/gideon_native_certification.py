from __future__ import annotations

"""Read-mostly native certification for an installed GIDEON Remote Control node.

The default mode never starts/stops services, installs packages, edits firewall,
Defender/OpenSSH or writes outside the requested evidence directory. Optional
service-cycle exercises live in platform wrappers and require explicit consent.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform as _platform
import re
import socket
import stat
import sys
from typing import Any, Callable

from gideon_diagnostics_service import collect_snapshot, default_data_root
from gideon_service_health import HealthState, service_manager_observations
from gideon_update_security import list_trusted_public_keys
from gideon_version import PRODUCT_VERSION, AGENT_VERSION, GATEWAY_VERSION
from gideon_evidence_security import sign_report
from tools.install_integrity import verify_manifest as verify_install_integrity

SCHEMA = "gideon-native-certification/v1"
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
BLOCKED = "BLOCKED"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalize_platform(value: str | None = None) -> str:
    text = (value or _platform.system()).strip().lower()
    if text.startswith("win"):
        return "windows"
    if text in {"linux", "ubuntu", "debian"}:
        return "linux"
    if text in {"darwin", "mac", "macos"}:
        return "macos"
    return text or "unknown"


def default_app_root(platform_name: str) -> Path:
    if platform_name == "windows":
        # Registry lookup is kept local/read-only and falls back to canonical path.
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\GIDEON\RemoteControl") as key:
                value, _ = winreg.QueryValueEx(key, "AppRoot")
            if value:
                return Path(str(value))
        except Exception:
            pass
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "GIDEON Remote Control" / "app"
    if platform_name == "linux":
        return Path("/opt/gideon/web/app")
    # macOS is Agent-only; point to a conventional portable Agent location.
    return Path("/Library/Application Support/GIDEONAgent")


def _config_paths(platform_name: str, data_root: Path) -> tuple[Path, Path]:
    if platform_name == "windows":
        return data_root / "config" / "gateway.json", data_root / "config" / "web_admin.json"
    return Path("/etc/gideon/gateway/gateway.json"), Path("/etc/gideon/web/web_admin.json")


def _trust_dir(platform_name: str, data_root: Path) -> Path:
    if platform_name == "windows":
        return data_root / "updates" / "trust" / "update-signing"
    return Path("/var/lib/gideon/updates/trust/update-signing")


def _check(check_id: str, status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"id": check_id, "status": status, "summary": summary, "details": details}


def check_version_contract(app_root: Path) -> dict[str, Any]:
    version_file = app_root / "gideon_version.py"
    release_manifest = app_root / "RELEASE-MANIFEST.json"
    try:
        text = version_file.read_text(encoding="utf-8-sig")
        match = re.search(r'^PRODUCT_VERSION\s*=\s*[\"\']([^\"\']+)[\"\']', text, re.M)
        observed = match.group(1) if match else ""
        release = json.loads(release_manifest.read_text(encoding="utf-8-sig"))
        manifest_version = str(release.get("version") or "") if isinstance(release, dict) else ""
    except Exception as exc:
        return _check("version_contract", FAIL, "No se pudo leer el contrato de versión instalado", error=f"{type(exc).__name__}: {exc}")
    ok = observed == PRODUCT_VERSION == manifest_version
    return _check(
        "version_contract", PASS if ok else FAIL,
        "Versión instalada coherente" if ok else "Versión instalada inconsistente",
        runtime=observed, expected=PRODUCT_VERSION, release_manifest=manifest_version,
    )


def check_install_integrity(app_root: Path) -> dict[str, Any]:
    errors = verify_install_integrity(app_root, require_exact_file_set=False)
    return _check(
        "immutable_integrity", PASS if not errors else FAIL,
        "Código/asset inmutable coincide con INSTALL-INTEGRITY-MANIFEST" if not errors else "Integridad inmutable no coincide",
        errors=errors[:50], error_count=len(errors),
    )


def check_ports(platform_name: str, data_root: Path) -> dict[str, Any]:
    if platform_name not in {"windows", "linux"}:
        return _check("gideon_ports", WARN, "Control plane no aplica a esta plataforma Agent-only")
    gw_path, web_path = _config_paths(platform_name, data_root)
    try:
        gw = json.loads(gw_path.read_text(encoding="utf-8-sig")); web = json.loads(web_path.read_text(encoding="utf-8-sig"))
        gw_port = int(gw.get("listen_port") or 0); web_port = int(web.get("listen_port") or 0)
    except Exception as exc:
        return _check("gideon_ports", FAIL, "No se pudieron leer puertos GIDEON", error=f"{type(exc).__name__}: {exc}")
    ok = 1024 <= gw_port <= 65535 and 1024 <= web_port <= 65535 and gw_port != web_port and gw_port not in {22, 443} and web_port not in {22, 443}
    return _check(
        "gideon_ports", PASS if ok else FAIL,
        "Puertos GIDEON aislados de 22/443" if ok else "Puertos GIDEON inválidos/no aislados",
        gateway_port=gw_port, web_port=web_port,
    )


def check_update_trust(platform_name: str, data_root: Path, *, required: bool) -> dict[str, Any]:
    if platform_name not in {"windows", "linux"}:
        return _check("update_trust", WARN, "Updater de control plane no aplica en Agent-only")
    root = _trust_dir(platform_name, data_root)
    try:
        rows = list_trusted_public_keys(root)
    except Exception as exc:
        return _check("update_trust", FAIL if required else WARN, "Trust store de updates inválido", error=f"{type(exc).__name__}: {exc}")
    active = [r for r in rows if not r.get("revoked") and r.get("fingerprint") != "INVALID"]
    status = PASS if active else (FAIL if required else WARN)
    return _check(
        "update_trust", status,
        "Existe al menos una clave pública de release activa" if active else "No hay clave pública de release activa provisionada",
        active_keys=[{"key_id": r.get("key_id"), "fingerprint": r.get("fingerprint")} for r in active],
        required=required,
    )


def check_linux_secret_permissions() -> dict[str, Any]:
    targets = [
        (Path("/etc/gideon/gateway/gateway.env"), 0o640),
        (Path("/etc/gideon/web/web.env"), 0o640),
        (Path("/etc/gideon/pki/root/gideon-root-ca.key"), 0o600),
        (Path("/etc/gideon/pki/agent-ca/agent-client-ca.key"), 0o600),
        (Path("/etc/gideon/pki/web/web.key"), 0o640),
        (Path("/etc/gideon/pki/gateway/gateway.key"), 0o640),
    ]
    problems: list[str] = []
    rows: list[dict[str, Any]] = []
    for path, maximum in targets:
        if not path.exists():
            problems.append(f"Falta {path}")
            rows.append({"path": str(path), "exists": False})
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        # No bit beyond the expected permission mask may be granted.
        excessive = mode & ~maximum
        if excessive:
            problems.append(f"Permisos demasiado amplios {oct(mode)}: {path}")
        rows.append({"path": str(path), "exists": True, "mode": oct(mode), "expected_max": oct(maximum)})
    return _check(
        "linux_secret_permissions", PASS if not problems else FAIL,
        "Permisos de secretos/PKI Linux restringidos" if not problems else "Permisos/archivos secretos Linux requieren atención",
        files=rows, problems=problems,
    )


def check_services(platform_name: str, *, probe: Callable[..., list] = service_manager_observations) -> dict[str, Any]:
    if platform_name not in {"windows", "linux"}:
        return _check("gideon_services", WARN, "Control plane no aplica a plataforma Agent-only")
    try:
        rows = probe(platform=platform_name)
    except Exception as exc:
        return _check("gideon_services", FAIL, "No se pudieron consultar servicios GIDEON", error=f"{type(exc).__name__}: {exc}")
    serialized = [r.as_dict() if hasattr(r, "as_dict") else dict(r) for r in rows]
    failed = [r for r in serialized if str(r.get("state")) != HealthState.RUNNING.value]
    return _check(
        "gideon_services", PASS if not failed else FAIL,
        "Todos los servicios/unidades GIDEON están RUNNING" if not failed else "Uno o más servicios/unidades GIDEON no están RUNNING",
        services=serialized,
    )


def check_functional_health(platform_name: str, data_root: Path, *, probe: Callable[..., Any] = collect_snapshot) -> dict[str, Any]:
    if platform_name not in {"windows", "linux"}:
        return _check("functional_health", WARN, "Control plane no aplica a plataforma Agent-only")
    try:
        snap = probe(data_root, platform=platform_name)
        payload = snap.as_dict() if hasattr(snap, "as_dict") else dict(snap)
        state = str(payload.get("state") or "")
    except Exception as exc:
        return _check("functional_health", FAIL, "No se pudo ejecutar diagnóstico funcional GIDEON", error=f"{type(exc).__name__}: {exc}")
    return _check(
        "functional_health", PASS if state == HealthState.RUNNING.value else FAIL,
        "Gateway/WebAdmin y manager GIDEON saludables" if state == HealthState.RUNNING.value else "Control plane GIDEON no está completamente saludable",
        snapshot=payload,
    )


def check_agent_only_layout(app_root: Path) -> dict[str, Any]:
    expected = ["gideon_agent.py", "gideon_agent_runtime.py", "gideon_version.py"]
    missing = [name for name in expected if not (app_root / name).is_file()]
    return _check("macos_agent_layout", PASS if not missing else FAIL, "Layout Agent macOS presente" if not missing else "Faltan archivos del Agent macOS", missing=missing)


def certify(
    app_root: Path,
    data_root: Path,
    *,
    platform_name: str | None = None,
    require_update_trust: bool = False,
    service_probe: Callable[..., list] = service_manager_observations,
    health_probe: Callable[..., Any] = collect_snapshot,
    include_native_permissions: bool = True,
    service_cycle_exercised: bool = False,
) -> dict[str, Any]:
    plat = _normalize_platform(platform_name)
    app_root = Path(app_root).resolve(); data_root = Path(data_root).resolve()
    checks: list[dict[str, Any]] = []
    checks.append(_check("native_platform", PASS if plat in {"windows", "linux", "macos"} else BLOCKED, f"Plataforma detectada: {plat}"))
    checks.append(check_version_contract(app_root))
    checks.append(check_install_integrity(app_root))
    if plat == "macos":
        checks.append(check_agent_only_layout(app_root))
    else:
        checks.append(check_ports(plat, data_root))
        checks.append(check_update_trust(plat, data_root, required=require_update_trust))
        checks.append(check_services(plat, probe=service_probe))
        checks.append(check_functional_health(plat, data_root, probe=health_probe))
        if plat == "linux" and include_native_permissions:
            checks.append(check_linux_secret_permissions())
    mandatory_fail = any(c["status"] in {FAIL, BLOCKED} for c in checks)
    overall = FAIL if mandatory_fail else (WARN if any(c["status"] == WARN for c in checks) else PASS)
    release_manifest = app_root / "RELEASE-MANIFEST.json"
    return {
        "schema": SCHEMA,
        "product": "GIDEON Remote Control",
        "version": PRODUCT_VERSION,
        "agent_version": AGENT_VERSION,
        "gateway_version": GATEWAY_VERSION,
        "overall": overall,
        "generated_at_utc": utc_now(),
        "host": {
            "platform": plat,
            "system": _platform.system(),
            "release": _platform.release(),
            "python": _platform.python_version(),
            "hostname": socket.gethostname(),
        },
        "paths": {"app_root": str(app_root), "data_root": str(data_root)},
        "release_manifest_sha256": sha256(release_manifest) if release_manifest.is_file() else "",
        "install_integrity_manifest_sha256": sha256(app_root / "INSTALL-INTEGRITY-MANIFEST.json") if (app_root / "INSTALL-INTEGRITY-MANIFEST.json").is_file() else "",
        "exercise": {"service_cycle_exercised": bool(service_cycle_exercised)},
        "policy": {
            "default_mode_mutates_services": False,
            "touches_defender": False,
            "touches_system_ssh": False,
            "touches_third_party_services": False,
        },
        "checks": checks,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# GIDEON Native Certification · {report.get('version')}", "",
        f"- Resultado: **{report.get('overall')}**",
        f"- Plataforma: `{report.get('host', {}).get('platform')}`",
        f"- Host: `{report.get('host', {}).get('hostname')}`",
        f"- Generado UTC: `{report.get('generated_at_utc')}`",
        f"- Release manifest SHA-256: `{report.get('release_manifest_sha256') or 'N/A'}`",
        "", "## Checks", "",
    ]
    for row in report.get("checks") or []:
        lines.append(f"- **{row.get('status')}** `{row.get('id')}` — {row.get('summary')}")
    lines += ["", "> Este reporte no demuestra pruebas que no se hayan ejecutado en el host nativo.", ""]
    return "\n".join(lines)


def write_evidence(report: dict[str, Any], output_dir: Path, *, signing_key: Path | None = None, key_id: str = "") -> tuple[Path, Path]:
    output_dir = Path(output_dir).resolve(); output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    base = output_dir / f"gideon-native-certification-{report['host']['platform']}-{stamp}"
    json_path = base.with_suffix(".json"); md_path = base.with_suffix(".md")
    if signing_key is not None:
        report = sign_report(report, signing_key, key_id=key_id)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="GIDEON native certification (read-mostly)")
    ap.add_argument("--platform", choices=["windows", "linux", "macos"], default=None)
    ap.add_argument("--app-root", default="")
    ap.add_argument("--data-root", default="")
    ap.add_argument("--output-dir", default="native-evidence")
    ap.add_argument("--require-update-trust", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--service-cycle-exercised", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--evidence-signing-key", default="", help="Clave privada Ed25519 del piloto; nunca se instala en GIDEON")
    ap.add_argument("--evidence-key-id", default="")
    ns = ap.parse_args(argv)
    plat = _normalize_platform(ns.platform)
    app_root = Path(ns.app_root) if ns.app_root else default_app_root(plat)
    data_root = Path(ns.data_root) if ns.data_root else default_data_root()
    report = certify(app_root, data_root, platform_name=plat, require_update_trust=ns.require_update_trust, service_cycle_exercised=ns.service_cycle_exercised)
    json_path, md_path = write_evidence(report, Path(ns.output_dir), signing_key=Path(ns.evidence_signing_key) if ns.evidence_signing_key else None, key_id=ns.evidence_key_id)
    if ns.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"GIDEON Native Certification: {report['overall']}")
        print(f"JSON: {json_path}")
        print(f"MD:   {md_path}")
    return 0 if report["overall"] == PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
