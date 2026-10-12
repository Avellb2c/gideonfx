from __future__ import annotations

"""Single source of truth for a standalone GIDEON Agent runtime.

Every generated Agent must be able to start on a clean endpoint without relying on
files that happened to exist in the Control Plane source tree.  This module owns the
Python runtime closure and non-Python support assets copied into every Agent bundle.
It also validates local GIDEON imports so a future refactor fails during build instead of
producing an installer that fails on the endpoint.
"""

import ast
import re
from pathlib import Path
import shutil
from typing import Iterable

RUNTIME_FILES: tuple[str, ...] = (
    "gideon_agent.py",
    "gideon_agent_http.py",
    "gideon_agent_connectivity.py",
    "gideon_agent_config.py",
    "gideon_agent_security.py",
    "gideon_agent_display_capability.py",
    "gideon_agent_player.py",
    "gideon_agent_archive.py",
    # The component contract is runtime-owned so a future signed Player
    # component can be verified and staged without ever changing core tunnel,
    # transfer, enrollment, or mTLS state.
    "gideon_agent_component.py",
    "gideon_agent_vlc_offline.py",
    "gideon_agent_vlc_offline_control.py",
    "gideon_agent_rdp_capability.py",
    "gideon_agent_bootstrap.py",
    "gideon_agent_worker.py",
    "gideon_agent_job_contract.py",
    "gideon_host_profiles.py",
    "gideon_agent_tray.py",
    "gideon_agent_display_session.py",
    "gideon_agent_update.py",
    "gideon_agent_session_handoff.py",
    "gideon_agent_vnc_bridge.py",
    "gideon_reverse_tunnel.py",
)

RUNTIME_DIRS: tuple[str, ...] = (
    "gideon_common",
)

# Source -> destination inside the standalone Agent payload.
# gideon_script_host.ps1 is deliberately present both in the Agent installer and in
# every signed PowerShell Job package.  The endpoint copy is useful for diagnostics
# and repair; a Job never silently falls back to an unverified host file.
RUNTIME_ASSETS: tuple[tuple[str, str], ...] = (
    ("gideon_script_host.ps1", "gideon_script_host.ps1"),
    # The local Windows-only mapping helper travels with the common payload so
    # a normal signed Agent update never leaves a multi-monitor pilot with an
    # old or missing companion. It has no network path and is usable only by a
    # local Windows administrator.
    ("deploy/agent/windows/gideon-agent-player-map.ps1", "gideon-agent-player-map.ps1"),
    # VLC remains an independently installed external program.  Ship the
    # notice with every Agent/update payload so its detected version and
    # provenance are never mistaken for an embedded GIDEON component.
    ("THIRD_PARTY_VLC_NOTICE.txt", "THIRD_PARTY_VLC_NOTICE.txt"),
)

# Machine/site state must never be replaced by a software-only update bundle.
PRESERVED_RUNTIME_NAMES: frozenset[str] = frozenset({
    "agent.json",
    "agent.runtime.json",
    "agent.status.json",
    "host_profile.json",
    "gideon_gateway_ca.pem",
    "client.crt",
    "client.key",
    "bootstrap.enrollment",
    "config.current.json",
    "config.previous.json",
    "config.pending.json",
    "config.rejected.json",
    "config.status.json",
    # The reviewed VLC kit can contain the complete corresponding GPL source
    # and is deliberately delivered by fresh installers/component maintenance,
    # never copied or backed up by a normal core self-update.
    "third_party",
    "venv",
    "runtime",
})


def _top_level_local_imports(path: Path, app_root: Path) -> set[str]:
    """Return GIDEON-local top-level modules/packages imported by *path*."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise RuntimeError(f"No se pudo analizar dependencia runtime Agent {path.name}: {exc}") from exc
    names: set[str] = set()
    for node in ast.walk(tree):
        modules: Iterable[str]
        if isinstance(node, ast.Import):
            modules = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules = (node.module,)
        else:
            continue
        for module in modules:
            top = str(module).split(".", 1)[0]
            if (app_root / f"{top}.py").is_file() or (app_root / top / "__init__.py").is_file():
                names.add(top)
    return names


def validate_common_runtime_source(app_root: Path) -> None:
    """Fail closed when Agent and ReverseTunnel are from different runtime APIs."""
    root = Path(app_root).resolve()
    agent_path = root / "gideon_agent.py"
    tunnel_path = root / "gideon_reverse_tunnel.py"
    if not agent_path.is_file() or not tunnel_path.is_file():
        raise RuntimeError(
            "COMMON_RUNTIME_INCOMPLETE: gideon_agent.py + gideon_reverse_tunnel.py "
            "must exist for every operating system."
        )
    agent_text = agent_path.read_text(encoding="utf-8-sig")
    tunnel_text = tunnel_path.read_text(encoding="utf-8-sig")
    required = re.search(r"(?m)^REVERSE_TUNNEL_API_REQUIRED\s*=\s*(\d+)\s*$", agent_text)
    provided = re.search(r"(?m)^TUNNEL_API_VERSION\s*=\s*(\d+)\s*$", tunnel_text)
    if not required or not provided:
        raise RuntimeError(
            "COMMON_RUNTIME_CONTRACT_MISSING: "
            "REVERSE_TUNNEL_API_REQUIRED/TUNNEL_API_VERSION not found."
        )
    if int(required.group(1)) != int(provided.group(1)):
        raise RuntimeError(
            f"COMMON_RUNTIME_API_MISMATCH: Agent requires API {required.group(1)} "
            f"but ReverseTunnel provides API {provided.group(1)}. BUILD BLOCKED."
        )


def validate_agent_runtime_sources(app_root: Path) -> dict[str, list[str]]:
    """Fail closed when a local import used by the Agent is absent from the payload.

    The function is intentionally build-time only; it never imports the Control Plane
    modules.  This catches the class of regression where code starts importing a new
    local module but a native installer still copies an old hard-coded list.
    """
    root = Path(app_root).resolve()
    validate_common_runtime_source(root)
    missing_sources: list[str] = []
    for name in RUNTIME_FILES:
        if not (root / name).is_file():
            missing_sources.append(name)
    for name in RUNTIME_DIRS:
        if not (root / name / "__init__.py").is_file():
            missing_sources.append(name + "/")
    for source_name, _destination_name in RUNTIME_ASSETS:
        if not (root / source_name).is_file():
            missing_sources.append(source_name)
    if missing_sources:
        raise FileNotFoundError("Runtime Agent incompleto en origen: " + ", ".join(sorted(missing_sources)))

    included_modules = {Path(name).stem for name in RUNTIME_FILES} | set(RUNTIME_DIRS)
    missing_imports: dict[str, list[str]] = {}
    for name in RUNTIME_FILES:
        path = root / name
        missing = sorted(_top_level_local_imports(path, root) - included_modules)
        if missing:
            missing_imports[name] = missing
    for package_name in RUNTIME_DIRS:
        package_root = root / package_name
        for path in sorted(package_root.rglob("*.py")):
            missing = sorted(_top_level_local_imports(path, root) - included_modules)
            if missing:
                missing_imports[path.relative_to(root).as_posix()] = missing
    if missing_imports:
        detail = "; ".join(f"{name} -> {','.join(mods)}" for name, mods in sorted(missing_imports.items()))
        raise RuntimeError("RUNTIME_LOCAL_DEPENDENCY_MISSING: " + detail)
    return {"files": list(RUNTIME_FILES), "dirs": list(RUNTIME_DIRS), "assets": [dst for _, dst in RUNTIME_ASSETS]}


def copy_agent_runtime_payload(app_root: Path, payload: Path) -> None:
    app_root = Path(app_root).resolve()
    payload = Path(payload)
    payload.mkdir(parents=True, exist_ok=True)
    validate_agent_runtime_sources(app_root)

    for name in RUNTIME_FILES:
        shutil.copy2(app_root / name, payload / name)

    for name in RUNTIME_DIRS:
        source = app_root / name
        shutil.copytree(
            source,
            payload / name,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )

    for source_name, destination_name in RUNTIME_ASSETS:
        source = app_root / source_name
        destination = payload / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def runtime_relative_files(payload: Path) -> list[Path]:
    payload = Path(payload)
    return [p.relative_to(payload) for p in sorted(payload.rglob("*")) if p.is_file()]


__all__ = [
    "RUNTIME_FILES",
    "RUNTIME_DIRS",
    "RUNTIME_ASSETS",
    "PRESERVED_RUNTIME_NAMES",
    "validate_agent_runtime_sources",
    "copy_agent_runtime_payload",
    "runtime_relative_files",
]
