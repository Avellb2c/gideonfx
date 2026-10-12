from __future__ import annotations

"""Canonical production payload policy.

The production installer is intentionally NOT a copy of the engineering tree.
This module is the single source of truth used by distribution, release and
installed-integrity manifests so historical docs/tests/build tooling cannot
silently leak back into OneClick packages.
"""

from pathlib import Path

NON_RUNTIME_TOP_LEVEL = {
    "tests", "docs", "legacy_tkinter", "tools", ".git", ".pytest_cache",
}

# Root compatibility/development artifacts that are not part of the supported
# production runtime. Qt/WebAdmin are the supported interfaces.
NON_RUNTIME_ROOT_FILES = {
    "ARCHITECTURE.md", "CHANGELOG.md", "MIGRATION.md", "OPERATIONS.md",
    "README.md", "SECURITY.md", "VALIDATION.md", "ONECLICK-INSTALLERS.md",
    "NATIVE-PILOT-PLAN-P8G.md", "P8H-PRODUCTION-PLAN.md",
    "P8G-ACCEPTANCE-MATRIX.json", "P8H-ACCEPTANCE-MATRIX.json",
    "RELEASE-HISTORY.json", "requirements-dev.txt", "pyproject.toml",
    "GIDEON-Legacy-Tkinter-GUI.bat", "GIDEON-Remote-Control-DIAGNOSTICO.bat",
    "GIDEON-Remote-Control-v6.bat", "GIDEON-Remote-Control-v6.sh",
    "GIDEON-Remote-Control-v6.vbs", "GIDEON-Remote-Control.desktop",
    "GIDEON-SSH-Admin-GUI.bat", "GIDEON-SSH-Admin-SILENCIOSO.vbs",
    "gideon_admin.bat", "Install-GIDEON-UI-v6.ps1",
    "WINDOWS-SERVICE-ACL-MATRIX.json",
    # Tkinter compatibility shims; the legacy implementation itself is also excluded.
    "gideon_agent_manager.py", "gideon_control_center.py", "gideon_diagnostics_center.py",
    "gideon_event_viewer.py", "gideon_file_transfer_gui.py", "gideon_group_manager.py",
    "gideon_gui.py", "gideon_site_detail.py",
}

NON_RUNTIME_DEPLOY_PREFIXES = {
    "deploy/gateway/docker/",       # optional engineering/container example
}

NON_RUNTIME_FILES = {
    # RC23 canonical support host lives at app-root/gideon_script_host.ps1 so it can
    # be repaired by an incremental update. The historical scripts/ copy is
    # protected user/state namespace and is no longer part of the runtime image.
    "scripts/gideon_script_host.ps1",
}

NON_RUNTIME_DEPLOY_FILES = {
    "deploy/agent/README-PACKAGING.md",
    "deploy/aws/SECURE-HEADLESS-UBUNTU.md",
    "deploy/gateway/README-AUTO-CONFIG.md",
    "deploy/updates/README.md",
    "deploy/updates/update-spec-6.3.2-p8e-to-6.3.3.json",
    "deploy/updates/update-spec.example.json",
    "deploy/web/nginx/README-MTLS-PUBLISHING.md",
}

EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".zip", ".gideondr", ".log"}

# ``third_party/vlc-offline`` is a reviewed source closure used only to build
# separately signed, platform-specific VLC components.  It can be several GB
# and is deliberately retained outside the core application baseline.  Its
# catalog is anchored by ``VLC-SOURCE-BASELINE.json`` (which remains in the
# core manifest), and the component builder validates selected bytes against
# that catalog before it stages or signs anything.  Do not broaden this to all
# of ``third_party``: any other component remains part of the core payload.
SEPARATELY_VERIFIED_COMPONENT_SOURCE_PREFIXES = (
    "third_party/vlc-offline/",
)

# A dated compatibility backup was left in existing installations before the
# immutable baseline existed.  It is neither imported nor executable runtime
# state, and must not make an otherwise healthy core manifest fail.  Keep this
# narrow rather than excluding arbitrary ``*.bak`` files.
NON_RUNTIME_ROOT_FILE_PREFIXES = (
    "gideon_version.py.bak-",
)


def is_production_payload_file(root: Path, path: Path) -> bool:
    root = Path(root).resolve()
    path = Path(path)
    if not path.is_file():
        return False
    rel = path.resolve().relative_to(root).as_posix()
    parts = rel.split("/")
    top = parts[0]
    name = parts[-1]

    if top in NON_RUNTIME_TOP_LEVEL or top.startswith("PHASE"):
        return False
    if "__pycache__" in parts:
        return False
    if Path(name).suffix.lower() in EXCLUDED_SUFFIXES:
        return False
    if len(parts) == 1:
        if name in NON_RUNTIME_ROOT_FILES:
            return False
        if any(name.startswith(prefix) for prefix in NON_RUNTIME_ROOT_FILE_PREFIXES):
            return False
        if name.startswith("RELEASE-NOTES-") and name.endswith(".md"):
            return False
    if rel in NON_RUNTIME_FILES:
        return False
    if rel in NON_RUNTIME_DEPLOY_FILES:
        return False
    if any(rel.startswith(prefix) for prefix in NON_RUNTIME_DEPLOY_PREFIXES):
        return False
    if any(rel.startswith(prefix) for prefix in SEPARATELY_VERIFIED_COMPONENT_SOURCE_PREFIXES):
        return False
    # Markdown is engineering/operator documentation, not executable payload.
    if name.lower().endswith(".md"):
        return False
    return True


def production_payload_files(root: Path) -> list[Path]:
    root = Path(root).resolve()
    return sorted(
        (p for p in root.rglob("*") if is_production_payload_file(root, p)),
        key=lambda p: p.relative_to(root).as_posix().lower(),
    )
