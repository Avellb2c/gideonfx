from __future__ import annotations

"""Declarative catalog for the Web Agent Builder.

P5 keeps UI choices separate from the packaging engine. Several visible OS
versions/distributions legitimately resolve to the same tested TARGETS entry;
that lets the Web expose a clear operator workflow without inventing unsupported
binary targets or duplicating packaging code.
"""

from typing import Any, Iterable


ARCH_LABELS = {
    "x86_64": "x64",
    "amd64": "x64",
    "arm64": "ARM64",
    "aarch64": "ARM64",
    "armv7l": "ARM32",
    "armhf": "ARM32",
    "x86": "x86",
    "i386": "x86",
}


FAMILY_DEFINITIONS: list[dict[str, Any]] = [
    {
        "id": "windows",
        "label": "Windows",
        "variants": [
            {"id": "windows_10", "label": "Windows 10", "target_id": "windows_x64"},
            {"id": "windows_11", "label": "Windows 11", "target_id": "windows_x64"},
            {"id": "windows_server_2016", "label": "Windows Server 2016 · Pulse", "target_id": "windows_server_2016"},
            {"id": "windows_server_2019", "label": "Windows Server 2019", "target_id": "windows_x64"},
            {"id": "windows_server_2022", "label": "Windows Server 2022 · Pulse", "target_id": "windows_server_2022"},
        ],
    },
    {
        "id": "linux",
        "label": "Linux",
        "variants": [
            {
                "id": "ubuntu", "label": "Ubuntu", "target_id": "linux_x64",
                "offline_vlc_distribution": "ubuntu", "offline_vlc_codename": "noble",
            },
            {
                "id": "debian", "label": "Debian", "target_id": "linux_x64",
                "offline_vlc_distribution": "debian", "offline_vlc_codename": "bookworm",
            },
            {
                "id": "aws_ubuntu", "label": "AWS Ubuntu", "target_id": "linux_x64",
                "offline_vlc_distribution": "ubuntu", "offline_vlc_codename": "noble",
            },
            {"id": "rhel", "label": "RHEL", "target_id": "linux_rhel_x64"},
            {"id": "rocky", "label": "Rocky Linux", "target_id": "linux_rhel_x64"},
            {"id": "almalinux", "label": "AlmaLinux", "target_id": "linux_rhel_x64"},
            {"id": "fedora", "label": "Fedora", "target_id": "linux_rhel_x64"},
        ],
    },
    {
        "id": "raspberry",
        "label": "Raspberry Pi",
        "variants": [
            {
                "id": "raspberry_os_32", "label": "Raspberry Pi OS 32-bit", "target_id": "linux_armhf",
                "offline_vlc_distribution": "raspbian", "offline_vlc_codename": "bookworm",
            },
            {
                "id": "raspberry_os_64", "label": "Raspberry Pi OS 64-bit", "target_id": "linux_arm64",
                "offline_vlc_distribution": "raspbian", "offline_vlc_codename": "bookworm",
            },
            {
                "id": "debian_bookworm_arm64", "label": "Debian 12 ARM64 para Raspberry", "target_id": "linux_arm64",
                "offline_vlc_distribution": "debian", "offline_vlc_codename": "bookworm",
            },
            {
                "id": "ubuntu_arm64", "label": "Ubuntu ARM64", "target_id": "linux_arm64",
                "offline_vlc_distribution": "ubuntu", "offline_vlc_codename": "noble",
            },
        ],
    },
    {
        "id": "macos",
        "label": "macOS",
        "variants": [
            {"id": "macos_intel", "label": "Intel", "target_id": "macos_x64"},
            {"id": "macos_apple_silicon", "label": "Apple Silicon", "target_id": "macos_arm64"},
        ],
    },
]


PROFILE_DEFINITIONS: list[dict[str, str]] = [
    {"id": "windows_10_11", "label": "Windows 10/11", "os_family": "windows", "os_variant": "windows_11", "connectivity_mode": "automatic"},
    {"id": "windows_server_2016_pulse", "label": "Windows Server 2016 Pulse", "os_family": "windows", "os_variant": "windows_server_2016", "connectivity_mode": "automatic"},
    {"id": "windows_server_2022_pulse", "label": "Windows Server 2022 Pulse", "os_family": "windows", "os_variant": "windows_server_2022", "connectivity_mode": "automatic"},
    {"id": "windows_admin", "label": "Windows Administrativo", "os_family": "windows", "os_variant": "windows_11", "connectivity_mode": "automatic"},
    {"id": "ubuntu_aws", "label": "Ubuntu AWS", "os_family": "linux", "os_variant": "aws_ubuntu", "connectivity_mode": "production"},
    {"id": "debian_ubuntu", "label": "Debian / Ubuntu", "os_family": "linux", "os_variant": "ubuntu", "connectivity_mode": "automatic"},
    {"id": "rhel", "label": "RHEL", "os_family": "linux", "os_variant": "rhel", "connectivity_mode": "automatic"},
    {"id": "rocky", "label": "Rocky", "os_family": "linux", "os_variant": "rocky", "connectivity_mode": "automatic"},
    {"id": "almalinux", "label": "AlmaLinux", "os_family": "linux", "os_variant": "almalinux", "connectivity_mode": "automatic"},
    {"id": "raspberry_pi", "label": "Raspberry Pi", "os_family": "raspberry", "os_variant": "raspberry_os_64", "connectivity_mode": "automatic"},
    {"id": "macos", "label": "macOS", "os_family": "macos", "os_variant": "macos_apple_silicon", "connectivity_mode": "automatic"},
    {"id": "custom", "label": "Personalizado", "os_family": "", "os_variant": "", "connectivity_mode": "automatic"},
]


ENROLLMENT_MODES = [
    {"id": "individual", "label": "Individual", "default_uses": 1, "min_uses": 1, "max_uses": 1, "description": "Un equipo / un uso del grant."},
    {"id": "group", "label": "Grupo", "default_uses": 10, "min_uses": 2, "max_uses": 50, "description": "Paquete controlado para un grupo de equipos."},
    {"id": "mass", "label": "Masivo", "default_uses": 100, "min_uses": 2, "max_uses": 100, "description": "Despliegue amplio, limitado por vigencia y usos."},
]


def build_catalog(target_rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Merge declarative OS choices with live backend capabilities."""
    target_map = {str(row.get("target_id") or ""): dict(row) for row in target_rows}
    families: list[dict[str, Any]] = []
    for family_raw in FAMILY_DEFINITIONS:
        family = {"id": family_raw["id"], "label": family_raw["label"], "variants": []}
        for variant_raw in family_raw["variants"]:
            target = target_map.get(str(variant_raw["target_id"]))
            if not target:
                continue
            architecture = str(target.get("architecture") or "")
            packages = [dict(x) for x in target.get("package_options") or [] if isinstance(x, dict)]
            family["variants"].append(
                {
                    "id": variant_raw["id"],
                    "label": variant_raw["label"],
                    "target_id": target["target_id"],
                    "target_label": target.get("label") or target["target_id"],
                    "architecture": architecture,
                    "architecture_label": ARCH_LABELS.get(architecture, architecture or "—"),
                    "profile": str(target.get("profile") or ""),
                    "notes": str(target.get("notes") or ""),
                    "offline_vlc_distribution": str(variant_raw.get("offline_vlc_distribution") or ""),
                    "offline_vlc_codename": str(variant_raw.get("offline_vlc_codename") or ""),
                    "package_options": packages,
                    "ready_any": bool(target.get("ready_any")),
                }
            )
        if family["variants"]:
            families.append(family)
    return {
        "schema": "gideon-agent-builder/v1",
        "families": families,
        "profiles": [dict(x) for x in PROFILE_DEFINITIONS],
        "enrollment_modes": [dict(x) for x in ENROLLMENT_MODES],
    }


def resolve_choice(
    catalog: dict[str, Any], *, os_family: str, os_variant: str,
    architecture: str, package_choice: str,
) -> dict[str, Any]:
    family = next((x for x in catalog.get("families", []) if x.get("id") == str(os_family)), None)
    if not family:
        raise ValueError("Sistema operativo no permitido por el Agent Builder.")
    variant = next((x for x in family.get("variants", []) if x.get("id") == str(os_variant)), None)
    if not variant:
        raise ValueError("Versión/distribución no permitida para el sistema operativo seleccionado.")
    expected_arch = str(variant.get("architecture") or "")
    if str(architecture or "") != expected_arch:
        raise ValueError("Arquitectura no compatible con la versión/distribución seleccionada.")
    option = next((x for x in variant.get("package_options", []) if x.get("value") == str(package_choice)), None)
    if not option:
        raise ValueError("Formato de instalador no permitido para la plataforma seleccionada.")
    if not bool(option.get("ready")):
        raise ValueError(str(option.get("detail") or "El backend de compilación no está disponible."))
    return {
        "target_id": str(variant["target_id"]),
        "package_choice": str(option["value"]),
        "package_type": str(option.get("resolved") or option["value"]),
        "target_label": str(variant.get("target_label") or variant["target_id"]),
        "os_family": str(family["id"]),
        "os_family_label": str(family["label"]),
        "os_variant": str(variant["id"]),
        "os_variant_label": str(variant["label"]),
        "architecture": expected_arch,
        "architecture_label": str(variant.get("architecture_label") or expected_arch),
        "offline_vlc_distribution": str(variant.get("offline_vlc_distribution") or ""),
        "offline_vlc_codename": str(variant.get("offline_vlc_codename") or ""),
    }


def validate_profile(profile_id: str) -> str:
    clean = str(profile_id or "custom").strip()
    if not any(x["id"] == clean for x in PROFILE_DEFINITIONS):
        raise ValueError("Perfil del Agent Builder no permitido.")
    return clean



def normalize_profile_for_choice(profile_id: str, os_family: str, os_variant: str) -> str:
    """Keep history truthful when an operator edits a preloaded profile.

    The UI switches to Personalizado after an OS/variant edit; this server-side
    normalization provides the same guarantee for direct/manual POSTs.
    """
    clean = validate_profile(profile_id)
    if clean == "custom":
        return clean
    row = next(x for x in PROFILE_DEFINITIONS if x["id"] == clean)
    if row.get("os_family") != str(os_family) or row.get("os_variant") != str(os_variant):
        return "custom"
    return clean

def enrollment_policy(mode: str, requested_uses: int) -> tuple[str, int]:
    clean = str(mode or "individual").strip().lower()
    row = next((x for x in ENROLLMENT_MODES if x["id"] == clean), None)
    if row is None:
        raise ValueError("Modo de enrolamiento no permitido.")
    if clean == "individual":
        return clean, 1
    try:
        value = int(requested_uses)
    except (TypeError, ValueError):
        value = int(row["default_uses"])
    value = max(int(row["min_uses"]), min(value, int(row["max_uses"])))
    return clean, value
