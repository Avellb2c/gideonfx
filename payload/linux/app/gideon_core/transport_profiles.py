from __future__ import annotations

from gideon_common.observability import best_effort_warning

from dataclasses import dataclass
from typing import Final

SFTP_SSH_SFTP: Final = "SFTP_SSH_SFTP"
SCP_SSH_SCP: Final = "SCP_SSH_SCP"
STDIN_SSH_SCP: Final = "STDIN_SSH_SCP"

DEFAULT_TRANSPORT_PROFILE: Final = SFTP_SSH_SFTP
VALID_TRANSPORT_PROFILES: Final = {
    SFTP_SSH_SFTP,
    SCP_SSH_SCP,
    STDIN_SSH_SCP,
}


@dataclass(frozen=True, slots=True)
class TransportProfileSpec:
    id: str
    label: str
    distribution: str
    control: str
    collection: str
    required_clients: tuple[str, ...]
    description: str
    recommended: bool = False

    def manifest_transport(self) -> dict[str, str]:
        return {
            "Distribution": self.distribution,
            "Control": self.control,
            "Collection": self.collection,
        }


SPECS: dict[str, TransportProfileSpec] = {
    SFTP_SSH_SFTP: TransportProfileSpec(
        id=SFTP_SSH_SFTP,
        label="SFTP → SSH → SFTP",
        distribution="SFTP",
        control="SSH",
        collection="SFTP",
        required_clients=("ssh", "sftp"),
        description=(
            "Modo actual/recomendado. Distribuye el paquete por SFTP, "
            "inicia y monitorea por SSH, y recolecta por SFTP."
        ),
        recommended=True,
    ),
    SCP_SSH_SCP: TransportProfileSpec(
        id=SCP_SSH_SCP,
        label="SCP → SSH → SCP",
        distribution="SCP",
        control="SSH",
        collection="SCP",
        required_clients=("ssh", "scp"),
        description=(
            "Transfiere un ZIP de trabajo por SCP, lo expande remotamente, "
            "controla por SSH y devuelve un ZIP de resultados por SCP."
        ),
    ),
    STDIN_SSH_SCP: TransportProfileSpec(
        id=STDIN_SSH_SCP,
        label="STDIN/SSH → SSH → SCP",
        distribution="SSH_STDIN",
        control="SSH",
        collection="SCP",
        required_clients=("ssh", "scp"),
        description=(
            "Modo histórico optimizado: el paquete viaja como Base64 por STDIN "
            "de ssh.exe, sin archivo de subida SFTP/SCP; el control sigue por SSH "
            "y la recolección se realiza por SCP."
        ),
    ),
}


def normalize_transport_profile(value: str | None) -> str:
    raw = str(value or "").strip().upper().replace("-", "_")
    aliases = {
        "SFTP": SFTP_SSH_SFTP,
        "CURRENT": SFTP_SSH_SFTP,
        "ACTUAL": SFTP_SSH_SFTP,
        "SCP": SCP_SSH_SCP,
        "STDIN": STDIN_SSH_SCP,
        "SSH_STDIN": STDIN_SSH_SCP,
    }
    raw = aliases.get(raw, raw)
    if not raw:
        return DEFAULT_TRANSPORT_PROFILE
    if raw not in VALID_TRANSPORT_PROFILES:
        raise ValueError(f"TransportProfile no soportado: {value}")
    return raw


def get_transport_profile(value: str | None) -> TransportProfileSpec:
    return SPECS[normalize_transport_profile(value)]


def profile_from_manifest(manifest: dict) -> str:
    explicit = manifest.get("TransportProfile")
    if explicit:
        try:
            return normalize_transport_profile(str(explicit))
        except Exception as exc:
            best_effort_warning(f"TransportProfile inválido en manifest: {explicit}", exc)

    transport = manifest.get("Transport") or {}
    dist = str(transport.get("Distribution") or "").upper()
    collect = str(transport.get("Collection") or "").upper()
    if dist == "SCP" and collect == "SCP":
        return SCP_SSH_SCP
    if dist in {"SSH_STDIN", "STDIN"} and collect == "SCP":
        return STDIN_SSH_SCP
    return SFTP_SSH_SFTP
