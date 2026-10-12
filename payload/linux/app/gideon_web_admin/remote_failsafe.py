from __future__ import annotations

"""Fail-safe placeholders for the optional browser remote-session stack.

The remote desktop feature must never be able to prevent WebAdmin from
starting.  These placeholders keep the rest of the application usable when
Guacamole/remote-session initialization fails because of local permissions,
SQLite state, malformed configuration, missing assets, or an unavailable
runtime component.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RemoteFeatureUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DisabledRemotePolicy:
    enabled: bool = False
    ticket_ttl_seconds: int = 60
    max_session_seconds: int = 14400
    max_active_sessions: int = 0
    max_sessions_per_user: int = 0
    max_sessions_per_target: int = 0
    connect_timeout_seconds: float = 1.0
    bind_ticket_to_ip: bool = True
    clipboard_enabled: bool = False
    file_transfer_enabled: bool = False
    max_clipboard_bytes: int = 1024 * 1024
    max_file_transfer_bytes: int = 100 * 1024 * 1024
    allowed_target_cidrs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DisabledGuacdConfig:
    host: str = "127.0.0.1"
    port: int = 4822
    vnc_enabled: bool = False
    rdp_security: str = "nla"
    rdp_ignore_cert: bool = False
    rdp_disable_copy: bool = True
    rdp_disable_paste: bool = True


class DisabledRemoteCredentialVault:
    def __init__(self, reason: str) -> None:
        self.reason = str(reason)

    def list_credentials(self, protocol: str | None = None) -> list[dict[str, Any]]:
        return []

    def create(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise RemoteFeatureUnavailable(self.reason)

    def delete(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise RemoteFeatureUnavailable(self.reason)

    def reveal_for_session(self, *args: Any, **kwargs: Any) -> dict[str, str]:
        raise RemoteFeatureUnavailable(self.reason)


class DisabledRemoteSessionStore:
    def __init__(self, reason: str) -> None:
        self.reason = str(reason)
        self.policy = DisabledRemotePolicy()

    def stats(self) -> dict[str, Any]:
        return {"enabled": False, "active": 0, "issued": 0, "degraded": True, "error": self.reason}

    def issue(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)

    def get_for_user(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)

    def consume(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)

    def close(self, *args: Any, **kwargs: Any) -> None:
        return None


class DisabledRemoteTargetResolver:
    def __init__(self, reason: str) -> None:
        self.reason = str(reason)

    def agent_candidates(self, *args: Any, **kwargs: Any) -> list[str]:
        return []

    def resolve_agent(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)

    def resolve_host(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)

    def probe(self, *args: Any, **kwargs: Any) -> tuple[bool, str]:
        return False, self.reason


class DisabledGuacamoleClientAssetStore:
    def __init__(self, data_dir: Path, reason: str) -> None:
        self.reason = str(reason)
        self.asset = Path(data_dir) / "disabled-guacamole-common.min.js"

    def status(self) -> dict[str, Any]:
        return {"ready": False, "version": "", "sha256": "", "degraded": True, "error": self.reason}

    def install(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)


class DisabledGuacdClient:
    def __init__(self, reason: str) -> None:
        self.reason = str(reason)
        self.config = DisabledGuacdConfig()

    def health(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "online": False,
            "host": self.config.host,
            "port": self.config.port,
            "degraded": True,
            "error": self.reason,
        }

    async def connect_and_handshake(self, *args: Any, **kwargs: Any):
        raise RemoteFeatureUnavailable(self.reason)


def disabled_remote_stack(data_dir: Path, reason: str):
    return (
        DisabledRemoteCredentialVault(reason),
        DisabledRemoteSessionStore(reason),
        DisabledRemoteTargetResolver(reason),
        DisabledGuacamoleClientAssetStore(data_dir, reason),
        DisabledGuacdClient(reason),
    )
