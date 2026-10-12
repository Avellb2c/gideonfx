from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gideon_common.redaction import redact_error

from .agent_installers import WebAgentInstallerManager
from .auth import SecurityStore
from .gateway import GatewayFacade
from .gateway_endpoints import GatewayEndpointRegistry
from .operations import WebOperations
from .product_updates import ProductUpdateQueue
from .security_assets import SecurityAssetManager
from .ssh_vault import SshIdentityVault
from .ssh_probe import SshConnectionProbe
from .security_controls import SlidingWindowLimiter, build_security_logger
from .settings_store import RuntimeSettingsStore
from .remote_credentials import RemoteCredentialVault
from .remote_sessions import RemoteSessionPolicy, RemoteSessionStore, RemoteTargetResolver
from .guacamole import GuacamoleClientAssetStore, GuacdClient, GuacdConfig
from .remote_failsafe import disabled_remote_stack
from .media_campaigns import CampaignStore


@dataclass(slots=True)
class WebAdminServices:
    """Composition root result for WebAdmin application services.

    FastAPI route code consumes this container instead of constructing concrete
    infrastructure dependencies itself.  This keeps construction decisions in
    one place and makes individual services replaceable in tests.
    """

    security: SecurityStore
    security_assets: SecurityAssetManager
    ssh_vault: SshIdentityVault
    ssh_probe: SshConnectionProbe
    gateway: GatewayFacade
    gateway_endpoints: GatewayEndpointRegistry
    operations: WebOperations
    agent_installers: WebAgentInstallerManager
    product_updates: ProductUpdateQueue
    runtime_settings: RuntimeSettingsStore
    login_limiter: SlidingWindowLimiter
    mfa_limiter: SlidingWindowLimiter
    security_logger: Any
    remote_credentials: RemoteCredentialVault
    remote_sessions: RemoteSessionStore
    remote_targets: RemoteTargetResolver
    guacamole_assets: GuacamoleClientAssetStore
    guacd: GuacdClient
    campaigns: CampaignStore
    module_status: dict[str, dict[str, Any]]


def build_web_admin_services(
    *,
    app_root: Path,
    data_dir: Path,
    config_path: Path,
    config: dict[str, Any],
    default_session_idle_seconds: int,
) -> WebAdminServices:
    security = SecurityStore(
        data_dir / "security.sqlite3",
        idle_timeout_seconds=int(config.get("session_idle_timeout_seconds", default_session_idle_seconds)),
        max_sessions_per_user=int(config.get("max_sessions_per_user", 5)),
    )
    security_assets = SecurityAssetManager(data_dir, config)
    ssh_vault = SshIdentityVault(data_dir)
    ssh_probe = SshConnectionProbe(app_root, data_dir, ssh_vault)
    gateway = GatewayFacade(config)
    gateway_endpoints = GatewayEndpointRegistry(
        app_root, data_dir, config, web_config_path=config_path, gateway=gateway
    )
    # The Media catalogue is created before Operations so recovered upload
    # jobs can safely finish their asynchronous asset transaction after a
    # controlled WebAdmin restart.  Normal Transfers remain independent.
    campaigns = CampaignStore(data_dir, security=security)
    operations = WebOperations(
        app_root, data_dir, config, security, gateway, security_assets, ssh_vault,
        media_campaign_store=campaigns,
    )
    agent_installers = WebAgentInstallerManager(app_root, data_dir, config, security, gateway, security_assets)
    product_updates = ProductUpdateQueue(data_dir, config)
    runtime_settings = RuntimeSettingsStore(
        Path(str(config.get("runtime_settings_file") or (data_dir / "runtime_settings.json")))
    )
    # Campaign planning uses an independent, additive SQLite catalog.  It is
    # intentionally not part of auth/security.sqlite3 or gateway.sqlite3.
    login_limiter = SlidingWindowLimiter(
        window_seconds=int(config.get("login_ip_window_seconds", 600)),
        max_failures=int(config.get("login_ip_max_failures", 10)),
        ban_seconds=int(config.get("login_ip_ban_seconds", 900)),
    )
    mfa_limiter = SlidingWindowLimiter(
        window_seconds=int(config.get("login_ip_window_seconds", 600)),
        max_failures=int(config.get("mfa_ip_max_failures", 10)),
        ban_seconds=int(config.get("login_ip_ban_seconds", 900)),
    )
    module_status: dict[str, dict[str, Any]] = {
        "core": {"status": "READY", "error": ""},
        "security": {"status": "READY", "error": ""},
        "gateway_facade": {"status": "READY", "error": ""},
        "agent_installer": {"status": "READY", "error": ""},
        "media_campaigns": {"status": "READY", "error": ""},
        "remote_sessions": {"status": "STARTING", "error": ""},
    }

    # RC30: browser remote control is optional and fail-open for WebAdmin
    # availability.  Any local config/SQLite/Vault/Guacamole problem degrades
    # only the remote module; login, Agents, Jobs, Scripts and Updates remain up.
    try:
        remote_policy = RemoteSessionPolicy.from_config(config)
        remote_credentials = RemoteCredentialVault(data_dir)
        remote_sessions = RemoteSessionStore(data_dir, remote_policy)
        remote_targets = RemoteTargetResolver(remote_policy.allowed_target_cidrs)
        guacamole_assets = GuacamoleClientAssetStore(data_dir)
        guacd = GuacdClient(GuacdConfig.from_config(config))
        config["_remote_feature_boot_error"] = ""
        module_status["remote_sessions"] = {
            "status": "READY" if remote_policy.enabled else "DISABLED",
            "error": "",
        }
    except Exception as exc:
        reason = "REMOTE_FEATURE_BOOT_FAILED: " + redact_error(exc)
        config["_remote_feature_boot_error"] = reason
        module_status["remote_sessions"] = {"status": "DEGRADED", "error": reason}
        (remote_credentials, remote_sessions, remote_targets, guacamole_assets, guacd) = disabled_remote_stack(data_dir, reason)
    return WebAdminServices(
        security=security,
        security_assets=security_assets,
        ssh_vault=ssh_vault,
        ssh_probe=ssh_probe,
        gateway=gateway,
        gateway_endpoints=gateway_endpoints,
        operations=operations,
        agent_installers=agent_installers,
        product_updates=product_updates,
        runtime_settings=runtime_settings,
        login_limiter=login_limiter,
        mfa_limiter=mfa_limiter,
        security_logger=build_security_logger(config.get("security_event_log")),
        remote_credentials=remote_credentials,
        remote_sessions=remote_sessions,
        remote_targets=remote_targets,
        guacamole_assets=guacamole_assets,
        guacd=guacd,
        campaigns=campaigns,
        module_status=module_status,
    )
