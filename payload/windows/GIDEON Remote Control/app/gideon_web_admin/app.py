from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask

from gideon_version import AGENT_VERSION, GATEWAY_VERSION, PRODUCT_VERSION
from gideon_license import GideonLicenseError, enforce_executive_license
from gideon_product_update import UpdateError, validate_update_transition
from gideon_agent_update_builder import stable_release_targets
from gideon_common.redaction import redact, redact_error

from .auth import ROLE_PERMISSIONS
from .security_assets import SecurityAssetError, MAX_PRIVATE_KEY_BYTES, MAX_CA_BYTES, MAX_YARA_BYTES, MAX_SSH_PUBLIC_KEY_BYTES
from .dependency_inventory import DependencyInventory
from .ssh_vault import (
    SshVaultError, MAX_SSH_PRIVATE_KEY_BYTES, MAX_SSH_FOLDER_FILES,
    MAX_SSH_FOLDER_TOTAL_BYTES, classify_private_key_blob,
)
from .agent_installers import AgentInstallerError
from .installer_history import filter_installer_history
from .diagnostics import build_agent_diagnostic, diagnostic_text, effective_state
from .services import build_web_admin_services
from .request_security import RequestSecurity
from .ingress_security import AdminNetworkBoundary
from .tls_management import register_tls_routes
from .step_up_cache import STEP_UP_CACHE
from .installer_orchestration import InstallerBuildOrchestrator
from .gateway import DisabledReleaseManager, WebAgentReleaseManager
from .remote_credentials import RemoteCredentialError
from .remote_sessions import RemoteSessionError
from .media_campaigns import CampaignConflictError, CampaignStoreError
from .media_manifest import MediaManifestError, build_payload as build_player_manifest_payload, sign_payload as sign_player_manifest
from .vlc_offline_install import OfflineVlcAuthorizationError, authorization_audit_metadata, build_install_authorization
from .rdp_capabilities import select_agent_rdp_profile, select_agent_remote_profile
from .guacamole import GuacamoleError, MAX_GUAC_CLIENT_JS_BYTES, guac_instruction, parse_guac_instruction
from .resource_metrics import ServerResourceMetrics
from .static_assets import StaticAssetUrls


LOG = logging.getLogger(__name__)
SESSION_COOKIE = "gideon_admin_session"
DEFAULT_SESSION_TTL_SECONDS = 43200
DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS = 43200
MAX_REMOTE_CREDENTIAL_ROUNDS = 3
REMOTE_RETRYABLE_CLASSIFICATIONS = frozenset({
    "RDP_AUTHENTICATION_FAILED",
    "RDP_AUTHENTICATION",
    "RDP_NLA_PASSWORD_REQUIRED",
    "RDP_SECURITY_NEGOTIATION",
    "RDP_CERTIFICATE",
})
REMOTE_RETRYABLE_END_REASONS = frozenset(REMOTE_RETRYABLE_CLASSIFICATIONS)
REMOTE_AUTOMATIC_SECURITY_CLASSIFICATIONS = frozenset({
    "RDP_SECURITY_NEGOTIATION",
    "RDP_CERTIFICATE",
})
REMOTE_AUTOMATIC_SECURITY_END_REASONS = frozenset(REMOTE_AUTOMATIC_SECURITY_CLASSIFICATIONS)

# Only these routes receive caller-supplied file bytes.  The WebAdmin
# middleware must reserve disk space before FastAPI can spool multipart input,
# but applying that check to every POST also blocks ordinary metadata actions
# (for example restoring a logically archived Screen) whenever the VM is below
# its upload reserve.  Keep the list explicit so a new upload endpoint is a
# deliberate security review point.
UPLOAD_RECEIVING_PERMISSIONS = {
    "/transfers": "transfers.manage",
    "/media/assets/upload": "media.manage",
    "/scripts/upload": "scripts.manage",
    "/system-updates/upload": "system_updates.manage",
    "/security/assets/signing/import": "security_assets.manage",
    "/security/assets/ca/upload": "security_assets.manage",
    "/security/assets/yara/upload": "security_assets.manage",
    "/security/assets/ssh-public/upload": "security_assets.manage",
    "/security/assets/ssh-identity/upload": "security_assets.manage",
    "/security/assets/ssh-identity/folder-upload": "security_assets.manage",
    "/security/assets/guacamole-client/upload": "security_assets.manage",
}


def _requires_storage_reserve_preflight(request_path: str) -> bool:
    """Return whether a request can spool/receive caller-supplied bytes.

    TLS management accepts bounded JSON containing certificate material rather
    than a multipart file, but it still needs the same free-space protection.
    Screen restore, campaign controls and other metadata-only requests must
    remain available even while uploads are deliberately paused by the reserve.
    """
    clean_path = str(request_path or "")
    return clean_path in UPLOAD_RECEIVING_PERMISSIONS or clean_path.startswith("/infrastructure/tls/")


def _request_version_token(request: Request, payload: dict[str, Any] | None = None) -> str:
    """Return an optimistic-concurrency token from JSON or a standard ETag.

    Browser forms carry the opaque value in a hidden field, while API clients
    may send it as ``version_token`` or ``If-Match``.  Accept the normal quoted
    ETag spelling without making the storage layer aware of HTTP syntax.
    """
    value = ""
    if isinstance(payload, dict):
        value = str(payload.get("version_token") or payload.get("expected_version_token") or "")
    if not value:
        value = str(request.headers.get("if-match") or "")
    value = value.strip()
    if value.startswith("W/"):
        value = value[2:].strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value


def _agent_version_key(value: str) -> tuple[int, int, int, int]:
    parts: list[int] = []
    for token in str(value or "0").split(".")[:4]:
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits or 0))
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def _approved_agent_releases(releases: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    approved: dict[tuple[str, str], dict[str, Any]] = {}
    for release in releases:
        if str(release.get("approval_state") or "").upper() != "APPROVED" or str(release.get("channel") or "").lower() != "stable":
            continue
        key = (str(release.get("platform") or "").lower(), str(release.get("architecture") or "").lower())
        current = approved.get(key)
        if current is None or _agent_version_key(str(release.get("version") or "")) > _agent_version_key(str(current.get("version") or "")):
            approved[key] = release
    return approved


def _decorate_agent_update(agent: dict[str, Any], release: dict[str, Any] | None) -> dict[str, Any]:
    diagnostics = agent.get("Diagnostics") if isinstance(agent.get("Diagnostics"), dict) else {}
    diagnostic_agent = diagnostics.get("agent") if isinstance(diagnostics.get("agent"), dict) else {}
    update = diagnostics.get("update") if isinstance(diagnostics.get("update"), dict) else {}
    request = agent.get("UpdateRequest") if isinstance(agent.get("UpdateRequest"), dict) else {}
    installed = str(agent.get("agent_version") or diagnostic_agent.get("agent_version") or "").strip()
    stable = str((release or {}).get("version") or "").strip()
    current = bool(stable and installed and _agent_version_key(installed) >= _agent_version_key(stable))
    agent["agent_version"] = installed
    agent["_stable"] = stable
    agent["_current"] = current
    agent["_update"] = bool(stable and not current)
    reported = str(update.get("state") or "UNKNOWN").upper()
    request_state = str(request.get("status") or "").upper()
    active_states = {"CHECK_REQUESTED", "CHECKING", "DOWNLOADING", "VERIFYING", "UPDATING", "APPLYING", "RESTARTING", "UPDATE_DEFERRED_BUSY"}
    if current:
        code, label, css = "CURRENT", "Al día", "success"
    elif request_state == "FAILED" or reported in {"UPDATE_ERROR", "ROLLED_BACK"}:
        code, label, css = "UPDATE_ERROR", "Falló", "danger"
    elif reported in active_states:
        code, label, css = reported, {
            "CHECK_REQUESTED": "Solicitud recibida", "CHECKING": "Comprobando", "DOWNLOADING": "Descargando",
            "VERIFYING": "Verificando firma", "UPDATING": "Programando", "APPLYING": "Instalando",
            "RESTARTING": "Reiniciando Agent", "UPDATE_DEFERRED_BUSY": "Esperando sesión o Job activo",
        }.get(reported, reported), "info"
    elif request_state in {"REQUESTED", "DELIVERED"}:
        code, label, css = request_state, "Solicitud en cola" if request_state == "REQUESTED" else "Entregada al Agent", "info"
    elif stable:
        code, label, css = "UPDATE_AVAILABLE", "Actualización disponible", "warning"
    else:
        code, label, css = "NO_RELEASE", "Sin release estable", "warning"
    agent["_update_state"] = code
    agent["_update_label"] = label
    agent["_update_css"] = css
    agent["_update_target"] = str(update.get("target_version") or request.get("target_version") or stable)
    agent["_update_checked_at"] = str(update.get("checked_at") or update.get("updated_at") or request.get("delivered_at") or request.get("requested_at") or "")
    agent["_update_detail"] = str(request.get("detail") or update.get("last_error") or "")
    return agent


def normalize_rdp_identity(username: str, domain: str = "") -> tuple[str, str]:
    """Accept Windows' DOMAIN\\user notation without sending it as one username."""
    clean_user = str(username or "").strip()
    clean_domain = str(domain or "").strip()
    if not clean_domain and "\\" in clean_user:
        prefix, account = clean_user.split("\\", 1)
        if prefix and account:
            clean_domain, clean_user = prefix, account
    return clean_user, clean_domain


def rdp_identity_matches_console(
    username: str, domain: str, console_username: str, console_domain: str = ""
) -> bool:
    """Compare a submitted RDP identity with the Agent's secret-free WTS observation."""
    requested_user, requested_domain = normalize_rdp_identity(username, domain)
    observed_user, observed_domain = normalize_rdp_identity(console_username, console_domain)
    if not requested_user or not observed_user or requested_user.casefold() != observed_user.casefold():
        return False
    requested_scope = requested_domain.strip().casefold()
    observed_scope = observed_domain.strip().casefold()
    return not requested_scope or requested_scope == "." or not observed_scope or requested_scope == observed_scope


def rdp_security_modes(preferred: str, *, allow_legacy: bool = False) -> tuple[str, ...]:
    """Return the bounded RDP negotiation plan for one password submission."""
    first = str(preferred or "nla").strip().lower()
    allowed = {"any", "nla", "tls", "rdp"} if allow_legacy else {"any", "nla", "tls"}
    if first not in allowed:
        first = "nla"
    candidates = (first, "any", "nla", "tls", "rdp") if allow_legacy else (first, "any", "nla", "tls")
    sequence: list[str] = []
    for value in candidates:
        if value == "rdp" and not allow_legacy:
            continue
        if value not in sequence:
            sequence.append(value)
    return tuple(sequence)


def rdp_security_attempt(
    preferred: str,
    attempt: int,
    *,
    legacy_previous_missing: bool = False,
    allow_legacy: bool = True,
) -> str:
    """Return one deterministic mode from a password's compatibility plan."""
    first = str(preferred or "nla").strip().lower()
    if first not in {"any", "nla", "tls", "rdp"}:
        first = "nla"
    if legacy_previous_missing and int(attempt or 1) > 1:
        # Sessions issued before this field existed actually used hard-coded ANY.
        # Their first retry must honor the configured mode instead of repeating ANY.
        return first
    sequence = rdp_security_modes(first, allow_legacy=allow_legacy)
    index = max(0, min(int(attempt or 1) - 1, len(sequence) - 1))
    return sequence[index]


def load_web_config(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("web_admin.json debe contener un objeto JSON.")
    return value


def _remote_ip(request: Request) -> str:
    trusted = bool(request.app.state.web_config.get("trust_proxy_headers", False))
    if trusted:
        forwarded = str(request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return str(request.client.host if request.client else "")


def normalize_session_policy(config: dict[str, Any]) -> dict[str, Any]:
    """Return the effective Web session policy, including legacy-default migration.

    P3 and older shipped 8 h absolute / 30 min idle values.  When those exact
    legacy defaults are found, upgrade them in memory to the P4 workday policy
    without rewriting an operator-customized config file.
    """
    effective = dict(config)
    policy = str(effective.get("session_policy") or "").strip().lower()
    try:
        ttl = int(effective.get("session_ttl_seconds", DEFAULT_SESSION_TTL_SECONDS))
    except (TypeError, ValueError):
        ttl = DEFAULT_SESSION_TTL_SECONDS
    try:
        idle = int(effective.get("session_idle_timeout_seconds", DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        idle = DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS
    legacy_defaults = ttl == 28800 and idle == 1800 and not policy
    if policy == "workday" or legacy_defaults:
        effective["session_ttl_seconds"] = DEFAULT_SESSION_TTL_SECONDS
        effective["session_idle_timeout_seconds"] = DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS
        effective["session_policy"] = "workday"
    return effective


def _script_self_approval_blocked(
    config: dict[str, Any],
    *,
    created_by: str,
    actor: str,
    actor_role: str,
) -> bool:
    """Return whether dual-control must reject a same-actor script approval.

    The normal maker/checker rule stays fail-closed for ADMIN and every other
    role.  SUPERADMIN may use the explicit emergency/solo-admin override when
    ``allow_superadmin_self_script_approval`` is enabled (default: enabled).
    Malware scanning remains a separate mandatory gate and is evaluated before
    this policy in the approval route.
    """
    if not bool(config.get("require_dual_script_approval", True)):
        return False
    if str(created_by or "").casefold() != str(actor or "").casefold():
        return False
    role = str(actor_role or "").strip().upper()
    if role == "SUPERADMIN" and bool(config.get("allow_superadmin_self_script_approval", True)):
        return False
    return True


def create_app(config_path: str | Path | None = None, *, config_override: dict[str, Any] | None = None) -> FastAPI:
    app_root = Path(__file__).resolve().parent.parent
    path = Path(config_path or os.environ.get("GIDEON_WEB_ADMIN_CONFIG") or (app_root / "config" / "web_admin.json"))
    config = normalize_session_policy(dict(config_override or load_web_config(path)))
    data_dir = Path(os.path.expandvars(str(config.get("data_dir") or "/var/lib/gideon-web-admin"))).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    edition = str(os.environ.get("GIDEON_EDITION") or config.get("edition") or "opensource").strip().lower()
    if edition not in {"opensource", "executive"}:
        raise RuntimeError("GIDEON_EDITION_INVALID")
    license_state: dict[str, Any] = {"Edition": edition, "Status": "NOT_REQUIRED" if edition == "opensource" else "UNKNOWN"}
    if edition == "executive":
        try:
            verified = enforce_executive_license(config, data_dir)
            license_state = {
                "Edition": edition,
                "Status": "VALID",
                "Customer": str(verified.get("Customer") or ""),
                "ExpiresAt": str(verified.get("ExpiresAt") or ""),
                "DaysRemaining": int(verified.get("_DaysRemaining") or 0),
            }
        except GideonLicenseError as exc:
            raise RuntimeError(str(exc)) from exc
    # RC30.95.31.7: make the 15-minute MFA step-up window durable and shared
    # across independent HTTP requests / WebAdmin process cycles. Only approval
    # timestamps keyed to the authenticated WebAdmin session are persisted.
    STEP_UP_CACHE.configure(data_dir / "security-step-up.sqlite3")
    services = build_web_admin_services(
        app_root=app_root,
        data_dir=data_dir,
        config_path=path,
        config=config,
        default_session_idle_seconds=DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
    )
    security = services.security
    security_assets = services.security_assets
    ssh_vault = services.ssh_vault
    ssh_probe = services.ssh_probe
    gateway = services.gateway
    gateway_endpoints = services.gateway_endpoints
    operations = services.operations
    agent_installers = services.agent_installers
    product_updates = services.product_updates
    runtime_settings = services.runtime_settings
    login_limiter = services.login_limiter
    mfa_limiter = services.mfa_limiter
    security_logger = services.security_logger
    remote_credentials = services.remote_credentials
    remote_sessions = services.remote_sessions
    remote_targets = services.remote_targets
    guacamole_assets = services.guacamole_assets
    guacd = services.guacd
    campaigns = services.campaigns
    module_status = services.module_status
    remote_policy_config = config.get("remote_sessions") if isinstance(config.get("remote_sessions"), dict) else {}
    allow_legacy_rdp_policy = str(remote_policy_config.get("allow_legacy_rdp_fallback", "false")).strip().lower() in {"1", "true", "yes", "on"}
    try:
        rdp_capability_max_age_seconds = max(30, min(int(remote_policy_config.get("rdp_capability_max_age_seconds", 180)), 900))
    except (TypeError, ValueError):
        rdp_capability_max_age_seconds = 180
    request_security = RequestSecurity(
        security=security,
        config=config,
        session_cookie=SESSION_COOKIE,
        default_session_ttl_seconds=DEFAULT_SESSION_TTL_SECONDS,
    )
    installer_orchestrator = InstallerBuildOrchestrator(agent_installers, gateway_endpoints)
    try:
        release_manager = WebAgentReleaseManager(app_root, data_dir, gateway, security_assets)
        module_status["release_manager"] = {"status": "READY", "error": ""}
    except Exception as exc:
        reason = "RELEASE_MANAGER_BOOT_FAILED: " + redact_error(exc)
        module_status["release_manager"] = {"status": "DEGRADED", "error": reason}
        release_manager = DisabledReleaseManager(reason)
    resource_metrics = ServerResourceMetrics(app_root, cache_ttl_seconds=5)

    app = FastAPI(title="Gideon Rx Web Admin", version=PRODUCT_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(AdminNetworkBoundary, allowed_cidrs=config.get('admin_allowed_cidrs'))
    app.state.web_config = config
    app.state.gideon_edition = edition
    app.state.gideon_license = license_state
    app.state.security = security
    app.state.gateway = gateway
    app.state.gateway_endpoints = gateway_endpoints
    app.state.operations = operations
    app.state.security_assets = security_assets
    app.state.ssh_vault = ssh_vault
    app.state.ssh_probe = ssh_probe
    app.state.agent_installers = agent_installers
    app.state.product_updates = product_updates
    app.state.runtime_settings = runtime_settings
    app.state.login_limiter = login_limiter
    app.state.mfa_limiter = mfa_limiter
    app.state.security_logger = security_logger
    app.state.remote_credentials = remote_credentials
    app.state.remote_sessions = remote_sessions
    app.state.remote_targets = remote_targets
    app.state.guacamole_assets = guacamole_assets
    app.state.guacd = guacd
    app.state.campaigns = campaigns
    app.state.app_root = app_root
    app.state.release_manager = release_manager
    app.state.module_status = module_status
    app.state.resource_metrics = resource_metrics
    templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
    static_root = (Path(__file__).resolve().parent / "static").resolve()
    # HTML must never accidentally reference a stale script/style after a
    # deployment.  A content fingerprint gives static responses a safe,
    # immutable browser-cache lifetime without relying on manually maintained
    # RC query strings that can drift between templates.
    static_assets = StaticAssetUrls(static_root)
    templates.env.globals["static_url"] = static_assets.url
    app.mount("/static", StaticFiles(directory=str(static_root)), name="static")
    # The Guacamole browser client is served through one explicit authenticated
    # endpoint below.  Do not mount the whole managed directory: metadata and
    # future files in that directory must never become web-addressable by
    # accident.

    def _sanitize_error_fields(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {k: _sanitize_error_fields(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize_error_fields(v, key) for v in value]
        low = str(key or "").lower()
        if any(part in low for part in ("error", "traceback", "exception")) and value not in (None, ""):
            return redact_error(value)
        return value

    def template(request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> HTMLResponse:
        identity = current_identity(request, allow_incomplete=True)
        base = {
            "request": request, "identity": identity, "product_version": PRODUCT_VERSION,
            "agent_version": AGENT_VERSION, "gateway_version": GATEWAY_VERSION,
            "active_path": request.url.path, "now": dt.datetime.now().astimezone(),
            "roles": sorted(ROLE_PERMISSIONS),
            "step_up": request_security.step_up_context(request),
        }
        base.update(_sanitize_error_fields(dict(context)))
        return templates.TemplateResponse(request, name, base, status_code=status_code)

    # Route-friendly aliases keep handler code small while request/session policy
    # remains centralized in RequestSecurity.
    set_session_cookie = request_security.set_session_cookie
    current_identity = request_security.current_identity
    require = request_security.require
    validate_csrf = request_security.validate_csrf
    require_superadmin_step_up = request_security.require_superadmin_step_up
    require_step_up = request_security.require_step_up
    require_mfa_step_up = request_security.require_mfa_step_up

    async def require_superadmin_step_up_async(
        request: Request,
        identity: Any,
        password: str,
        mfa_code: str,
        *,
        resource: str = "sensitive-operation",
    ) -> dict[str, int | bool]:
        """Keep Argon2 verification away from the shared asyncio event loop."""
        return await asyncio.to_thread(
            require_superadmin_step_up, request, identity, password, mfa_code,
            resource=resource,
        )

    register_tls_routes(app, config=config, require=require, security=security, template=template)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Reject protected uploads before FastAPI parses/spools multipart bodies.
        # This prevents an unauthenticated request from consuming the VM disk.
        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.url.path not in {"/login", "/bootstrap", "/account/recovery"}:
            early_identity = await asyncio.to_thread(
                current_identity, request, allow_incomplete=True
            )
            if early_identity is None:
                return RedirectResponse("/login?next=" + str(request.url.path), status_code=303)
            required_upload_permission = UPLOAD_RECEIVING_PERMISSIONS.get(request.url.path)
            if required_upload_permission and not early_identity.can(required_upload_permission):
                return HTMLResponse("No autorizado", status_code=403)
            if request.url.path.startswith('/infrastructure/tls/'):
                if early_identity.role != 'SUPERADMIN':
                    return HTMLResponse('Solo SuperAdmin', status_code=403)
                if request.headers.get('content-type', '').split(';')[0].strip() != 'application/json':
                    return HTMLResponse('Se requiere application/json', status_code=415)
                try:
                    if int(request.headers.get('content-length') or '0') > 8 * 1024 * 1024:
                        return HTMLResponse('Archivos TLS demasiado grandes', status_code=413)
                except ValueError:
                    return HTMLResponse('Content-Length inválido', status_code=400)
            if _requires_storage_reserve_preflight(request.url.path):
                try:
                    content_length = int(request.headers.get("content-length") or "0")
                except ValueError:
                    content_length = 0
                # Preserve a configurable emergency free-space reserve before
                # multipart parsing can spool an upload to the VM volume.  This
                # intentionally excludes metadata-only actions such as Screen
                # restore, which never receive a file.
                min_free = max(256 * 1024 * 1024, int(config.get("min_free_disk_bytes", 1024 * 1024 * 1024)))
                try:
                    free_now = shutil.disk_usage(data_dir).free
                except OSError:
                    free_now = min_free + max(0, content_length)
                if content_length > 0 and free_now - content_length < min_free:
                    try:
                        security.audit(
                            early_identity.username, "uploads.storage_preflight", "FAILED",
                            "Upload rejected because the protected VM free-space reserve would be crossed.",
                            request_security.remote_ip(request), resource=request.url.path, role=early_identity.role,
                        )
                    except Exception:
                        # The storage guard must stay fail-closed even if an
                        # audit write cannot be persisted on a nearly full disk.
                        pass
                    return template(
                        request,
                        "error.html",
                        {
                            "title": "Espacio temporal insuficiente",
                            "error": "No se recibió ningún archivo. Libere espacio mediante la limpieza controlada de GIDEON y vuelva a intentar la carga.",
                        },
                        status_code=507,
                    )
                if request.url.path in {"/transfers", "/media/assets/upload"}:
                    configured_limit = "max_media_upload_bytes" if request.url.path == "/media/assets/upload" else "max_transfer_upload_bytes"
                    body_limit = int(config.get(configured_limit, config.get("max_transfer_upload_bytes", 1024 * 1024 * 1024))) + 2 * 1024 * 1024
                    if content_length > body_limit:
                        return HTMLResponse("Archivo demasiado grande", status_code=413)
                if request.url.path == "/scripts/upload":
                    body_limit = int(config.get("max_script_upload_bytes", 5 * 1024 * 1024)) + 1024 * 1024
                    if content_length > body_limit:
                        return HTMLResponse("Script demasiado grande", status_code=413)
                if request.url.path == "/system-updates/upload":
                    body_limit = int(config.get("max_system_update_upload_bytes", 50 * 1024 * 1024)) + 2 * 1024 * 1024
                    if content_length > body_limit:
                        return HTMLResponse("Paquete de actualización demasiado grande", status_code=413)
                if request.url.path == "/security/assets/guacamole-client/upload":
                    body_limit = MAX_GUAC_CLIENT_JS_BYTES + 1024 * 1024
                    if content_length > body_limit:
                        return HTMLResponse("Cliente Guacamole demasiado grande", status_code=413)
                elif request.url.path.startswith("/security/assets/"):
                    body_limit = 3 * 1024 * 1024
                    if content_length > body_limit:
                        return HTMLResponse("Activo de seguridad demasiado grande", status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self' wss:; img-src 'self' data:; style-src 'self'; script-src 'self'; worker-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.url.scheme == "https" or str(request.headers.get("x-forwarded-proto") or "").lower() == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith("/static/"):
            # Only fingerprints created by ``static_url`` receive a long
            # cache lifetime.  Old bookmarks and an operator-added URL stay
            # revalidated, so a mixed HTML/static deployment cannot persist.
            fingerprint = str(request.query_params.get("v") or "")
            asset_name = request.url.path.removeprefix("/static/")
            if re.fullmatch(r"[0-9a-f]{16}", fingerprint) and static_assets.matches(asset_name, fingerprint):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            else:
                response.headers["Cache-Control"] = "no-cache"
        elif request.url.path not in {"/healthz"}:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_exception(request: Request, exc: HTTPException):
        if exc.status_code == 401:
            return RedirectResponse("/login?next=" + str(request.url.path), status_code=303)
        identity = await asyncio.to_thread(current_identity, request, allow_incomplete=True)
        if identity is None:
            return RedirectResponse("/login?next=" + str(request.url.path), status_code=303)
        if exc.status_code == 428 and exc.detail == "MFA_REQUIRED":
            return RedirectResponse("/mfa" if identity and identity.mfa_enabled else "/account/mfa/setup", status_code=303)
        if exc.status_code == 428 and exc.detail == "PASSWORD_CHANGE_REQUIRED":
            return RedirectResponse("/account/password", status_code=303)
        return template(request, "error.html", {"title": "Operación no disponible", "error": str(exc.detail)}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception):
        """Return a safe, traceable response instead of FastAPI's blank 500 page.

        A browser viewer may otherwise receive only ``Internal Server Error`` if
        an optional remote-session dependency fails while rendering its page.
        Keep the actual exception server-side, associate it with an audit event,
        and provide the operator an opaque ID that can be correlated in logs.
        """
        error_id = "web-" + secrets.token_hex(8)
        detail = redact_error(exc)
        LOG.error("unhandled web request id=%s path=%s type=%s detail=%s", error_id, request.url.path, type(exc).__name__, detail)
        try:
            identity = await asyncio.to_thread(current_identity, request, allow_incomplete=True)
            security.audit(
                str(getattr(identity, "username", "system") or "system"),
                "web.request.unhandled", "FAILED",
                f"Id={error_id}; Type={type(exc).__name__}; Detail={detail}",
                request_security.remote_ip(request), resource=str(request.url.path)[:512],
                role=str(getattr(identity, "role", "") or "SYSTEM"),
            )
        except Exception:
            # Error reporting must never replace the original recovery response.
            pass
        message = f"La página no pudo completarse. Código de diagnóstico: {error_id}."
        wants_json = request.url.path.startswith("/api/") or "application/json" in str(request.headers.get("accept") or "").lower()
        if wants_json:
            return JSONResponse({"detail": message, "error_id": error_id}, status_code=500)
        try:
            return template(request, "error.html", {"title": "Error interno controlado", "error": message}, status_code=500)
        except Exception:
            return HTMLResponse(message, status_code=500)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        # Readiness must never depend on Gateway/guacd network calls and must not
        # fail because an optional SQLite-backed feature is degraded.  If this
        # route can execute, the WebAdmin core is serving HTTP.
        try:
            users_configured: bool | None = security.user_count() > 0
            security_status = "READY"
            security_error = ""
        except Exception as exc:
            users_configured = None
            security_status = "DEGRADED"
            security_error = redact_error(exc)
        modules = {key: dict(value) for key, value in module_status.items()}
        modules["security"] = {"status": security_status, "error": security_error}
        gateway_state = gateway.resilience_state()
        modules["gateway_facade"] = {
            "status": "DEGRADED" if bool(gateway_state.get("CircuitOpen")) else "READY",
            "error": redact_error(gateway_state.get("LastError")) if gateway_state.get("LastError") else "",
        }
        degraded = sorted(
            key for key, value in modules.items()
            if str(value.get("status") or "").upper() == "DEGRADED"
        )
        remote = modules.get("remote_sessions") or {"status": "UNKNOWN", "error": ""}
        return {
            "Ok": True,
            "Status": "DEGRADED" if degraded else "HEALTHY",
            "Service": "GIDEON Web Admin",
            "Version": PRODUCT_VERSION,
            "UsersConfigured": users_configured,
            "Modules": modules,
            "DegradedModules": degraded,
            # Backward-compatible fields consumed by RC29 diagnostics.
            "RemoteSessions": str(remote.get("status") or "UNKNOWN"),
            "RemoteSessionsError": str(remote.get("error") or ""),
        }

    @app.get("/remote-client/guacamole-common.min.js", response_class=FileResponse)
    def guacamole_browser_client(request: Request):
        # The JS bundle is public upstream code but GIDEON still serves it only to
        # authenticated operators, and only this exact file is exposed.
        require(request, "remote.view")
        status = guacamole_assets.status()
        if not bool(status.get("ready")) or not guacamole_assets.asset.is_file():
            raise HTTPException(404, "Cliente Guacamole no provisionado.")
        return FileResponse(
            str(guacamole_assets.asset),
            media_type="application/javascript",
            filename="guacamole-common.min.js",
            headers={
                "Cache-Control": "private, max-age=3600, immutable",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "/"):
        if security.user_count() == 0:
            return template(request, "bootstrap.html", {"title": "Configuración inicial"})
        if current_identity(request, allow_incomplete=True):
            return RedirectResponse("/", status_code=303)
        return template(request, "login.html", {"title": "Iniciar sesión", "next": next, "error": ""})

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
        ip = request_security.remote_ip(request)
        decision = login_limiter.check(ip)
        if not decision.allowed:
            security_logger.warning("AUTH_RATE_LIMIT ip=%s retry_after=%s", ip, decision.retry_after)
            return template(request, "login.html", {"title": "Iniciar sesión", "next": next, "error": f"Demasiados intentos. Espere {decision.retry_after} segundos."}, status_code=429)
        row = security.authenticate_password(username, password)
        if not row or row.get("locked"):
            decision = login_limiter.failure(ip)
            security.audit(str(username or ""), "auth.login", "FAILED", "Credenciales inválidas o cuenta bloqueada", ip)
            security_logger.warning("AUTH_LOGIN_FAILED ip=%s user=%s banned=%s", ip, str(username or "")[:128], not decision.allowed)
            return template(request, "login.html", {"title": "Iniciar sesión", "next": next, "error": "Usuario, contraseña o estado de cuenta inválido."}, status_code=401)
        login_limiter.success(ip)
        security_logger.info("AUTH_LOGIN_PASSWORD_OK ip=%s user=%s", ip, str(row.get("username") or "")[:128])
        mfa_complete = not bool(row.get("mfa_enabled"))
        raw, _ = security.create_session(int(row["id"]), remote_ip=ip, user_agent=str(request.headers.get("user-agent") or ""), ttl_seconds=int(config.get("session_ttl_seconds", DEFAULT_SESSION_TTL_SECONDS)), mfa_complete=mfa_complete)
        security.audit(str(row["username"]), "auth.login", "SUCCESS", "Contraseña validada", ip, role=str(row["role"]))
        target = "/account/password" if bool(row.get("must_change_password")) else ("/mfa" if bool(row.get("mfa_enabled")) else ("/account/mfa/setup" if bool(config.get("require_mfa", True)) else next))
        response = RedirectResponse(target, status_code=303)
        set_session_cookie(response, raw)
        return response

    @app.get("/bootstrap", response_class=HTMLResponse)
    def bootstrap_page(request: Request):
        if security.user_count() > 0:
            return RedirectResponse("/login", status_code=303)
        return template(request, "bootstrap.html", {"title": "Configuración inicial", "error": ""})

    @app.post("/bootstrap", response_class=HTMLResponse)
    def bootstrap(
        request: Request,
        username: str = Form(...),
        display_name: str = Form(...),
        password: str = Form(...),
        confirm: str = Form(...),
        bootstrap_token: str = Form(""),
    ):
        if security.user_count() > 0:
            raise HTTPException(status_code=409, detail="La configuración inicial ya fue completada.")
        bootstrap_token_env = str(config.get("bootstrap_token_env") or "GIDEON_WEB_BOOTSTRAP_TOKEN")
        expected = os.environ.get(bootstrap_token_env, "")
        submitted = str(bootstrap_token or "")
        if bool(config.get("require_bootstrap_token", True)) and not expected:
            return template(request, "bootstrap.html", {"title": "Configuración inicial", "error": f"Bootstrap bloqueado: falta la variable {bootstrap_token_env}."}, status_code=503)
        if expected and not secrets.compare_digest(expected, submitted):
            return template(request, "bootstrap.html", {"title": "Configuración inicial", "error": "Token de bootstrap inválido."}, status_code=403)
        if password != confirm:
            return template(request, "bootstrap.html", {"title": "Configuración inicial", "error": "Las contraseñas no coinciden."}, status_code=400)
        try:
            security.bootstrap_admin(username, password, display_name)
        except Exception as exc:
            return template(request, "bootstrap.html", {"title": "Configuración inicial", "error": str(exc)}, status_code=400)
        return RedirectResponse("/login", status_code=303)

    @app.get("/mfa", response_class=HTMLResponse)
    def mfa_page(request: Request):
        identity = current_identity(request, allow_incomplete=True)
        if identity is None:
            return RedirectResponse("/login", status_code=303)
        if not identity.mfa_enabled:
            return RedirectResponse("/account/mfa/setup", status_code=303)
        return template(request, "mfa.html", {"title": "Verificación en dos pasos", "error": ""})

    @app.post("/mfa", response_class=HTMLResponse)
    async def mfa_verify(request: Request, code: str = Form(...)):
        identity = current_identity(request, allow_incomplete=True)
        if identity is None:
            return RedirectResponse("/login", status_code=303)
        await validate_csrf(request, identity)
        ip = request_security.remote_ip(request)
        limiter_key = f"{ip}:{identity.user_id}"
        decision = mfa_limiter.check(limiter_key)
        if not decision.allowed:
            security_logger.warning("AUTH_MFA_RATE_LIMIT ip=%s user=%s retry_after=%s", ip, identity.username, decision.retry_after)
            return template(request, "mfa.html", {"title": "Verificación en dos pasos", "error": f"Demasiados intentos. Espere {decision.retry_after} segundos."}, status_code=429)
        secret = security.get_mfa_secret(identity.user_id)
        if not security.verify_totp(secret, code):
            mfa_limiter.failure(limiter_key)
            security.audit(identity.username, "auth.mfa", "FAILED", "Código TOTP inválido", ip, role=identity.role)
            security_logger.warning("AUTH_MFA_FAILED ip=%s user=%s", ip, identity.username)
            return template(request, "mfa.html", {"title": "Verificación en dos pasos", "error": "Código inválido. Revise la hora del dispositivo."}, status_code=401)
        mfa_limiter.success(limiter_key)
        rotated = security.rotate_session(request.cookies.get(SESSION_COOKIE, ""), mfa_complete=True)
        if rotated is None:
            security.audit(identity.username, "auth.mfa", "FAILED", "La sesión expiró durante la rotación MFA", ip, role=identity.role)
            return RedirectResponse("/login", status_code=303)
        security.audit(identity.username, "auth.mfa", "SUCCESS", "MFA validado; sesión rotada", ip, role=identity.role)
        security_logger.info("AUTH_MFA_OK ip=%s user=%s", ip, identity.username)
        response = RedirectResponse("/", status_code=303)
        set_session_cookie(response, rotated[0])
        return response

    @app.post("/logout")
    async def logout(request: Request):
        identity = current_identity(request, allow_incomplete=True)
        if identity:
            await validate_csrf(request, identity)
            # Remote MFA reuse is browser-scoped and short lived, but explicit
            # logout invalidates all outstanding grants for this user immediately.
            STEP_UP_CACHE.clear_user(identity.user_id)
            security.audit(identity.username, "auth.logout", "SUCCESS", "Sesión cerrada; step-up revocado", request_security.remote_ip(request), role=identity.role)
        security.logout(request.cookies.get(SESSION_COOKIE, ""))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        identity = require(request, "dashboard.view")
        health: dict[str, Any] = {}; agents: list[dict[str, Any]] = []; jobs: list[dict[str, Any]] = []
        releases: list[dict[str, Any]] = []; gateway_error = ""
        try:
            health = gateway.health(); agents = gateway.agents(); jobs = gateway.jobs(limit=120); releases = gateway.releases()
        except Exception:
            # Inicio only needs to communicate degraded freshness. The detailed
            # exception belongs to the protected diagnostic/audit path.
            gateway_error = "Gateway temporalmente no disponible"
        ttl = int(config.get("agent_online_ttl_seconds", 90))
        def online(row: dict[str, Any]) -> bool:
            try:
                stamp = dt.datetime.fromisoformat(str(row.get("last_seen") or "").replace("Z", "+00:00"))
                return (dt.datetime.now(stamp.tzinfo) - stamp).total_seconds() <= ttl
            except Exception:
                return False
        active_agents = sum(1 for a in agents if online(a))
        active_jobs = sum(1 for j in jobs if str(j.get("status") or "").upper() in {"QUEUED","CLAIMED","RUNNING"})
        incidents = sum(1 for j in jobs if str(j.get("status") or "").upper() in {"FAILED","CANCELLED"} or j.get("error"))
        successful_jobs = sum(1 for j in jobs if str(j.get("status") or "").upper() in {"RESULT_READY","SUCCESS","SUCCEEDED","COMPLETED"})
        approved = sum(1 for r in releases if str(r.get("approval_state") or "").upper() == "APPROVED")
        try:
            control_plane = operations.control_plane_health()
        except Exception as exc:
            # Resource/diagnostic telemetry enriches Inicio, but must never make
            # the administrative console unavailable.
            control_plane = {
                "state": "DEGRADED", "fresh": False, "age_seconds": None,
                "generated_at_utc": "", "source": "WebAdmin",
                "services": [], "detail": f"Estado no disponible ({type(exc).__name__}).",
            }
        resources = resource_metrics.snapshot()
        platform_healthy = bool(health.get("Ok")) and str(control_plane.get("state") or "").upper() == "RUNNING"
        return template(request, "dashboard.html", {
            "title": "Inicio", "health": health, "agents": agents, "jobs": jobs[:10], "gateway_error": gateway_error,
            "control_plane": control_plane, "resources": resources, "platform_healthy": platform_healthy,
            "metrics": {
                "agents": len(agents), "active_agents": active_agents,
                "offline_agents": max(0, len(agents) - active_agents), "active_jobs": active_jobs,
                "successful_jobs": successful_jobs, "incidents": incidents, "approved": approved,
            },
        })

    @app.get("/api/dashboard/resources", response_class=JSONResponse)
    def dashboard_resources(request: Request):
        require(request, "dashboard.view")
        return JSONResponse(resource_metrics.snapshot(), headers={"Cache-Control": "no-store"})

    @app.get("/guide", response_class=HTMLResponse)
    @app.get("/guide/installation", response_class=HTMLResponse)
    def installation_guide(request: Request):
        """Render the safe, operator-facing installation and cloud guide."""
        require(request, "dashboard.view")
        return template(request, "installation_guide.html", {"title": "Configuración inicial"})

    @app.get("/agents", response_class=HTMLResponse)
    def agents_page(request: Request, q: str = "", status: str = "all", platform: str = "all", sort: str = "site"):
        require(request, "agents.view")
        # GatewayFacade may cache its dictionaries.  The list page decorates rows
        # for presentation, so work on shallow copies rather than cache entries.
        rows = [dict(row) for row in gateway.agents()]; releases = gateway.releases()
        approved = _approved_agent_releases(releases)
        now = dt.datetime.now().astimezone(); ttl=int(config.get("agent_online_ttl_seconds",90))
        for row in rows:
            try:
                seen=dt.datetime.fromisoformat(str(row.get("last_seen") or "").replace("Z","+00:00")); row["_online"]=(dt.datetime.now(seen.tzinfo)-seen).total_seconds()<=ttl
            except Exception: row["_online"]=False
            row["_state"] = effective_state(row, ttl_seconds=ttl)
            rel=approved.get((str(row.get("platform") or "").lower(),str(row.get("architecture") or "").lower()))
            _decorate_agent_update(row, rel)
            row["_target_version"] = row["_stable"]
        status = str(status or "all").strip().lower()
        if status not in {"all", "online", "offline", "updates"}:
            status = "all"
        platform = str(platform or "all").strip().lower()
        if platform not in {"all", "windows", "linux", "raspberry", "macos", "other"}:
            platform = "all"
        sort = str(sort or "site").strip().lower()
        if sort not in {"site", "name", "state", "last_seen", "version"}:
            sort = "site"
        search=q.strip().lower()
        filtered=[]
        for row in rows:
            if status=="online" and not row["_online"]: continue
            if status=="offline" and row["_online"]: continue
            if status=="updates" and not row["_update"]: continue
            row_platform = str(row.get("platform") or "").strip().lower()
            if platform == "other" and row_platform in {"windows", "linux", "raspberry", "macos"}: continue
            if platform not in {"all", "other"} and row_platform != platform: continue
            if search and search not in " ".join(str(row.get(k) or "") for k in ("site_code","site_name","agent_id","agent_name","hostname","platform","host_profile")).lower(): continue
            filtered.append(row)

        def text_key(row: dict, *keys: str) -> tuple[str, ...]:
            return tuple(str(row.get(key) or "").casefold() for key in keys)

        if sort == "name":
            filtered.sort(key=lambda row: text_key(row, "agent_name", "hostname", "agent_id", "site_code"))
        elif sort == "state":
            filtered.sort(key=lambda row: (not bool(row.get("_online")), text_key(row, "site_code", "site_name", "agent_name", "hostname")))
        elif sort == "last_seen":
            def seen_key(row: dict) -> float:
                try:
                    return dt.datetime.fromisoformat(str(row.get("last_seen") or "").replace("Z", "+00:00")).timestamp()
                except Exception:
                    return float("-inf")
            filtered.sort(key=seen_key, reverse=True)
        elif sort == "version":
            filtered.sort(key=lambda row: text_key(row, "agent_version", "platform", "architecture"), reverse=True)
        else:
            filtered.sort(key=lambda row: text_key(row, "site_code", "site_name", "agent_name", "hostname", "agent_id"))
        return template(request, "agents.html", {"title":"Agentes","agents":filtered,"q":q,"status":status,"platform":platform,"sort":sort,"total_agents":rows})

    @app.get("/agents/{agent_id}", response_class=HTMLResponse)
    def agent_detail(request: Request, agent_id: str):
        require(request, "agents.view")
        row=next((x for x in gateway.agents() if str(x.get("agent_id"))==agent_id),None)
        if row is None: raise HTTPException(status_code=404,detail="Agent no encontrado")
        releases = _approved_agent_releases(gateway.releases())
        _decorate_agent_update(row, releases.get((str(row.get("platform") or "").lower(), str(row.get("architecture") or "").lower())))
        jobs=gateway.jobs(limit=40,agent_id=agent_id)
        try:
            config_info = gateway.agent_configuration(agent_id)
            config_history = gateway.agent_configuration_history(agent_id)
            desired = config_info.get("Configuration") if isinstance(config_info.get("Configuration"), dict) else {}
            settings = desired.get("settings") if isinstance(desired, dict) and isinstance(desired.get("settings"), dict) else {}
            settings_json = json.dumps(settings, ensure_ascii=False, indent=2) if settings else json.dumps({
                "control_plane": {},
                "poll_seconds": 5,
                "status_seconds": 5,
                "update": {"channel": "stable", "check_seconds": 3600, "auto_install_approved": True, "require_approved": True},
            }, ensure_ascii=False, indent=2)
        except Exception as exc:
            config_info = {"Configuration": None, "Status": {"status": "UNAVAILABLE", "detail": f"{type(exc).__name__}: {exc}"}}
            config_history = []
            settings_json = "{}"
        ttl = int(config.get("agent_online_ttl_seconds", 90))
        diagnostic_report = build_agent_diagnostic(row, config_info, ttl_seconds=ttl)
        return template(request,"agent_detail.html",{
            "title":str(row.get("agent_name") or row.get("hostname") or agent_id),
            "agent":row,"jobs":jobs,"config_info":config_info,"config_history":config_history,"config_settings_json":settings_json,
            "diagnostic":diagnostic_report,"diagnostic_text":diagnostic_text(diagnostic_report),
            "agent_state":effective_state(row,ttl_seconds=ttl),
        })

    @app.get("/agents/{agent_id}/diagnostics.txt")
    def agent_diagnostics_text(request: Request, agent_id: str):
        require(request, "agents.view")
        row=next((x for x in gateway.agents() if str(x.get("agent_id"))==agent_id),None)
        if row is None: raise HTTPException(status_code=404,detail="Agent no encontrado")
        try:
            config_info=gateway.agent_configuration(agent_id)
        except Exception as exc:
            config_info={"Configuration":None,"Status":{"status":"UNAVAILABLE","detail":redact_error(exc)}}
        report=build_agent_diagnostic(row,config_info,ttl_seconds=int(config.get("agent_online_ttl_seconds",90)))
        safe_id="".join(ch for ch in agent_id if ch.isalnum() or ch in "-_.")[:80] or "agent"
        security.audit(current_identity(request).username,"agents.diagnostics.download","SUCCESS",f"AgentId={safe_id}; Format=txt",request_security.remote_ip(request),resource=agent_id,role=current_identity(request).role)
        return Response(
            content=diagnostic_text(report), media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition":f'attachment; filename="GIDEON-Agent-{safe_id}-diagnostic.txt"'},
        )

    @app.get("/agents/{agent_id}/diagnostics.json")
    def agent_diagnostics_json(request: Request, agent_id: str):
        require(request, "agents.view")
        row=next((x for x in gateway.agents() if str(x.get("agent_id"))==agent_id),None)
        if row is None: raise HTTPException(status_code=404,detail="Agent no encontrado")
        try:
            config_info=gateway.agent_configuration(agent_id)
        except Exception as exc:
            config_info={"Configuration":None,"Status":{"status":"UNAVAILABLE","detail":redact_error(exc)}}
        report=redact(build_agent_diagnostic(row,config_info,ttl_seconds=int(config.get("agent_online_ttl_seconds",90))))
        safe_id="".join(ch for ch in agent_id if ch.isalnum() or ch in "-_.")[:80] or "agent"
        security.audit(current_identity(request).username,"agents.diagnostics.download","SUCCESS",f"AgentId={safe_id}; Format=json",request_security.remote_ip(request),resource=agent_id,role=current_identity(request).role)
        return Response(
            content=json.dumps(report,ensure_ascii=False,indent=2), media_type="application/json; charset=utf-8",
            headers={"Content-Disposition":f'attachment; filename="GIDEON-Agent-{safe_id}-diagnostic.json"'},
        )

    @app.post("/agents/{agent_id}/configuration")
    async def agent_configuration_set(request: Request, agent_id: str):
        identity=require(request,"agents.operate"); await validate_csrf(request,identity)
        form=await request.form()
        raw=str(form.get("settings_json") or "{}").strip()
        note=str(form.get("note") or "").strip()
        try:
            settings=json.loads(raw)
            if not isinstance(settings,dict):
                raise ValueError("La configuración debe ser un objeto JSON.")
            result = await asyncio.to_thread(
                gateway.set_agent_configuration, agent_id, settings,
                actor=identity.username, note=note,
            )
            security.audit(identity.username,"agents.configuration.set","SUCCESS",json.dumps(result,ensure_ascii=False)[:4000],request_security.remote_ip(request),resource=agent_id,role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"agents.configuration.set","FAILED",str(exc),request_security.remote_ip(request),resource=agent_id,role=identity.role)
            raise HTTPException(400,str(exc))
        return RedirectResponse(f"/agents/{agent_id}",status_code=303)

    @app.post("/agents/{agent_id}/purge")
    async def agent_purge(request: Request, agent_id: str):
        identity=require(request,"agents.purge"); await validate_csrf(request,identity)
        try:
            result = await asyncio.to_thread(gateway.purge_agent, agent_id)
            security.audit(identity.username,"agents.purge","SUCCESS",json.dumps(result,ensure_ascii=False),request_security.remote_ip(request),resource=agent_id,role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"agents.purge","FAILED",str(exc),request_security.remote_ip(request),resource=agent_id,role=identity.role); raise HTTPException(409,str(exc))
        return RedirectResponse("/agents",status_code=303)

    @app.post("/agents/{agent_id}/restart")
    async def agent_restart(request: Request, agent_id: str):
        identity=require(request,"agents.operate"); await validate_csrf(request,identity)
        try:
            result = await asyncio.to_thread(
                operations.dispatch_restart,
                agent_id=agent_id, actor=identity.username, delay_seconds=60,
            )
            security.audit(identity.username,"agents.remote_restart","SUCCESS",str(result.get("JobId") or ""),request_security.remote_ip(request),resource=agent_id,role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"agents.remote_restart","FAILED",str(exc),request_security.remote_ip(request),resource=agent_id,role=identity.role)
            raise HTTPException(409,str(exc))
        return RedirectResponse(f"/jobs/{result['JobId']}",status_code=303)

    @app.post("/agents/{agent_id}/uninstall")
    async def agent_uninstall(request: Request, agent_id: str):
        identity=require(request,"agents.operate"); await validate_csrf(request,identity)
        if not bool(config.get("allow_server_side_signing",False)):
            raise HTTPException(409,"Desinstalación remota Web deshabilitada hasta configurar una clave de firma externa/montada.")
        agents = await asyncio.to_thread(gateway.agents)
        row=next((x for x in agents if str(x.get("agent_id"))==agent_id),None)
        if row is None: raise HTTPException(404,"Agent no encontrado")
        try:
            from gideon_services import AgentAdministrationService
            cfg={"agent_control_plane":{"base_url":config.get("gateway_base_url"),"admin_api_key_env":config.get("gateway_admin_token_env","GIDEON_AGENT_ADMIN_TOKEN"),"verify_tls":config.get("gateway_verify_tls",True),"ca_file":config.get("gateway_ca_file"),"require_https":config.get("gateway_require_https",True)}}
            service=AgentAdministrationService(app_root,cfg)
            result = await asyncio.to_thread(service.queue_remote_uninstall, row)
            security.audit(identity.username,"agents.remote_uninstall","SUCCESS",str(result.get("job",{}).get("JobId")),request_security.remote_ip(request),resource=agent_id,role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"agents.remote_uninstall","FAILED",str(exc),request_security.remote_ip(request),resource=agent_id,role=identity.role); raise HTTPException(409,str(exc))
        return RedirectResponse(f"/agents/{agent_id}",status_code=303)

    def _job_error_category(value: Any) -> str:
        text=str(value or "").lower()
        if not text:
            return "SIN_DETALLE"
        if "permission denied" in text or "publickey" in text or "auth" in text:
            return "SSH_AUTENTICACION"
        if "host key" in text or "known_hosts" in text:
            return "SSH_HOST_KEY"
        if "sftp" in text or "subsystem" in text:
            return "SFTP"
        if "timeout" in text or "timed out" in text or "no route" in text or "connection refused" in text or "tcp/22" in text:
            return "RED_VPN"
        if "preflight" in text:
            return "PREFLIGHT"
        if "dispatch" in text:
            return "DESPACHO"
        if "collect" in text or "recole" in text:
            return "RECOLECCION"
        if "cancel" in text or "interrupt" in text:
            return "CANCELACION"
        return "OTRO"

    def _collect_jobs_overview(status: str = "", *, local_limit: int = 250, gateway_limit: int = 250):
        wanted=str(status or "").upper().strip()
        grouped: dict[str,dict[str,Any]]={}
        # GIDEON RC30.95.28: cap cold Gateway wait to 1.5 s. Agentless manifests
        # are local and therefore render even if the Gateway is slow.
        try:
            rows=gateway.jobs_fast(limit=gateway_limit,status=status)
        except Exception:
            rows=[]
        for row in rows:
            jid=str(row.get("job_id") or "").strip()
            if not jid:
                continue
            g=grouped.setdefault(jid,{"job_id":jid,"created_at":row.get("created_at"),"updated_at":row.get("updated_at"),"targets":0,"ready":0,"failed":0,"active":0,"rows":[],"method":"Agent HTTPS/PULL"})
            g["targets"]+=1; g["rows"].append(row)
            st=str(row.get("status") or "").upper()
            if bool(row.get("ResultReady")): g["ready"]+=1
            if st in {"FAILED","CANCELLED","INTERRUPTED"} or row.get("error"): g["failed"]+=1
            if st in {"QUEUED","CLAIMED","RUNNING"}: g["active"]+=1
            if str(row.get("updated_at") or "") > str(g.get("updated_at") or ""): g["updated_at"]=row.get("updated_at")
        for g in grouped.values():
            if g["active"]:
                g["status"]="RUNNING"
            elif g["failed"]:
                g["status"]="FAILED"
            elif g["targets"] and g["ready"]>=g["targets"]:
                g["status"]="COMPLETED"
            else:
                g["status"]="PENDING"
            g["cancellable"]=bool(g["active"])

        for transfer in operations.transfer_jobs(limit=local_limit):
            state = str(transfer.get("Status") or "QUEUED_FOR_ANALYSIS").upper()
            if wanted and state != wanted:
                continue
            job_id = str(transfer.get("JobId") or "")
            if not job_id:
                continue
            targets = int(transfer.get("TargetCount") or 0)
            queued = int(transfer.get("QueuedCount") or 0)
            failed = 1 if state == "FAILED" else 0
            grouped[job_id] = {
                "job_id": job_id,
                "created_at": transfer.get("CreatedAt"),
                "updated_at": transfer.get("UpdatedAt"),
                "targets": targets,
                "ready": queued,
                "failed": failed,
                "active": 0 if state in {"COMPLETED", "FAILED"} else max(1, targets - queued),
                "rows": list(transfer.get("Results") or []),
                "method": "Transferencia segura",
                "status": state,
                "cancellable": False,
            }

        for manifest in operations.agentless_jobs(limit=local_limit):
            state=str(manifest.get("Status") or "").upper()
            if wanted and state != wanted:
                continue
            sites=list((manifest.get("Sites") or {}).values()) if isinstance(manifest.get("Sites"),dict) else []
            terminal={"COMPLETED","COMPLETED_WITH_WARNINGS","COMPLETED_WITH_ERRORS","COMPLETED_WITH_SKIPPED","PARTIAL","FAILED","LAUNCH_FAILED","ACTION_REQUIRED","CANCELLED","CANCELLED_WITH_ERRORS","INTERRUPTED"}
            failed=sum(1 for row in sites if str(row.get("RemoteState") or row.get("TaskState") or "").upper() in {"FAILED","CANCELLED","INTERRUPTED","DISPATCH_FAILED","PREFLIGHT_FAILED"} or row.get("Error") or row.get("LastError"))
            ready=sum(1 for row in sites if str(row.get("RemoteState") or "").upper() in {"COMPLETED","COLLECTED"} or bool(row.get("CollectionVerified")))
            targets=int(manifest.get("TotalCount") or len(sites))
            grouped[str(manifest.get("JobId") or "")]= {
                "job_id":str(manifest.get("JobId") or ""),"created_at":manifest.get("CreatedAt"),"updated_at":manifest.get("UpdatedAt"),
                "targets":targets,"ready":int(manifest.get("CollectedCount") or ready),
                "failed":int(manifest.get("FailedCount") or failed),"active":0 if state in terminal else max(0,targets-ready-failed),
                "rows":sites,"method":"SSH/SFTP","status":state,"cancellable":state not in terminal,
            }
        jobs=sorted(grouped.values(),key=lambda x:str(x.get("created_at") or ""),reverse=True)
        if wanted:
            jobs=[j for j in jobs if str(j.get("status") or "").upper()==wanted]
        return jobs

    def _job_analysis_from_rows(job_id: str, method: str, status_value: str, rows: list[dict[str,Any]], *, manifest: dict[str,Any] | None = None) -> dict[str,Any]:
        categories: dict[str,int]={}
        problem_sites=[]
        completed=failed=pending=0
        for row in rows:
            state=str(row.get("RemoteState") or row.get("TaskState") or row.get("status") or "").upper()
            err=str(row.get("Error") or row.get("LastError") or row.get("error") or "")
            if state in {"COMPLETED","COLLECTED","RESULT_READY"} or bool(row.get("CollectionVerified")) or bool(row.get("ResultReady")):
                completed+=1
            elif state in {"FAILED","CANCELLED","INTERRUPTED","DISPATCH_FAILED","PREFLIGHT_FAILED"} or err:
                failed+=1
            else:
                pending+=1
            if err:
                cat=_job_error_category(err); categories[cat]=categories.get(cat,0)+1
                problem_sites.append({"site":str(row.get("SiteCode") or row.get("site_code") or row.get("agent_id") or "-"),"name":str(row.get("SiteName") or row.get("site_name") or row.get("hostname") or ""),"state":state or "-","category":cat,"error":err[:800]})
        total=max(len(rows),completed+failed+pending)
        protocol=(manifest or {}).get("ProtocolPreflight") if isinstance((manifest or {}).get("ProtocolPreflight"),dict) else {}
        preflight={"target":int(protocol.get("TargetCount") or 0),"checked":int(protocol.get("CheckedCount") or 0),"passed":int(protocol.get("PassedCount") or 0),"failed":int(protocol.get("FailedCount") or 0)}
        success_pct=round((completed/total)*100,1) if total else 0.0
        recommendations=[]
        if categories.get("SSH_AUTENTICACION"): recommendations.append("Revisar usuario/clave pública/authorized_keys en las sedes con fallo SSH.")
        if categories.get("RED_VPN"): recommendations.append("Revisar VPN, ruta y TCP/22 de las sedes con timeout o rechazo de conexión.")
        if categories.get("SFTP"): recommendations.append("Validar el subsistema SFTP de sshd en las sedes afectadas.")
        if categories.get("DESPACHO"): recommendations.append("Reintentar únicamente destinos fallidos después de validar SSH/SFTP.")
        if categories.get("RECOLECCION"): recommendations.append("Revisar archivos de salida y permisos de recolección SFTP.")
        if not recommendations and failed==0 and total:
            recommendations.append("No se detectan fallos en los resultados disponibles.")
        return {"job_id":job_id,"method":method,"status":status_value,"total":total,"completed":completed,"failed":failed,"pending":pending,"success_pct":success_pct,"categories":sorted(categories.items(),key=lambda x:(-x[1],x[0])),"problem_sites":problem_sites,"preflight":preflight,"recommendations":recommendations}

    @app.get("/jobs", response_class=HTMLResponse)
    def jobs_page(request: Request, status: str = "", page: int = 1):
        require(request,"jobs.view")
        jobs_all=_collect_jobs_overview(status)
        page=max(1,int(page or 1)); page_size=50
        total=len(jobs_all); pages=max(1,(total+page_size-1)//page_size); page=min(page,pages)
        jobs=jobs_all[(page-1)*page_size:page*page_size]
        counts={"total":total,"active":sum(1 for j in jobs_all if j.get("cancellable")),"failed":sum(1 for j in jobs_all if int(j.get("failed") or 0)>0),"completed":sum(1 for j in jobs_all if str(j.get("status") or "").upper().startswith("COMPLETED"))}
        return template(request,"jobs.html",{"title":"Jobs","jobs":jobs,"status":status,"page":page,"pages":pages,"counts":counts})

    @app.get("/jobs/analysis", response_class=HTMLResponse)
    def jobs_general_analysis(request: Request):
        require(request,"jobs.view")
        jobs=_collect_jobs_overview("",local_limit=300,gateway_limit=300)[:200]
        by_status: dict[str,int]={}; by_method: dict[str,int]={}; categories: dict[str,int]={}
        total_targets=total_failed=total_ready=0
        for j in jobs:
            st=str(j.get("status") or "UNKNOWN").upper(); by_status[st]=by_status.get(st,0)+1
            method=str(j.get("method") or "-"); by_method[method]=by_method.get(method,0)+1
            total_targets+=int(j.get("targets") or 0); total_failed+=int(j.get("failed") or 0); total_ready+=int(j.get("ready") or 0)
            for row in j.get("rows") or []:
                err=str(row.get("Error") or row.get("LastError") or row.get("error") or "")
                if err:
                    cat=_job_error_category(err); categories[cat]=categories.get(cat,0)+1
        analysis={"jobs":len(jobs),"active":sum(1 for j in jobs if j.get("cancellable")),"targets":total_targets,"ready":total_ready,"failed":total_failed,"by_status":sorted(by_status.items(),key=lambda x:(-x[1],x[0])),"by_method":sorted(by_method.items(),key=lambda x:(-x[1],x[0])),"categories":sorted(categories.items(),key=lambda x:(-x[1],x[0]))[:10]}
        return template(request,"jobs_analysis.html",{"title":"Análisis general de Jobs","analysis":analysis,"jobs":jobs[:20]})

    @app.get("/jobs/{job_id}/analysis", response_class=HTMLResponse)
    def job_analysis(request: Request, job_id: str):
        require(request,"jobs.view")
        transfer = operations.transfer_job(job_id)
        if transfer is not None:
            state = str(transfer.get("Status") or "QUEUED_FOR_ANALYSIS").upper()
            results = [dict(row) for row in (transfer.get("Results") or []) if isinstance(row, dict)]
            if not results:
                results = [{
                    "agent_id": "preparación", "status": state,
                    "error": str(transfer.get("Error") or ""),
                }]
            else:
                for row in results:
                    row.setdefault("status", "RESULT_READY" if state == "COMPLETED" else state)
            analysis = _job_analysis_from_rows(job_id, "Transferencia segura", state, results)
            return template(request,"job_analysis.html",{"title":f"Análisis {job_id}","analysis":analysis})
        manifest=operations.agentless_job(job_id)
        if manifest is not None:
            sites=list((manifest.get("Sites") or {}).values()) if isinstance(manifest.get("Sites"),dict) else []
            analysis=_job_analysis_from_rows(job_id,"SSH/SFTP",str(manifest.get("Status") or "-"),sites,manifest=manifest)
            return template(request,"job_analysis.html",{"title":f"Análisis {job_id}","analysis":analysis})
        try:
            rows=gateway.job(job_id)
        except Exception as exc:
            raise HTTPException(502,"No se pudo consultar el Job en Gateway: "+redact_error(exc)) from exc
        if not rows: raise HTTPException(404,"Job no encontrado")
        status_value="RUNNING" if any(str(r.get("status") or "").upper() in {"QUEUED","CLAIMED","RUNNING"} for r in rows) else "FAILED" if any(r.get("error") or str(r.get("status") or "").upper() in {"FAILED","CANCELLED","INTERRUPTED"} for r in rows) else "COMPLETED"
        analysis=_job_analysis_from_rows(job_id,"Agent HTTPS/PULL",status_value,rows)
        return template(request,"job_analysis.html",{"title":f"Análisis {job_id}","analysis":analysis})

    @app.get("/jobs/{job_id}/status.json")
    def job_live_status(request: Request, job_id: str):
        require(request,"jobs.view")
        transfer = operations.transfer_job(job_id)
        if transfer is not None:
            state = str(transfer.get("Status") or "QUEUED_FOR_ANALYSIS").upper()
            return Response(json.dumps({
                "job_id": job_id,
                "status": state,
                "terminal": state in {"COMPLETED", "FAILED"},
                "cancellable": False,
                "updated_at": transfer.get("UpdatedAt"),
                "phase": transfer.get("Phase"),
                "detail": transfer.get("Detail"),
                "scan_status": transfer.get("ScanStatus"),
                "scan_engine": transfer.get("ScanEngine"),
                "scan_duration_ms": transfer.get("ScanDurationMs"),
                "queued_count": int(transfer.get("QueuedCount") or 0),
                "target_count": int(transfer.get("TargetCount") or 0),
                "error": transfer.get("Error"),
                "sites": {},
            },ensure_ascii=False),media_type="application/json",headers={"Cache-Control":"no-store"})
        manifest=operations.agentless_job(job_id)
        if manifest is None:
            raise HTTPException(404,"Live status disponible para Jobs Agentless")
        state=str(manifest.get("Status") or "STARTING").upper()
        terminal={"COMPLETED","COMPLETED_WITH_WARNINGS","COMPLETED_WITH_ERRORS","COMPLETED_WITH_SKIPPED","PARTIAL","FAILED","LAUNCH_FAILED","ACTION_REQUIRED","CANCELLED","CANCELLED_WITH_ERRORS","INTERRUPTED"}
        protocol=manifest.get("ProtocolPreflight") if isinstance(manifest.get("ProtocolPreflight"),dict) else {}
        pf_sites=protocol.get("Sites") if isinstance(protocol.get("Sites"),dict) else {}
        sites_raw=manifest.get("Sites") if isinstance(manifest.get("Sites"),dict) else {}
        sites={}
        for code,raw in sites_raw.items():
            if not isinstance(raw,dict): continue
            pf=pf_sites.get(str(code)) if isinstance(pf_sites.get(str(code)),dict) else {}
            ssh=pf.get("SSH") if isinstance(pf.get("SSH"),dict) else {}; sftp=pf.get("SFTP") if isinstance(pf.get("SFTP"),dict) else {}
            sites[str(code)]={"remote":str(raw.get("RemoteState") or raw.get("TaskState") or "PENDING"),"transfer":str(raw.get("TransferStatus") or "-"),"collection":str(raw.get("CollectionStatus") or "-"),"error":str(raw.get("Error") or raw.get("LastError") or ""),"ssh":"OK" if ssh.get("Ok") else ("FAIL" if pf else "-"),"sftp":"N/A" if pf and sftp.get("Required") is False else "OK" if sftp.get("Ok") else ("FAIL" if pf else "-")}
        return Response(json.dumps({"job_id":job_id,"status":state,"terminal":state in terminal,"cancellable":state not in terminal,"updated_at":manifest.get("UpdatedAt"),"preflight":{"target":int(protocol.get("TargetCount") or 0),"checked":int(protocol.get("CheckedCount") or 0),"passed":int(protocol.get("PassedCount") or 0),"failed":int(protocol.get("FailedCount") or 0)},"sites":sites},ensure_ascii=False),media_type="application/json",headers={"Cache-Control":"no-store"})

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_detail(request: Request, job_id: str):
        require(request, "jobs.view")

        transfer = operations.transfer_job(job_id)
        if transfer is not None:
            state = str(transfer.get("Status") or "QUEUED_FOR_ANALYSIS").upper()
            return template(request, "transfer_job_detail.html", {
                "title": job_id,
                "job_id": job_id,
                "job": transfer,
                "results": [dict(row) for row in (transfer.get("Results") or []) if isinstance(row, dict)],
                "auto_refresh": state not in {"COMPLETED", "FAILED"},
            })

        # GIDEON RC30.95.23: resolve local Agentless manifests first. Their JobIds
        # are Control Plane records; Gateway availability must not prevent reopen.
        manifest = operations.agentless_job(job_id)
        if manifest is not None:
            manifest = dict(manifest)
            connectivity = manifest.get("ConnectivityPreflight")
            if not isinstance(connectivity, dict):
                connectivity = {}
            ssh_identity = manifest.get("SshIdentity")
            if not isinstance(ssh_identity, dict):
                ssh_identity = {}
            protocol = manifest.get("ProtocolPreflight")
            if not isinstance(protocol, dict):
                protocol = {}
            protocol_sites = protocol.get("Sites")
            if not isinstance(protocol_sites, dict):
                protocol_sites = {}
            sites_raw = manifest.get("Sites")
            if not isinstance(sites_raw, dict):
                sites_raw = {}
            sites: list[dict[str, Any]] = []
            for raw in sites_raw.values():
                if not isinstance(raw, dict):
                    continue
                row = dict(raw)
                code = str(row.get("SiteCode") or "")
                pf = protocol_sites.get(code)
                if not isinstance(pf, dict):
                    pf = {}
                ssh_pf = pf.get("SSH") if isinstance(pf.get("SSH"), dict) else {}
                sftp_pf = pf.get("SFTP") if isinstance(pf.get("SFTP"), dict) else {}
                row["_preflight_known"] = bool(pf)
                row["_ssh_preflight"] = "OK" if ssh_pf.get("Ok") else ("FAIL" if pf else "-")
                row["_sftp_preflight"] = (
                    "N/A" if pf and sftp_pf.get("Required") is False
                    else "OK" if sftp_pf.get("Ok")
                    else "FAIL" if pf
                    else "-"
                )
                row["_preflight_detail"] = str(pf.get("Detail") or "")
                sites.append(row)
            route_mode = (
                str(manifest.get("ControllerConnectionMode") or "").strip()
                or str(connectivity.get("Mode") or "").strip()
                or "-"
            )
            runtime_state = operations.agentless_runtime_state(job_id, manifest)
            action_required: list[dict[str, str]] = []
            state = str(manifest.get("Status") or "").upper()
            try:
                action_state = operations.agentless_action_state(job_id, manifest)
            except Exception:
                action_state = {"status": state, "action_code": str(manifest.get("ActionRequired") or ""), "retryable_count": 0, "retryable_sites": [], "active_count": 0}
            if state == "ACTION_REQUIRED":
                if int(action_state.get("retryable_count") or 0) > 0:
                    action_required.append({
                        "code": str(action_state.get("action_code") or "RETRY_OR_IGNORE_SITES"),
                        "title": "Hay sedes pendientes que requieren una decisión",
                        "detail": f"{int(action_state.get('retryable_count') or 0)} sede(s) quedaron fallidas/diferidas o marcadas como reintentables después del ciclo remoto. El preflight SSH/SFTP puede estar correcto y aun así existir una incidencia de ejecución.",
                        "href": "#action-required-panel",
                        "action": "Reintentar, omitir o aprobar el resultado",
                    })
                if not ssh_identity.get("id"):
                    action_required.append({
                        "code": "SSH_IDENTITY_NOT_RECORDED",
                        "title": "Identidad SSH no registrada",
                        "detail": "Este Job es anterior al preflight autenticado o perdió su metadata. Seleccione una identidad SSH validada al crear el nuevo Job.",
                        "href": "/security/assets#ssh-identities",
                        "action": "Configurar SSH/SFTP",
                    })
                if not protocol:
                    action_required.append({
                        "code": "SSH_SFTP_PREFLIGHT_NOT_RECORDED",
                        "title": "Preflight SSH/SFTP no registrado",
                        "detail": "No existe evidencia del usuario, puerto, autenticación SSH y subsistema SFTP usados por este Job. No se debe reanudar a ciegas.",
                        "href": "/execute?method=AGENTLESS",
                        "action": "Crear Job validado",
                    })
                elif int(protocol.get("FailedCount") or 0) > 0:
                    action_required.append({
                        "code": "SSH_SFTP_PREFLIGHT_FAILED",
                        "title": "Hay sedes que no autenticaron por SSH/SFTP",
                        "detail": f"Fallaron {int(protocol.get('FailedCount') or 0)} de {int(protocol.get('TargetCount') or 0)} destinos con usuario {protocol.get('Username') or '-'}.",
                        "href": "/security/assets#ssh-identities",
                        "action": "Revisar conexión",
                    })
                if runtime_state.get("stale"):
                    backend = runtime_state.get("backend") if isinstance(runtime_state.get("backend"), dict) else {}
                    action_required.append({
                        "code": "JOB_STALE",
                        "title": "Backend del Job sin actividad",
                        "detail": f"Sin actualización por {int(runtime_state.get('age_seconds') or 0)} s; backend={backend.get('detail') or '-'}.",
                        "href": "",
                        "action": "Use Cancelar Job o Recuperar Job trabado",
                    })
                dispatch_failed = sum(1 for row in sites if str(row.get("RemoteState") or "").upper() == "DISPATCH_FAILED")
                if dispatch_failed:
                    action_required.append({
                        "code": "DISPATCH_FAILED",
                        "title": "Falló el despacho SSH",
                        "detail": f"{dispatch_failed} destino(s) quedaron DISPATCH_FAILED. Revise usuario/identidad/puerto y vuelva a ejecutar después de validar SSH + SFTP.",
                        "href": "/execute?method=AGENTLESS",
                        "action": "Nueva ejecución",
                    })
            return template(request, "agentless_job_detail.html", {
                "title": job_id,
                "job_id": job_id,
                "manifest": manifest,
                "sites": sites,
                "route_mode": route_mode,
                "ssh_identity": ssh_identity,
                "protocol_preflight": protocol,
                "runtime_state": runtime_state,
                "action_required": action_required,
                "action_state": action_state,
                "auto_refresh": state in {
                    "PREFLIGHT_QUEUED", "PREFLIGHT_RUNNING", "LAUNCHING", "STARTING",
                    "RETRY_QUEUED", "RETRYING", "QUEUED", "DISPATCHING", "MONITORING", "RUNNING", "COLLECTING", "CANCEL_REQUESTED",
                },
            })

        try:
            rows = gateway.job(job_id)
        except Exception as exc:
            raise HTTPException(502, "No se pudo consultar el Job en Gateway: " + redact_error(exc)) from exc
        if rows:
            return template(request, "job_detail.html", {"title": job_id, "job_id": job_id, "rows": rows})
        raise HTTPException(404, "Job no encontrado")

    @app.post("/jobs/{job_id}/agentless/retry-unresolved")
    async def agentless_job_retry_unresolved(request: Request, job_id: str):
        identity = require(request, "jobs.execute")
        await validate_csrf(request, identity)
        try:
            result = await asyncio.to_thread(
                operations.retry_agentless_unresolved, job_id, actor=identity.username
            )
            security.audit(
                identity.username, "jobs.resolve.retry_unresolved", "SUCCESS", json.dumps(result),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
        except Exception as exc:
            security.audit(
                identity.username, "jobs.resolve.retry_unresolved", "FAILED", redact_error(exc),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/agentless/omit-selected")
    async def agentless_job_omit_selected(request: Request, job_id: str):
        identity = require(request, "jobs.execute")
        await validate_csrf(request, identity)
        form = await request.form()
        selected = [str(value).strip() for value in form.getlist("site_code") if str(value).strip()]
        try:
            result = await asyncio.to_thread(
                operations.omit_agentless_sites,
                job_id, actor=identity.username, site_codes=selected, approve_current=False,
            )
            security.audit(
                identity.username, "jobs.resolve.omit_selected", "SUCCESS", json.dumps(result),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
        except Exception as exc:
            security.audit(
                identity.username, "jobs.resolve.omit_selected", "FAILED", redact_error(exc),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/agentless/approve-current")
    async def agentless_job_approve_current(request: Request, job_id: str):
        identity = require(request, "jobs.execute")
        await validate_csrf(request, identity)
        try:
            result = await asyncio.to_thread(
                operations.omit_agentless_sites,
                job_id, actor=identity.username, site_codes=[], approve_current=True,
            )
            security.audit(
                identity.username, "jobs.resolve.approve_current", "SUCCESS", json.dumps(result),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
        except Exception as exc:
            security.audit(
                identity.username, "jobs.resolve.approve_current", "FAILED", redact_error(exc),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/agentless/reconcile-action")
    async def agentless_job_reconcile_action(request: Request, job_id: str):
        identity = require(request, "jobs.execute")
        await validate_csrf(request, identity)
        try:
            result = await asyncio.to_thread(
                operations.reconcile_agentless_action_required, job_id, actor=identity.username
            )
            security.audit(
                identity.username, "jobs.resolve.reconcile", "SUCCESS", json.dumps(result),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
        except Exception as exc:
            security.audit(
                identity.username, "jobs.resolve.reconcile", "FAILED", redact_error(exc),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/agentless/recover")
    async def agentless_job_recover(request: Request, job_id: str):
        identity = require(request, "jobs.cancel")
        await validate_csrf(request, identity)
        try:
            result = await asyncio.to_thread(
                operations.recover_agentless, job_id, actor=identity.username
            )
            security.audit(
                identity.username, "jobs.recover_agentless", "SUCCESS", json.dumps(result),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
        except Exception as exc:
            security.audit(
                identity.username, "jobs.recover_agentless", "FAILED", redact_error(exc),
                request_security.remote_ip(request), resource=job_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/agentless/cancel")
    async def agentless_job_cancel(request: Request, job_id: str):
        identity=require(request,"jobs.cancel"); await validate_csrf(request,identity)
        try:
            result = await asyncio.to_thread(
                operations.cancel_agentless, job_id, actor=identity.username
            )
            security.audit(identity.username,"jobs.cancel_agentless","SUCCESS",json.dumps(result),request_security.remote_ip(request),resource=job_id,role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"jobs.cancel_agentless","FAILED",str(exc),request_security.remote_ip(request),resource=job_id,role=identity.role)
            raise HTTPException(409,str(exc))
        return RedirectResponse(f"/jobs/{job_id}",status_code=303)

    @app.post("/jobs/{job_id}/cancel-all")
    async def job_cancel_all(request: Request, job_id: str):
        identity=require(request,"jobs.cancel"); await validate_csrf(request,identity)
        manifest=operations.agentless_job(job_id)
        if manifest is not None:
            state=str(manifest.get("Status") or "").upper()
            terminal={"COMPLETED","COMPLETED_WITH_WARNINGS","COMPLETED_WITH_ERRORS","COMPLETED_WITH_SKIPPED","PARTIAL","FAILED","LAUNCH_FAILED","ACTION_REQUIRED","CANCELLED","CANCELLED_WITH_ERRORS","INTERRUPTED"}
            if state in terminal:
                raise HTTPException(409,f"El Job ya está en estado terminal: {state}")
            try:
                result = await asyncio.to_thread(
                    operations.cancel_agentless, job_id, actor=identity.username
                )
                security.audit(identity.username,"jobs.cancel_all","SUCCESS",json.dumps(result),request_security.remote_ip(request),resource=job_id,role=identity.role)
            except Exception as exc:
                security.audit(identity.username,"jobs.cancel_all","FAILED",redact_error(exc),request_security.remote_ip(request),resource=job_id,role=identity.role)
                raise HTTPException(409,str(exc))
            return RedirectResponse(f"/jobs/{job_id}",status_code=303)

        try:
            rows = await asyncio.to_thread(gateway.job, job_id)
        except Exception as exc:
            raise HTTPException(502,"No se pudo consultar el Job en Gateway: "+redact_error(exc)) from exc
        active=[]
        for row in rows:
            st=str(row.get("status") or "").upper()
            aid=str(row.get("agent_id") or row.get("AgentId") or "").strip()
            if aid and st in {"QUEUED","CLAIMED","RUNNING"}:
                active.append(aid)
        if not active:
            raise HTTPException(409,"El Job no tiene destinos activos para cancelar.")
        semaphore=asyncio.Semaphore(6)
        results=[]
        async def cancel_one(agent_id: str):
            async with semaphore:
                try:
                    value=await asyncio.to_thread(gateway.cancel,job_id,agent_id)
                    results.append({"agent_id":agent_id,"ok":True,"result":value})
                except Exception as exc:
                    results.append({"agent_id":agent_id,"ok":False,"error":redact_error(exc)})
        await asyncio.gather(*(cancel_one(aid) for aid in active))
        failed=sum(1 for r in results if not r.get("ok"))
        security.audit(identity.username,"jobs.cancel_all","SUCCESS" if failed==0 else "PARTIAL",json.dumps({"targets":len(active),"failed":failed}),request_security.remote_ip(request),resource=job_id,role=identity.role)
        if failed==len(active):
            raise HTTPException(409,"No se pudo cancelar ningún destino activo del Job.")
        return RedirectResponse(f"/jobs/{job_id}",status_code=303)

    @app.post("/jobs/{job_id}/{agent_id}/cancel")
    async def job_cancel(request: Request, job_id: str, agent_id: str):
        identity=require(request,"jobs.cancel"); await validate_csrf(request,identity)
        result = await asyncio.to_thread(gateway.cancel, job_id, agent_id)
        security.audit(identity.username,"jobs.cancel","SUCCESS",json.dumps(result),request_security.remote_ip(request),resource=f"{job_id}/{agent_id}",role=identity.role)
        return RedirectResponse(f"/jobs/{job_id}",status_code=303)

    @app.get("/jobs/{job_id}/{agent_id}/result")
    def job_result(request: Request, job_id: str, agent_id: str):
        require(request,"jobs.download")
        import tempfile
        temp=Path(tempfile.gettempdir())/f"gideon-result-{secrets.token_hex(8)}.zip"
        gateway.download_result(job_id,agent_id,temp)
        return FileResponse(
            temp,
            filename=f"{job_id}-{agent_id}.zip",
            media_type="application/zip",
            background=BackgroundTask(temp.unlink, missing_ok=True),
        )

    @app.get("/jobs/{job_id}/export.xlsx")
    def job_excel(request: Request, job_id: str):
        identity = require(request, "jobs.download")
        manifest = operations.agentless_job(job_id)
        mode = "AGENTLESS" if manifest is not None else "AGENT"
        try:
            data = operations.export_agentless_excel(job_id) if manifest is not None else operations.export_excel(job_id)
        except FileNotFoundError as exc:
            security.audit(
                identity.username, "jobs.export_excel", "FAILED",
                f"Mode={mode}; {redact_error(exc)}", request_security.remote_ip(request),
                resource=job_id, role=identity.role,
            )
            raise HTTPException(404, str(exc)) from exc
        except Exception as exc:
            security.audit(
                identity.username, "jobs.export_excel", "FAILED",
                f"Mode={mode}; {redact_error(exc)}", request_security.remote_ip(request),
                resource=job_id, role=identity.role,
            )
            raise HTTPException(500, "No se pudo generar el Excel consolidado del Job: " + redact_error(exc)) from exc
        security.audit(
            identity.username, "jobs.export_excel", "SUCCESS",
            f"Mode={mode}; Bytes={len(data)}", request_security.remote_ip(request),
            resource=job_id, role=identity.role,
        )
        filename = f"GIDEON-{job_id}-RESULTADOS.xlsx" if manifest is not None else f"GIDEON-{job_id}.xlsx"
        return Response(
            data,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/scripts",response_class=HTMLResponse)
    def scripts_page(request: Request):
        require(request,"scripts.view"); scripts=security.list_scripts(); available,reason=operations.execution_available()
        return template(request,"scripts.html",{"title":"Scripts","scripts":scripts,"execution_available":available,"execution_reason":reason})

    @app.post("/scripts/upload")
    async def scripts_upload(request: Request, file: UploadFile = File(...)):
        identity=require(request,"scripts.manage"); await validate_csrf(request,identity)
        content=await file.read()
        try:
            row = await asyncio.to_thread(
                operations.ingest_script,
                filename=file.filename or "script", content=content, actor=identity.username,
            )
            security.audit(identity.username,"scripts.upload","SUCCESS",f"Id={row.get('id')} Sha256={row.get('sha256')}",request_security.remote_ip(request),resource=str(row.get("name")),role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"scripts.upload","FAILED",str(exc),request_security.remote_ip(request),resource=str(file.filename),role=identity.role); raise HTTPException(400,str(exc))
        return RedirectResponse("/scripts",status_code=303)

    @app.post("/scripts/{script_id}/approval")
    async def script_approval(request: Request, script_id: int, approved: str = Form(...), note: str = Form("")):
        identity=require(request,"scripts.manage"); await validate_csrf(request,identity)
        flag=str(approved).lower() in {"1","true","yes","approve","approved"}
        row = security.get_script(script_id)
        if row is None:
            raise HTTPException(404, "Script no encontrado")
        if flag and bool(config.get("require_malware_scan_for_scripts", True)) and str(row.get("scan_status") or "").upper() != "CLEAN":
            raise HTTPException(409, f"El script no puede aprobarse: scan={row.get('scan_status')}")
        self_approval = flag and str(row.get("created_by") or "").casefold() == identity.username.casefold()
        if flag and _script_self_approval_blocked(
            config,
            created_by=str(row.get("created_by") or ""),
            actor=identity.username,
            actor_role=identity.role,
        ):
            raise HTTPException(409, "Doble control activo: quien cargó el script no puede aprobarlo salvo un SUPERADMIN autorizado.")
        dual_override = bool(
            self_approval
            and bool(config.get("require_dual_script_approval", True))
            and str(identity.role or "").upper() == "SUPERADMIN"
            and bool(config.get("allow_superadmin_self_script_approval", True))
        )
        security.approve_script(script_id,flag,actor=identity.username,note=note)
        security.audit(
            identity.username,
            "scripts.approval",
            "SUCCESS",
            f"Approved={flag} DualControlOverride={dual_override}",
            request_security.remote_ip(request),
            resource=str(script_id),
            role=identity.role,
        )
        return RedirectResponse("/scripts",status_code=303)

    @app.get("/execute",response_class=HTMLResponse)
    def execute_page(request: Request):
        require(request,"jobs.execute")
        agents=gateway.agents()
        scripts=[x for x in security.list_scripts() if str(x.get("approval_state") or "").upper()=="APPROVED"]
        available,reason=operations.execution_available()
        host_group=str(request.query_params.get("host_group") or "").strip()
        agentless=operations.agentless_groups_view(host_group or None)
        return template(request,"execute.html",{
            "title":"Nueva ejecución","agents":agents,"groups":security.list_groups(),"scripts":scripts,
            "execution_available":available,"execution_reason":reason,
            "host_groups":agentless["groups"],"selected_host_group":agentless["selected_group"],
            "host_sites":agentless["sites"],"ssh_identities":agentless["ssh_identities"],
            "ssh_defaults":agentless.get("ssh_defaults") or {"username":"damautapp","port":22},
        })

    @app.post("/execute")
    async def execute_submit(request: Request):
        identity=require(request,"jobs.execute"); await validate_csrf(request,identity); form=await request.form()
        method=str(form.get("execution_method") or "AGENT").strip().upper()
        script_ids=[int(x) for x in form.getlist("script_id")]
        continue_on_error=str(form.get("continue_on_error") or "") in {"1","true","on"}
        try:
            if method == "AGENTLESS":
                site_codes=[str(x) for x in form.getlist("site_code")]
                meta = await asyncio.to_thread(
                    operations.enqueue_agentless,
                    group_id=str(form.get("site_group") or ""), site_codes=site_codes, script_ids=script_ids,
                    actor=identity.username, ssh_identity_id=str(form.get("ssh_identity_id") or ""),
                    ssh_username=str(form.get("ssh_username") or ""),
                    ssh_port=str(form.get("ssh_port") or "22"),
                    transport_profile=str(form.get("transport_profile") or "SFTP_SSH_SFTP"),
                    network_mode=str(form.get("network_mode") or "AUTO"),
                    continue_on_error=continue_on_error, export_format=str(form.get("export_format") or "xlsx"),
                )
                target_count=len(site_codes)
                audit_action="jobs.enqueue_agentless"
            elif method == "AGENT":
                agent_ids=[str(x) for x in form.getlist("agent_id")]
                meta = await asyncio.to_thread(
                    operations.dispatch,
                    agent_ids=agent_ids, script_ids=script_ids,
                    actor=identity.username, continue_on_error=continue_on_error,
                )
                target_count=len(agent_ids)
                audit_action="jobs.execute"
            else:
                raise ValueError(f"Método de ejecución no soportado: {method}")
            security.audit(identity.username,audit_action,"SUCCESS",f"Targets={target_count} Scripts={len(script_ids)} Method={method}",request_security.remote_ip(request),resource=str(meta.get("JobId")),role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"jobs.execute","FAILED",f"Method={method} {exc}",request_security.remote_ip(request),role=identity.role); raise HTTPException(409,str(exc))
        return RedirectResponse(f"/jobs/{meta['JobId']}",status_code=303)


    def remote_page_context(request: Request, **extra: Any) -> dict[str, Any]:
        host_group = str(request.query_params.get("host_group") or "").strip()
        agent_filter = str(request.query_params.get("agent_id") or "").strip()
        remote_boot_error = str(config.get("_remote_feature_boot_error") or "")
        try:
            agents_raw = gateway.agents()
            gateway_error = ""
        except Exception as exc:
            agents_raw = []
            gateway_error = f"GATEWAY_UNAVAILABLE: {type(exc).__name__}: {exc}"
        agents: list[dict[str, Any]] = []
        for row in agents_raw:
            item = dict(row)
            item["RemoteIPs"] = remote_targets.agent_candidates(item)
            item["ReverseTunnelReady"] = bool(item.get("reverse_tunnel_online"))
            item["RemoteProfile"] = select_agent_remote_profile(item)
            item["RemoteProtocol"] = item["RemoteProfile"]["protocol"]
            item["RemoteProtocols"] = item["RemoteProfile"]["protocols"]
            protocol_readiness = item["RemoteProfile"].get("ready_by_protocol") or {}
            item["RemoteAccessReady"] = (
                any(bool(value) for value in protocol_readiness.values())
                if protocol_readiness else bool(item["RemoteProfile"]["ready"])
            )
            item["RemoteAccessReason"] = item["RemoteProfile"]["reason"]
            # Agents expose their desktop only through the authenticated reverse
            # tunnel.  A stale/private inventory IP is never a valid fallback:
            # /remote/start deliberately refuses direct Agent routes as well.
            route_ready = item["ReverseTunnelReady"]
            capability_ready = (
                not item["RemoteProfile"]["known"]
                or (item["RemoteProfile"]["supported"] and bool(item["RemoteAccessReady"]))
            )
            item["RemoteReady"] = route_ready and capability_ready
            item["RdpNegotiation"] = select_agent_rdp_profile(
                item,
                fallback_security=str(guacd.config.rdp_security or "nla"),
                max_age_seconds=rdp_capability_max_age_seconds,
                allow_policy_legacy=allow_legacy_rdp_policy,
            )
            # ``agent_id`` comes from the quick action on an Agent detail
            # page.  It is a preselection, not an inventory filter: hiding
            # every other enrolled Agent made the main remote-control picker
            # look empty and prevented the operator from changing destination
            # without navigating away first.  Keep all known Agents visible;
            # the template/JS only disable entries whose tunnel or remote
            # service is not ready.
            agents.append(item)
        agentless = operations.agentless_groups_view(host_group or None)
        context: dict[str, Any] = {
            "title": "Control remoto",
            "agents": agents,
            "host_groups": agentless["groups"],
            "selected_host_group": agentless["selected_group"],
            "host_sites": agentless["sites"],
            "remote_credentials": remote_credentials.list_credentials(),
            "guacd_status": guacd.health(),
            "guacamole_client": guacamole_assets.status(),
            "remote_stats": remote_sessions.stats(),
            "selected_agent_id": agent_filter,
            "rdp_security": str(guacd.config.rdp_security or "nla").lower(),
            "error": remote_boot_error or gateway_error,
            "message": "",
        }
        context.update(extra)
        return context

    @app.get("/remote", response_class=HTMLResponse)
    def remote_page(request: Request):
        require(request, "remote.view")
        return template(request, "remote.html", remote_page_context(request))

    @app.get("/remote/step-up-status", response_class=JSONResponse)
    def remote_step_up_status(request: Request):
        """Return the authoritative remote-control MFA reuse window.

        RC30.95.31.10 scopes this grant to the authenticated user + one browser
        context, independent of the selected remote server/list and independent
        from WebAdmin session-row rotation.  No TOTP/password/credential material
        is returned.
        """
        identity = require(request, "remote.control")
        client_id = str(request.headers.get("x-gideon-stepup-client") or request.query_params.get("client_id") or "").strip()
        status = request_security.remote_step_up_context(request, identity, client_id)
        scope_key = request_security.remote_step_up_scope_key(request, identity, client_id)
        return JSONResponse(
            {
                "active": bool(status.get("active")),
                "verified_unix": int(status.get("verified_unix") or 0),
                "until_unix": int(status.get("until_unix") or 0),
                "remaining_seconds": int(status.get("remaining_seconds") or 0),
                "ttl_seconds": int(status.get("ttl_seconds") or 900),
                "session_id": int(identity.session_id),
                "scope": scope_key[:12],
                "backend": STEP_UP_CACHE.backend_name,
                "store_version": STEP_UP_CACHE.store_version,
                "grant_type": "remote-browser-scope",
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/remote/start", response_class=HTMLResponse)
    async def remote_start(request: Request):
        identity = require(request, "remote.control")
        await validate_csrf(request, identity)
        form = await request.form()
        source_type = str(form.get("source_type") or "").strip().upper()
        source_id = str(form.get("source_id") or "").strip()
        protocol = str(form.get("protocol") or "RDP").strip().upper()
        credential_mode = str(form.get("credential_mode") or "VAULT").strip().upper()
        credential_id = str(form.get("credential_id") or "").strip()
        requested_ip = str(form.get("target_ip") or "").strip()
        host_group = str(form.get("host_group") or "").strip()
        interactive_username = str(form.get("interactive_username") or "").strip()
        interactive_domain = str(form.get("interactive_domain") or "").strip()
        interactive_password = str(form.get("interactive_password") or "")
        rdp_session_mode = str(form.get("rdp_session_mode") or "STANDARD").strip().upper()
        # This is an operator-declared intent, not a trust boundary.  The
        # selected Agent profile below recomputes protocol, local impact and
        # whether an acknowledgement is mandatory before any tunnel is opened.
        connection_intent = str(form.get("connection_intent") or "STANDARD_ACCESS").strip().upper()
        intent_acknowledged = str(form.get("intent_acknowledged") or "").strip().lower() in {"1", "true", "on", "yes"}
        clipboard_enabled = bool(
            remote_sessions.policy.clipboard_enabled
            and str(form.get("clipboard_enabled") or "").strip().lower() in {"1", "true", "on", "yes"}
        )
        file_transfer_enabled = bool(
            remote_sessions.policy.file_transfer_enabled
            and protocol == "RDP"
            and str(form.get("file_transfer_enabled") or "").strip().lower() in {"1", "true", "on", "yes"}
        )
        rdp_profile = select_agent_rdp_profile(
            {}, fallback_security=str(guacd.config.rdp_security or "nla"),
            max_age_seconds=rdp_capability_max_age_seconds,
            allow_policy_legacy=allow_legacy_rdp_policy,
        )
        requested_rdp_user = ""
        requested_rdp_domain = ""
        active_console_user = ""
        active_console_domain = ""
        session_switch_expected = False
        max_handoff_reconnects = 0
        ephemeral_id = ""
        passwordless_vnc = False
        selected_vault_credential: dict[str, Any] = {}
        local_session_impact = "NO_LOCAL_IMPACT"
        consent_state = "NOT_APPLICABLE"
        operator_ack_required = False
        request_id = "rreq_" + secrets.token_hex(12)
        remote_profile: dict[str, Any] = {
            "known": False, "ready": None, "supported": True, "protocol": protocol,
            "protocols": [protocol], "port": 3389 if protocol == "RDP" else 5900,
            "server": "", "reason": "", "file_transfer": False,
            "file_transfer_reason": "El Agent todavía no publicó capacidad de transferencia.",
        }
        try:
            # Remote control is already inside an authenticated WebAdmin session.
            # A fresh TOTP is enough when the 15-minute step-up window is not
            # active; the WebAdmin password is deliberately not requested here.
            require_mfa_step_up(
                request, identity, str(form.get("mfa_code") or ""),
                resource=f"remote-session:{source_type}:{source_id}",
                client_id=str(form.get("step_up_client_id") or ""),
            )
            if protocol not in {"RDP", "VNC"}:
                raise RemoteSessionError("Protocolo remoto inválido. Use RDP o VNC.")
            if connection_intent not in {
                "PHYSICAL_CONSOLE", "INDEPENDENT_SESSION", "ADMIN_CONSOLE", "STANDARD_ACCESS"
            }:
                raise RemoteSessionError("REMOTE_CONNECTION_INTENT_INVALID: seleccione una intención de control remoto válida.")
            if credential_mode not in {"VAULT", "INTERACTIVE"}:
                raise RemoteSessionError("Modo de credencial inválido.")

            if source_type == "AGENT":
                agents = await asyncio.to_thread(gateway.agents)
                row = next((x for x in agents if str(x.get("agent_id") or "") == source_id), None)
                if row is None:
                    raise RemoteSessionError("Agent no encontrado.")
                source_label = remote_targets.agent_label(row)
                rdp_profile = select_agent_rdp_profile(
                    row,
                    fallback_security=str(guacd.config.rdp_security or "nla"),
                    max_age_seconds=rdp_capability_max_age_seconds,
                    allow_policy_legacy=allow_legacy_rdp_policy,
                )
                remote_profile = select_agent_remote_profile(row)
                platform_name = str(row.get("platform") or "").strip().lower()
                protocols_announced = {str(item).upper() for item in (remote_profile.get("protocols") or [])}
                ready_by_protocol = remote_profile.get("ready_by_protocol") or {}
                session_kinds = remote_profile.get("session_kinds") or {}
                rdp_kind = str(session_kinds.get("RDP") or "").strip().lower()
                rdp_server = str((remote_profile.get("servers") or {}).get("RDP") or remote_profile.get("server") or "").strip().lower()
                physical_console_available = bool(
                    "VNC" in protocols_announced
                    and ready_by_protocol.get("VNC")
                    and session_kinds.get("VNC") == "physical-console"
                )
                independent_session_available = bool(
                    "RDP" in protocols_announced
                    and ready_by_protocol.get("RDP")
                    and (
                        rdp_kind in {"independent-desktop", "xrdp-desktop"}
                        or (platform_name == "linux" and "xrdp" in rdp_server)
                        or bool(rdp_profile.get("concurrent_sessions_possible"))
                    )
                )
                if connection_intent != "STANDARD_ACCESS" and not remote_profile.get("known"):
                    raise RemoteSessionError(
                        "REMOTE_CONNECTION_INTENT_UNAVAILABLE: el Agent no publicó una capacidad remota firmada; "
                        "actualícelo antes de seleccionar una intención guiada."
                    )
                # The browser can only request an intent. Recompute its
                # allowed transport and session mode from the signed Agent
                # heartbeat before opening any tunnel.
                if connection_intent == "PHYSICAL_CONSOLE":
                    if not physical_console_available:
                        raise RemoteSessionError(
                            "REMOTE_PHYSICAL_CONSOLE_UNAVAILABLE: este Agent no anunció una consola física VNC controlable. "
                            "RDP/Guacamole no se presentará como pantalla física."
                        )
                    protocol, rdp_session_mode = "VNC", "STANDARD"
                elif connection_intent == "INDEPENDENT_SESSION":
                    if not independent_session_available:
                        raise RemoteSessionError(
                            "REMOTE_INDEPENDENT_SESSION_UNAVAILABLE: se requiere XRDP anunciado o Windows Server/RDS "
                            "con capacidad multi-sesión reportada por el Agent."
                        )
                    protocol = "RDP"
                    rdp_session_mode = "SEPARATE" if bool(rdp_profile.get("concurrent_sessions_possible")) else "STANDARD"
                elif connection_intent == "ADMIN_CONSOLE":
                    if not (
                        platform_name == "windows"
                        and "RDP" in protocols_announced
                        and ready_by_protocol.get("RDP")
                        and bool(rdp_profile.get("administrative_console"))
                    ):
                        raise RemoteSessionError(
                            "REMOTE_ADMIN_CONSOLE_UNAVAILABLE: se requiere Windows con RDP administrativo anunciado por el Agent."
                        )
                    protocol, rdp_session_mode = "RDP", "ADMIN"
                if remote_profile["known"]:
                    if not remote_profile["supported"]:
                        raise RemoteSessionError(
                            f"REMOTE_ACCESS_UNSUPPORTED: el Agent {row.get('platform') or 'desconocido'} "
                            f"no tiene un servicio remoto utilizable. {remote_profile['reason']}"
                        )
                    protocol_ready = bool(
                        (remote_profile.get("ready_by_protocol") or {}).get(protocol, remote_profile["ready"])
                    )
                    if not protocol_ready:
                        raise RemoteSessionError(
                            f"REMOTE_ACCESS_NOT_READY: {protocol} ({(remote_profile.get('servers') or {}).get(protocol) or remote_profile['server'] or 'servicio local'}) "
                            f"no está escuchando en el Agent. {remote_profile['reason']}"
                        )
                    if protocol not in set(remote_profile["protocols"]):
                        raise RemoteSessionError(
                            f"REMOTE_PROTOCOL_MISMATCH: el Agent anuncia "
                            f"{', '.join(remote_profile['protocols'])}; se solicitó {protocol}."
                        )
                passwordless_vnc = bool(
                    protocol == "VNC"
                    and (remote_profile.get("session_kinds") or {}).get("VNC") == "physical-console"
                    and not bool((remote_profile.get("password_required") or {}).get("VNC", True))
                )
                # Do not trust the browser checkbox alone.  Linux/xrdp needs
                # xrdp-chansrv for Guacamole's redirected drive; the Agent's
                # signed heartbeat is the authoritative capability signal.
                file_transfer_enabled = bool(file_transfer_enabled and remote_profile.get("file_transfer"))
            elif source_type == "HOST":
                view = operations.agentless_groups_view(host_group or None)
                row = next((x for x in view["sites"] if str(x.get("SiteCode") or "") == source_id), None)
                if row is None:
                    raise RemoteSessionError("Host no encontrado en la lista seleccionada.")
                if connection_intent != "STANDARD_ACCESS":
                    raise RemoteSessionError(
                        "REMOTE_CONNECTION_INTENT_REQUIRES_AGENT: un host directo no informa pantalla física, "
                        "usuarios ni capacidad multi-sesión. Use Acceso directo de compatibilidad o instale un Agent."
                    )
                target_host, source_label = remote_targets.resolve_host(row)
            else:
                raise RemoteSessionError("Seleccione un Agent o un host de lista.")

            if protocol != "RDP":
                rdp_session_mode = "STANDARD"
            elif rdp_session_mode not in {"STANDARD", "RESUME", "ADMIN", "SEPARATE"}:
                if rdp_session_mode == "SHARE":
                    raise RemoteSessionError(
                        "REMOTE_INTERACTIVE_SHARE_UNAVAILABLE: este Agent todavía no incluye el módulo de captura "
                        "interactiva necesario para compartir la pantalla física como AnyDesk/TeamViewer."
                    )
                raise RemoteSessionError("Modo de sesión RDP inválido.")

            # The browser may have started with RDP selected and then the
            # signed Agent profile may have forced a physical VNC console.
            # Re-evaluate after the intent has been resolved so a stale form
            # checkbox can never enable Guacamole's RDP drive on a VNC ticket.
            file_transfer_enabled = bool(file_transfer_enabled and protocol == "RDP")

            if credential_mode == "VAULT":
                credentials = {str(x.get("id") or ""): x for x in remote_credentials.list_credentials(protocol)}
                selected_vault_credential = credentials.get(credential_id) or {}
                if not selected_vault_credential:
                    raise RemoteSessionError("Seleccione un perfil GIDEON compatible con el protocolo.")
                if protocol == "RDP":
                    requested_rdp_user, requested_rdp_domain = normalize_rdp_identity(
                        str(selected_vault_credential.get("username") or ""),
                        str(selected_vault_credential.get("domain") or ""),
                    )
            else:
                if passwordless_vnc and not interactive_username:
                    interactive_username = "physical-console"
                if protocol == "RDP":
                    interactive_username, interactive_domain = normalize_rdp_identity(
                        interactive_username, interactive_domain
                    )
                    requested_rdp_user, requested_rdp_domain = interactive_username, interactive_domain
                if protocol == "RDP" and not interactive_username:
                    raise RemoteSessionError("Ingrese el usuario remoto.")
                if protocol == "RDP" and not interactive_password:
                    raise RemoteSessionError(
                        "RDP_PASSWORD_REQUIRED: ingrese la contraseña real de Windows. GIDEON la mantendrá "
                        "solo en memoria mientras prueba automáticamente los modos autorizados."
                    )

            if protocol == "VNC" and credential_mode == "INTERACTIVE" and not interactive_password and not passwordless_vnc:
                raise RemoteSessionError("VNC requiere la contraseña de conexión.")
            if passwordless_vnc and credential_mode != "INTERACTIVE":
                raise RemoteSessionError(
                    "REMOTE_PHYSICAL_CONSOLE_INTERACTIVE_REQUIRED: la consola física anunciada por el Agent se autoriza "
                    "con sesión interactiva, MFA y ticket de un solo uso; no use un perfil Vault VNC."
                )

            if source_type == "AGENT":
                active_console_user = str(rdp_profile.get("active_console_user") or "").strip()
                active_console_domain = str(rdp_profile.get("active_console_domain") or "").strip()
                session_switch_expected = bool(
                    protocol == "RDP"
                    and str(rdp_profile.get("session_model") or "") == "single-interactive-session"
                    and active_console_user
                    and requested_rdp_user
                    and not rdp_identity_matches_console(
                        requested_rdp_user, requested_rdp_domain, active_console_user, active_console_domain
                    )
                )
                max_handoff_reconnects = int(bool(
                    protocol == "RDP"
                    and credential_mode == "INTERACTIVE"
                    and rdp_session_mode != "SEPARATE"
                    and str(rdp_profile.get("session_model") or "") == "single-interactive-session"
                    and session_switch_expected
                ))
                if connection_intent == "PHYSICAL_CONSOLE":
                    local_session_impact, consent_state, operator_ack_required = (
                        "PHYSICAL_CONSOLE_VISIBLE", "OPERATOR_ACK_REQUIRED", True
                    )
                elif connection_intent == "INDEPENDENT_SESSION":
                    local_session_impact, consent_state = "INDEPENDENT_SESSION", "NOT_APPLICABLE"
                elif session_switch_expected:
                    local_session_impact, consent_state, operator_ack_required = (
                        "POSSIBLE_SESSION_HANDOFF", "OPERATOR_AUTHORIZED_AUTO_HANDOFF", True
                    )
                elif connection_intent == "ADMIN_CONSOLE":
                    local_session_impact, consent_state = "ADMIN_CONSOLE", "NOT_APPLICABLE"
            else:
                local_session_impact, consent_state, operator_ack_required = (
                    "DIRECT_HOST_UNKNOWN", "UNAVAILABLE_DIRECT_HOST", True
                )
            if operator_ack_required and not intent_acknowledged:
                raise RemoteSessionError(
                    "REMOTE_INTENT_ACK_REQUIRED: revise el usuario activo, impacto y consentimiento indicado; "
                    "confirme explícitamente la autorización del operador antes de abrir esta sesión."
                )

            default_port = 3389 if protocol == "RDP" else 5900
            try:
                target_port = int(form.get("target_port") or default_port)
            except (TypeError, ValueError):
                target_port = default_port
            if target_port < 1 or target_port > 65535:
                raise RemoteSessionError("Puerto remoto inválido.")
            advertised_ports = remote_profile.get("ports") if isinstance(remote_profile.get("ports"), dict) else {}
            if source_type == "AGENT" and remote_profile.get("known") and protocol in advertised_ports:
                browser_default = 5900 if protocol == "VNC" else 3389
                if target_port == browser_default:
                    target_port = int(advertised_ports[protocol])
            if protocol == "VNC" and not guacd.config.vnc_enabled:
                raise RemoteSessionError("VNC está deshabilitado por política de seguridad.")

            route_mode = "DIRECT"
            if source_type == "AGENT":
                tunnel_error = ""
                try:
                    reservation = await asyncio.to_thread(
                        gateway.open_reverse_tunnel,
                        source_id,
                        protocol=protocol,
                        target_port=target_port,
                        session_switch={
                            "enabled": session_switch_expected,
                            "request_id": request_id,
                            "active_user": active_console_user,
                            "requested_user": requested_rdp_user,
                            "timeout_seconds": 35,
                        },
                    )
                    target_host = str(reservation.get("BrokerHost") or "").strip()
                    target_port = int(reservation.get("BrokerPort") or 0)
                    if not target_host or target_port < 1 or target_port > 65535:
                        raise RemoteSessionError("El Gateway devolvió una reserva de túnel inválida.")
                    route_mode = "REVERSE_TUNNEL"
                except Exception as exc:
                    # Agents are deliberately configured tunnel-only and keep
                    # RDP/xrdp bound to loopback.  Probing the reported private
                    # IP here only adds a misleading timeout (and can expose a
                    # stale address); fail with the actionable tunnel cause.
                    tunnel_error = f"{type(exc).__name__}: {exc}"
                    raise RemoteSessionError(
                        f"AGENT_REVERSE_TUNNEL_UNAVAILABLE: {tunnel_error}. "
                        "Este Agent usa túnel inverso obligatorio; no se intentará una ruta directa. "
                        "Verifique que figure ONLINE, que ReverseTunnel esté conectado y que RDP/xrdp esté escuchando en loopback."
                    ) from exc
            else:
                reachable, probe_detail = await asyncio.to_thread(
                    remote_targets.probe, target_host, target_port,
                    timeout_seconds=remote_sessions.policy.connect_timeout_seconds,
                )
                if not reachable:
                    raise RemoteSessionError(
                        f"REMOTE_TARGET_UNREACHABLE: {target_host}:{target_port}. {probe_detail}. "
                        "Verifique VPN/ruta y que RDP/VNC esté habilitado en el destino."
                    )

            security_modes = (
                rdp_security_modes(
                    str(rdp_profile.get("preferred_security") or guacd.config.rdp_security),
                    allow_legacy=(route_mode == "REVERSE_TUNNEL" and bool(rdp_profile.get("allow_legacy_rdp"))),
                )
                if protocol == "RDP" else ("",)
            )
            if protocol == "RDP":
                if rdp_session_mode == "SEPARATE" and not bool(rdp_profile.get("concurrent_sessions_possible")):
                    product = str(rdp_profile.get("product_name") or "este Windows")
                    raise RemoteSessionError(
                        f"RDP_SEPARATE_SESSION_UNAVAILABLE: {product} no reporta capacidad multi-sesión. "
                        "Una sesión separada sin interrumpir al usuario requiere Windows Server con RDS habilitado y licenciado."
                    )
                if rdp_session_mode == "ADMIN" and not bool(rdp_profile.get("administrative_console", True)):
                    raise RemoteSessionError("RDP_ADMIN_CONSOLE_UNAVAILABLE: el Agent no reporta consola administrativa.")
            max_security_attempts = len(security_modes) if credential_mode == "INTERACTIVE" else 1
            max_credential_rounds = MAX_REMOTE_CREDENTIAL_ROUNDS if credential_mode == "INTERACTIVE" else 1
            if credential_mode == "INTERACTIVE":
                ephemeral_id = remote_credentials.create_ephemeral(
                    protocol=protocol, username=interactive_username, password=interactive_password,
                    domain=interactive_domain, user_id=identity.user_id, web_session_id=identity.session_id,
                    ttl_seconds=600,
                    max_uses=max_security_attempts + max_handoff_reconnects,
                    allow_empty_password=passwordless_vnc,
                )
                credential_id = ephemeral_id

            row, raw_ticket = remote_sessions.issue(
                user_id=identity.user_id, web_session_id=identity.session_id, username=identity.username,
                source_type=source_type, source_id=source_id, source_label=source_label,
                target_host=target_host, target_port=target_port, protocol=protocol,
                credential_id=credential_id, client_ip=request_security.remote_ip(request),
                credential_mode=credential_mode,
                max_attempts=max_credential_rounds * max_security_attempts,
                route_mode=route_mode,
                credential_round=1,
                security_attempt=1,
                max_credential_rounds=max_credential_rounds,
                max_security_attempts=max_security_attempts,
                clipboard_enabled=clipboard_enabled,
                file_transfer_enabled=file_transfer_enabled,
                rdp_security=(security_modes[0] if protocol == "RDP" else ""),
                rdp_security_plan=security_modes,
                rdp_session_mode=rdp_session_mode,
                max_handoff_reconnects=max_handoff_reconnects,
                connection_intent=connection_intent,
                local_session_impact=local_session_impact,
                operator_acknowledged=intent_acknowledged,
                consent_state=consent_state,
            )
            # Drop local immutable references as early as Python permits.  The
            # interactive secret now lives only in the one-use in-memory cache.
            interactive_password = ""
            security.audit(
                identity.username, "remote.session.issue", "SUCCESS",
                f"Source={source_type}:{source_id}; Protocol={protocol}; Target={target_host}:{target_port}; "
                f"Route={route_mode}; CredentialMode={credential_mode}; SecurityModes={','.join(security_modes) or '-'}; "
                f"SecuritySource={rdp_profile.get('source') or 'webadmin-default'}; "
                f"Intent={connection_intent}; LocalImpact={local_session_impact}; ConsentState={consent_state}; "
                f"IntentAcknowledged={intent_acknowledged}; SessionMode={rdp_session_mode}; SessionModel={rdp_profile.get('session_model') or 'unknown'}; "
                f"SessionSwitchExpected={session_switch_expected}; "
                f"HandoffReconnects={max_handoff_reconnects}; "
                f"Clipboard={'enabled' if clipboard_enabled else 'disabled'}; "
                f"FileTransfer={'enabled' if file_transfer_enabled else 'disabled'}; "
                f"CredentialRounds={max_credential_rounds}; TTL={remote_sessions.policy.ticket_ttl_seconds}s",
                request_security.remote_ip(request), resource=str(row["session_id"]), role=identity.role,
            )
            if intent_acknowledged:
                security.audit(
                    identity.username, "remote.intent.ack", "SUCCESS",
                    f"Intent={connection_intent}; LocalImpact={local_session_impact}; ConsentState={consent_state}; "
                    f"SessionSwitchExpected={session_switch_expected}; ActiveConsoleReported={bool(active_console_user)}",
                    request_security.remote_ip(request), resource=str(row["session_id"]), role=identity.role,
                )
            response = RedirectResponse(f"/remote/session/{row['session_id']}", status_code=303)
            response.set_cookie(
                "gideon_remote_ticket", raw_ticket, httponly=True, secure=bool(config.get("secure_cookies", True)),
                samesite="strict", max_age=int(remote_sessions.policy.ticket_ttl_seconds),
                path=f"/remote/ws/{row['session_id']}",
            )
            return response
        except HTTPException as exc:
            if ephemeral_id:
                remote_credentials.discard_ephemeral(ephemeral_id)
            if exc.status_code in {403, 428}:
                return template(request, "remote.html", remote_page_context(request, error=str(exc.detail)), status_code=exc.status_code)
            raise
        except Exception as exc:
            if ephemeral_id:
                remote_credentials.discard_ephemeral(ephemeral_id)
            interactive_password = ""
            security.audit(
                identity.username, "remote.session.issue", "FAILED", str(exc), request_security.remote_ip(request),
                resource=f"{source_type}:{source_id}", role=identity.role,
            )
            return template(request, "remote.html", remote_page_context(request, error=str(exc)), status_code=409)


    @app.get("/remote/session/{session_id}", response_class=HTMLResponse)
    def remote_viewer(request: Request, session_id: str):
        identity = require(request, "remote.control")
        row = remote_sessions.get_for_user(session_id, identity.user_id)
        if row is None:
            raise HTTPException(404, "Sesión remota no encontrada.")
        session_status = str(row.get("status") or "UNKNOWN").upper()
        connectable = session_status in {"ISSUED", "ACTIVE"}
        client = guacamole_assets.status()
        if not bool(client.get("ready")):
            raise HTTPException(
                409,
                "Falta guacamole-common-js. Un SuperAdmin debe cargar el bundle oficial desde Claves y secretos.",
            )
        return template(request, "remote_viewer.html", {
            "title": "Control remoto",
            "remote_session": row,
            "remote_connectable": connectable,
            "guacamole_client": client,
        })

    def _remote_session_diagnostic_classification(detail: str, end_reason: str) -> tuple[str, str]:
        text = (str(detail or "") + " " + str(end_reason or "")).casefold()
        if "guacd_rdp_stalled" in text:
            return (
                "GUACD_RDP_STALLED",
                "El escritorio dejó de responder a teclado y mouse aunque el último cuadro seguía visible. GIDEON cerró únicamente ese canal para liberar el worker; vuelva a conectar.",
            )
        if "guacd_client_unresponsive" in text or ("aborted. see logs" in text and "776" in text):
            return (
                "GUACD_CLIENT_UNRESPONSIVE",
                "El escritorio llegó al navegador, pero una operación gráfica bloqueó la confirmación de cuadros y guacd cerró por falta de respuesta. Recargue con el visor actualizado; GIDEON usará el decodificador compatible.",
            )
        explicit_bad_credentials = (
            "rdp_authentication_failed", "authentication failure", "authentication failed",
            "logon failure", "status_logon_failure", "0xc000006d", "bad credentials",
            "invalid credentials", "incorrect password", "credentials did not work",
            "credenciales incorrectas", "credenciales no son correctas", "contraseña incorrecta",
            "password is incorrect", "access denied",
        )
        if any(x in text for x in explicit_bad_credentials):
            return (
                "RDP_AUTHENTICATION_FAILED",
                "RDP rechazó las credenciales. GIDEON probará automáticamente todos los modos autorizados con esta misma contraseña antes de solicitar otra.",
            )
        if any(x in text for x in ("wrong security type", "security negotiation failed")):
            return (
                "RDP_SECURITY_NEGOTIATION",
                "El túnel llegó al servicio RDP, pero el modo de seguridad no pudo negociarse. GIDEON probará automáticamente el siguiente modo autorizado con la misma contraseña.",
            )
        if "rdp_nla_password_required" in text:
            return (
                "RDP_NLA_PASSWORD_REQUIRED",
                "Windows exige autenticación NLA antes de mostrar el escritorio. Ingrese la contraseña real de Windows; un PIN de Windows Hello no funciona como contraseña RDP.",
            )
        if any(x in text for x in ("certificate", "certificado", "cert ", "tls", "x509")):
            return (
                "RDP_CERTIFICATE",
                "El canal RDP llegó a guacd pero la validación TLS/certificado parece haber fallado. Revise la política del certificado RDP antes de relajarla.",
            )
        if any(x in text for x in ("authentication", "autentic", "logon", "credentials", "credssp", "nla", "password")):
            return (
                "RDP_AUTHENTICATION",
                "La red y guacd responden, pero RDP rechazó o no pudo completar la autenticación. Revise usuario, dominio, contraseña y NLA.",
            )
        if any(x in text for x in ("timed out", "timeout", "refused", "unreachable", "no route", "network")):
            return (
                "RDP_NETWORK",
                "La sesión no pudo mantener la conexión con el destino RDP. Revise VPN/ruta, puerto 3389 y servicio Remote Desktop del equipo.",
            )
        if "guacd_eof_before_display" in text:
            return (
                "RDP_DROPPED_BEFORE_DISPLAY",
                "guacd aceptó la sesión, pero el destino RDP cerró antes de enviar el primer frame. El detalle de auditoría del servidor indica la siguiente causa útil.",
            )
        if "guacd_remote_error" in text:
            return (
                "GUACD_REMOTE_ERROR",
                "guacd devolvió un error remoto después del handshake. Use el detalle del servidor para corregir la causa exacta.",
            )
        if str(end_reason or "").upper() == "CLIENT_DISCONNECTED":
            return ("CLIENT_DISCONNECTED", "El navegador cerró la sesión de forma normal.")
        if str(end_reason or "").upper() == "CLIENT_REQUESTED_DISCONNECT":
            return ("CLIENT_REQUESTED_DISCONNECT", "El visor solicitó cerrar la conexión; Windows no originó este cierre.")
        return (
            "REMOTE_SESSION_RUNTIME",
            "La sesión terminó sin una clasificación específica. Revise el detalle de auditoría y el estado de guacd mostrados abajo.",
        )

    def _remote_runtime_close_reason(exc: Exception) -> str:
        detail = str(exc or "")
        classification, _ = _remote_session_diagnostic_classification(detail, "")
        if classification == "RDP_AUTHENTICATION_FAILED":
            return "RDP_AUTHENTICATION_FAILED"
        if classification == "RDP_NLA_PASSWORD_REQUIRED":
            return "RDP_NLA_PASSWORD_REQUIRED"
        if classification == "RDP_SECURITY_NEGOTIATION":
            return "RDP_SECURITY_NEGOTIATION"
        if classification == "RDP_CERTIFICATE":
            return "RDP_CERTIFICATE"
        if classification == "RDP_NETWORK":
            return "RDP_NETWORK"
        if classification == "GUACD_CLIENT_UNRESPONSIVE":
            return "GUACD_CLIENT_UNRESPONSIVE"
        if classification == "GUACD_RDP_STALLED":
            return "GUACD_RDP_STALLED"
        if "GUACD_EOF_BEFORE_DISPLAY" in detail:
            return "GUACD_EOF_BEFORE_DISPLAY"
        if "GUACD_REMOTE_ERROR" in detail:
            return "GUACD_REMOTE_ERROR"
        return type(exc).__name__

    def _remote_session_audit_rows(session_id: str) -> list[dict[str, Any]]:
        audit_rows: list[dict[str, Any]] = []
        for item in security.list_audit(limit=500):
            if str(item.get("resource") or "") != str(session_id):
                continue
            action = str(item.get("action") or "")
            if not action.startswith("remote.session."):
                continue
            audit_rows.append({
                "created_at": str(item.get("created_at") or ""),
                "action": action,
                "result": str(item.get("result") or ""),
                "detail": str(item.get("detail") or "")[:4000],
            })
        return audit_rows[:40]

    def _remote_retry_state(row: dict[str, Any], identity: Any, classification: str) -> dict[str, Any]:
        protocol = str(row.get("protocol") or "").upper()
        mode = str(row.get("credential_mode") or "VAULT").upper()
        route_mode = str(row.get("route_mode") or "DIRECT").upper()
        declared_max_security = max(1, min(int(row.get("max_security_attempts") or 1), 4))
        stored_modes = tuple(
            item for item in str(row.get("rdp_security_plan") or "").split(",")
            if item in {"any", "nla", "tls", "rdp"}
        )
        modes = stored_modes if protocol == "RDP" and stored_modes else (
            rdp_security_modes(
                guacd.config.rdp_security,
                allow_legacy=(route_mode == "REVERSE_TUNNEL" and declared_max_security >= 4),
            ) if protocol == "RDP" else ("",)
        )
        credential_round = max(1, int(row.get("credential_round") or 1))
        security_attempt = max(1, int(row.get("security_attempt") or 1))
        max_credential_rounds = max(1, min(int(row.get("max_credential_rounds") or 1), MAX_REMOTE_CREDENTIAL_ROUNDS))
        max_security_attempts = max(1, min(declared_max_security, len(modes)))
        retry_attempt = max(1, int(row.get("retry_attempt") or 1))
        max_attempts = max(1, int(row.get("max_attempts") or 1))
        closed = str(row.get("status") or "").upper() in {"CLOSED", "EXPIRED"}
        retryable_failure = classification in REMOTE_RETRYABLE_CLASSIFICATIONS
        automatic_failure = classification in REMOTE_AUTOMATIC_SECURITY_CLASSIFICATIONS
        credential_available = False
        if mode == "INTERACTIVE" and protocol == "RDP" and str(row.get("status") or "").upper() in {"ACTIVE", "CLOSED", "EXPIRED"}:
            try:
                reference = remote_sessions.credential_reference_for_retry(
                    str(row.get("session_id") or ""),
                    user_id=identity.user_id,
                    web_session_id=identity.session_id,
                    username=identity.username,
                )
                credential_available = remote_credentials.ephemeral_available(
                    reference,
                    protocol=protocol,
                    user_id=identity.user_id,
                    web_session_id=identity.session_id,
                )
            except Exception:
                credential_available = False
        has_next_security = security_attempt < max_security_attempts
        automatic_eligible = bool(
            mode == "INTERACTIVE"
            and protocol == "RDP"
            and closed
            and automatic_failure
            and has_next_security
            and credential_available
        )
        credential_eligible = bool(
            mode == "INTERACTIVE"
            and closed
            and retryable_failure
            and credential_round < max_credential_rounds
            and (not automatic_failure or not has_next_security or not credential_available)
        )
        handoff_attempt = max(0, int(row.get("handoff_reconnect_attempt") or 0))
        max_handoff_reconnects = max(0, min(int(row.get("max_handoff_reconnects") or 0), 1))
        handoff_reconnect_eligible = bool(
            mode == "INTERACTIVE"
            and protocol == "RDP"
            and str(row.get("source_type") or "").upper() == "AGENT"
            and str(row.get("route_mode") or "").upper() == "REVERSE_TUNNEL"
            and str(row.get("status") or "").upper() in {"ACTIVE", "CLOSED"}
            and handoff_attempt < max_handoff_reconnects
            and credential_available
        )
        next_security = modes[security_attempt] if protocol == "RDP" and has_next_security else ""
        return {
            "credential_mode": mode,
            "attempt": retry_attempt,
            "max_attempts": max_attempts,
            "remaining": max(0, max_attempts - retry_attempt),
            "credential_round": credential_round,
            "max_credential_rounds": max_credential_rounds,
            "remaining_credentials": max(0, max_credential_rounds - credential_round),
            "security_attempt": security_attempt,
            "max_security_attempts": max_security_attempts,
            "security_modes": list(modes[:max_security_attempts]),
            "rdp_security": str(row.get("rdp_security") or (modes[0] if protocol == "RDP" else "")),
            "next_rdp_security": next_security,
            "credential_available": credential_available,
            "automatic_eligible": automatic_eligible,
            "credential_eligible": credential_eligible,
            # Backward-compatible alias used by older viewer bundles.
            "eligible": credential_eligible,
            "handoff_reconnect_attempt": handoff_attempt,
            "max_handoff_reconnects": max_handoff_reconnects,
            "handoff_reconnect_eligible": handoff_reconnect_eligible,
        }

    async def _remote_retry_target(row: dict[str, Any]) -> tuple[str, int, str]:
        retry_target_host = str(row.get("target_host") or "")
        retry_target_port = int(row.get("target_port") or 0)
        retry_route_mode = str(row.get("route_mode") or "DIRECT")
        if str(row.get("source_type") or "").upper() == "AGENT":
            protocol = str(row.get("protocol") or "RDP").strip().upper()
            advertised_port = 3389 if protocol == "RDP" else 5900
            # Broker ports are one-use and cannot be reused as the Agent's
            # loopback target. Refresh the signed capability heartbeat so a
            # retry keeps xrdp/VNC's advertised non-default service port.
            agents = await asyncio.to_thread(gateway.agents)
            agent = next(
                (item for item in agents if str(item.get("agent_id") or "") == str(row.get("source_id") or "")),
                None,
            )
            if isinstance(agent, dict):
                profile = select_agent_remote_profile(agent)
                ports = profile.get("ports") if isinstance(profile.get("ports"), dict) else {}
                try:
                    candidate = int(ports.get(protocol) or advertised_port)
                except (TypeError, ValueError):
                    candidate = advertised_port
                if 1 <= candidate <= 65535:
                    advertised_port = candidate
            reservation = await asyncio.to_thread(
                gateway.open_reverse_tunnel,
                str(row.get("source_id") or ""),
                protocol=protocol,
                target_port=advertised_port,
            )
            retry_target_host = str(reservation.get("BrokerHost") or "").strip()
            retry_target_port = int(reservation.get("BrokerPort") or 0)
            if not retry_target_host or retry_target_port < 1 or retry_target_port > 65535:
                raise RemoteSessionError("El Gateway devolvió una reserva de túnel inválida para el reintento.")
            retry_route_mode = "REVERSE_TUNNEL"
        return retry_target_host, retry_target_port, retry_route_mode

    @app.get("/remote/session/{session_id}/diagnostics.json")
    def remote_session_diagnostics(request: Request, session_id: str):
        identity = require(request, "remote.control")
        row = remote_sessions.get_for_user(session_id, identity.user_id)
        if row is None:
            raise HTTPException(404, "Sesión remota no encontrada.")
        audit_rows = _remote_session_audit_rows(session_id)
        runtime_failure = next((
            x for x in audit_rows
            if x.get("action") in {"remote.session.runtime", "remote.session.connect"}
            and str(x.get("result") or "").upper() == "FAILED"
        ), None)
        detail = str((runtime_failure or {}).get("detail") or "")
        server_status = str(row.get("status") or "UNKNOWN").upper()
        end_reason = str(row.get("end_reason") or "")
        if runtime_failure is None and not end_reason and server_status in {"ISSUED", "ACTIVE"}:
            classification = (
                "REMOTE_SESSION_ACTIVE" if server_status == "ACTIVE" else "REMOTE_SESSION_PENDING"
            )
            recommendation = ""
        else:
            classification, recommendation = _remote_session_diagnostic_classification(
                detail, end_reason
            )
        retry_state = _remote_retry_state(row, identity, classification)
        effective_rdp_security = str(retry_state.get("rdp_security") or "")
        guacd_health = guacd.health(timeout=0.8)
        return JSONResponse({
            "schema": 3,
            "version": PRODUCT_VERSION,
            "session_id": str(row.get("session_id") or session_id),
            "server_status": server_status,
            "end_reason": end_reason,
            "source_type": str(row.get("source_type") or ""),
            "source_id": str(row.get("source_id") or ""),
            "source_label": str(row.get("source_label") or ""),
            "route_mode": str(row.get("route_mode") or "DIRECT"),
            "target_host": str(row.get("target_host") or ""),
            "target_port": int(row.get("target_port") or 0),
            "protocol": str(row.get("protocol") or ""),
            "rdp_session_mode": str(row.get("rdp_session_mode") or "STANDARD"),
            # These are operator-visible decision facts only.  Do not add the
            # reported console user, a Vault identity or any credential data to
            # this endpoint/report because diagnostics are designed to be
            # safely copied into a support ticket.
            "connection_intent": str(row.get("connection_intent") or "STANDARD_ACCESS"),
            "local_session_impact": str(row.get("local_session_impact") or ""),
            "operator_acknowledged": bool(row.get("operator_acknowledged", 0)),
            "consent_state": str(row.get("consent_state") or "NOT_APPLICABLE"),
            "created_at": str(row.get("created_at") or ""),
            "activated_at": str(row.get("activated_at") or ""),
            "ended_at": str(row.get("ended_at") or ""),
            "classification": classification,
            "recommendation": recommendation,
            "runtime_error": detail,
            "retry": retry_state,
            "capabilities": {
                "clipboard": bool(row.get("clipboard_enabled", 1)),
                "file_transfer": bool(row.get("file_transfer_enabled", 1)),
                "max_clipboard_bytes": int(remote_sessions.policy.max_clipboard_bytes),
                "max_file_transfer_bytes": int(remote_sessions.policy.max_file_transfer_bytes),
            },
            "guacd": {
                "online": bool(guacd_health.get("online")),
                "host": str(guacd_health.get("host") or ""),
                "port": int(guacd_health.get("port") or 0),
                "latency_ms": int(guacd_health.get("latency_ms") or 0),
                "error": str(guacd_health.get("error") or "")[:1000],
                "rdp_security": effective_rdp_security,
                "rdp_ignore_cert": True,
            },
            "audit": audit_rows,
        })

    @app.post("/remote/session/{session_id}/handoff-reconnect")
    async def remote_session_handoff_reconnect(request: Request, session_id: str):
        """Replace the first RDP transport once after Windows session arbitration."""
        identity = require(request, "remote.control")
        await validate_csrf(request, identity)
        row = remote_sessions.get_for_user(session_id, identity.user_id)
        if row is None:
            raise HTTPException(404, "Sesión remota no encontrada.")
        state = _remote_retry_state(row, identity, "REMOTE_SESSION_ACTIVE")
        if not bool(state.get("handoff_reconnect_eligible")):
            raise HTTPException(409, "Esta sesión no requiere o ya utilizó el reenganche de Windows.")
        try:
            retry_target_host, retry_target_port, retry_route_mode = await _remote_retry_target(row)
            new_row, raw_ticket = remote_sessions.issue_handoff_reconnect(
                previous_session_id=session_id,
                user_id=identity.user_id,
                web_session_id=identity.session_id,
                username=identity.username,
                client_ip=request_security.remote_ip(request),
                target_host=retry_target_host,
                target_port=retry_target_port,
                route_mode=retry_route_mode,
            )
            security.audit(
                identity.username, "remote.session.handoff_reconnect", "SUCCESS",
                f"Previous={session_id}; New={new_row['session_id']}; "
                f"Handoff={new_row.get('handoff_reconnect_attempt')}/{new_row.get('max_handoff_reconnects')}; "
                f"CredentialRound={new_row.get('credential_round')}; SecurityAttempt={new_row.get('security_attempt')}; "
                f"RdpSecurity={new_row.get('rdp_security') or '-'}; "
                f"Target={new_row.get('target_host')}:{new_row.get('target_port')}",
                request_security.remote_ip(request), resource=str(new_row["session_id"]), role=identity.role,
            )
            response = JSONResponse({
                "ok": True,
                "session_id": str(new_row["session_id"]),
                "url": f"/remote/session/{new_row['session_id']}",
                "handoff_reconnect_attempt": int(new_row.get("handoff_reconnect_attempt") or 0),
                "max_handoff_reconnects": int(new_row.get("max_handoff_reconnects") or 0),
            })
            response.set_cookie(
                "gideon_remote_ticket", raw_ticket, httponly=True, secure=bool(config.get("secure_cookies", True)),
                samesite="strict", max_age=int(remote_sessions.policy.ticket_ttl_seconds),
                path=f"/remote/ws/{new_row['session_id']}",
            )
            return response
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(
                identity.username, "remote.session.handoff_reconnect", "FAILED", str(exc),
                request_security.remote_ip(request), resource=session_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))

    @app.post("/remote/session/{session_id}/auto-retry")
    async def remote_session_auto_retry(request: Request, session_id: str):
        """Try the next RDP security mode using the same in-memory password."""
        identity = require(request, "remote.control")
        await validate_csrf(request, identity)
        row = remote_sessions.get_for_user(session_id, identity.user_id)
        if row is None:
            raise HTTPException(404, "Sesión remota no encontrada.")
        audit_rows = _remote_session_audit_rows(session_id)
        runtime_failure = next((
            x for x in audit_rows
            if x.get("action") in {"remote.session.runtime", "remote.session.connect"}
            and str(x.get("result") or "").upper() == "FAILED"
        ), None)
        detail = str((runtime_failure or {}).get("detail") or "")
        classification, _ = _remote_session_diagnostic_classification(detail, str(row.get("end_reason") or ""))
        state = _remote_retry_state(row, identity, classification)
        if not bool(state.get("automatic_eligible")):
            if bool(state.get("credential_eligible")):
                raise HTTPException(409, "La contraseña actual agotó sus modos; ingrese una nueva contraseña.")
            raise HTTPException(409, "Esta sesión no admite otro modo automático.")
        try:
            retry_target_host, retry_target_port, retry_route_mode = await _remote_retry_target(row)
            new_row, raw_ticket = remote_sessions.issue_retry(
                previous_session_id=session_id,
                user_id=identity.user_id,
                web_session_id=identity.session_id,
                username=identity.username,
                credential_id="",
                reuse_credential=True,
                client_ip=request_security.remote_ip(request),
                target_host=retry_target_host,
                target_port=retry_target_port,
                route_mode=retry_route_mode,
                rdp_security=str(state.get("next_rdp_security") or ""),
            )
            security.audit(
                identity.username, "remote.session.security_retry", "SUCCESS",
                f"Previous={session_id}; New={new_row['session_id']}; "
                f"CredentialRound={new_row.get('credential_round')}/{new_row.get('max_credential_rounds')}; "
                f"SecurityAttempt={new_row.get('security_attempt')}/{new_row.get('max_security_attempts')}; "
                f"RdpSecurity={new_row.get('rdp_security') or '-'}; "
                f"Target={new_row.get('target_host')}:{new_row.get('target_port')}",
                request_security.remote_ip(request), resource=str(new_row["session_id"]), role=identity.role,
            )
            response = JSONResponse({
                "ok": True,
                "session_id": str(new_row["session_id"]),
                "url": f"/remote/session/{new_row['session_id']}",
                "credential_round": int(new_row.get("credential_round") or 1),
                "max_credential_rounds": int(new_row.get("max_credential_rounds") or MAX_REMOTE_CREDENTIAL_ROUNDS),
                "security_attempt": int(new_row.get("security_attempt") or 1),
                "max_security_attempts": int(new_row.get("max_security_attempts") or 1),
                "rdp_security": str(new_row.get("rdp_security") or ""),
            })
            response.set_cookie(
                "gideon_remote_ticket", raw_ticket, httponly=True, secure=bool(config.get("secure_cookies", True)),
                samesite="strict", max_age=int(remote_sessions.policy.ticket_ttl_seconds),
                path=f"/remote/ws/{new_row['session_id']}",
            )
            return response
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(
                identity.username, "remote.session.security_retry", "FAILED", str(exc),
                request_security.remote_ip(request), resource=session_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))

    @app.post("/remote/session/{session_id}/retry")
    async def remote_session_retry(request: Request, session_id: str):
        identity = require(request, "remote.control")
        await validate_csrf(request, identity)
        row = remote_sessions.get_for_user(session_id, identity.user_id)
        if row is None:
            raise HTTPException(404, "Sesión remota no encontrada.")
        audit_rows = _remote_session_audit_rows(session_id)
        runtime_failure = next((
            x for x in audit_rows
            if x.get("action") in {"remote.session.runtime", "remote.session.connect"}
            and str(x.get("result") or "").upper() == "FAILED"
        ), None)
        detail = str((runtime_failure or {}).get("detail") or "")
        classification, _ = _remote_session_diagnostic_classification(detail, str(row.get("end_reason") or ""))
        mode = str(row.get("credential_mode") or "VAULT").upper()
        retry_state = _remote_retry_state(row, identity, classification)
        if (
            mode != "INTERACTIVE"
            or str(row.get("status") or "").upper() not in {"CLOSED", "EXPIRED"}
            or classification not in REMOTE_RETRYABLE_CLASSIFICATIONS
        ):
            raise HTTPException(409, "Esta sesión no admite reintento de credenciales.")
        if bool(retry_state.get("automatic_eligible")):
            raise HTTPException(409, "GIDEON todavía debe probar automáticamente los demás modos con la contraseña actual.")
        if not bool(retry_state.get("credential_eligible")):
            raise HTTPException(409, "Se agotaron las 3 contraseñas permitidas para esta conexión.")

        form = await request.form()
        interactive_username = str(form.get("interactive_username") or "").strip()
        interactive_domain = str(form.get("interactive_domain") or "").strip()
        interactive_password = str(form.get("interactive_password") or "")
        ephemeral_id = ""
        try:
            if str(row.get("protocol") or "RDP").upper() == "RDP":
                interactive_username, interactive_domain = normalize_rdp_identity(
                    interactive_username, interactive_domain
                )
            if not interactive_username:
                raise RemoteSessionError("Ingrese el usuario remoto.")
            if str(row.get("protocol") or "RDP").upper() == "RDP" and not interactive_password:
                raise RemoteSessionError(
                    "RDP_PASSWORD_REQUIRED: ingrese la contraseña real de Windows. GIDEON la mantendrá "
                    "solo en memoria mientras prueba los modos autorizados para este reintento."
                )
            retry_target_host, retry_target_port, retry_route_mode = await _remote_retry_target(row)
            max_security_attempts = max(1, int(retry_state.get("max_security_attempts") or 1))
            try:
                previous_ephemeral_id = remote_sessions.credential_reference_for_retry(
                    session_id,
                    user_id=identity.user_id,
                    web_session_id=identity.session_id,
                    username=identity.username,
                )
                remote_credentials.discard_ephemeral(previous_ephemeral_id)
            except Exception:
                pass
            ephemeral_id = remote_credentials.create_ephemeral(
                protocol=str(row.get("protocol") or "RDP"),
                username=interactive_username,
                password=interactive_password,
                domain=interactive_domain,
                user_id=identity.user_id,
                web_session_id=identity.session_id,
                ttl_seconds=600,
                max_uses=max_security_attempts + max(
                    0,
                    int(retry_state.get("max_handoff_reconnects") or 0)
                    - int(retry_state.get("handoff_reconnect_attempt") or 0),
                ),
            )
            new_row, raw_ticket = remote_sessions.issue_retry(
                previous_session_id=session_id,
                user_id=identity.user_id,
                web_session_id=identity.session_id,
                username=identity.username,
                credential_id=ephemeral_id,
                client_ip=request_security.remote_ip(request),
                target_host=retry_target_host,
                target_port=retry_target_port,
                route_mode=retry_route_mode,
                rdp_security=(
                    str((retry_state.get("security_modes") or [guacd.config.rdp_security])[0])
                    if str(row.get("protocol") or "RDP").upper() == "RDP" else ""
                ),
            )
            interactive_password = ""
            security.audit(
                identity.username, "remote.session.retry", "SUCCESS",
                f"Previous={session_id}; New={new_row['session_id']}; "
                f"CredentialRound={new_row.get('credential_round')}/{new_row.get('max_credential_rounds')}; "
                f"SecurityAttempt={new_row.get('security_attempt')}/{new_row.get('max_security_attempts')}; "
                f"Protocol={new_row.get('protocol')}; RdpSecurity={new_row.get('rdp_security') or '-'}; "
                f"Target={new_row.get('target_host')}:{new_row.get('target_port')}",
                request_security.remote_ip(request), resource=str(new_row["session_id"]), role=identity.role,
            )
            response = JSONResponse({
                "ok": True,
                "session_id": str(new_row["session_id"]),
                "url": f"/remote/session/{new_row['session_id']}",
                "credential_round": int(new_row.get("credential_round") or 1),
                "max_credential_rounds": int(new_row.get("max_credential_rounds") or MAX_REMOTE_CREDENTIAL_ROUNDS),
                "security_attempt": int(new_row.get("security_attempt") or 1),
                "max_security_attempts": int(new_row.get("max_security_attempts") or 1),
            })
            response.set_cookie(
                "gideon_remote_ticket", raw_ticket, httponly=True, secure=bool(config.get("secure_cookies", True)),
                samesite="strict", max_age=int(remote_sessions.policy.ticket_ttl_seconds),
                path=f"/remote/ws/{new_row['session_id']}",
            )
            return response
        except HTTPException:
            if ephemeral_id:
                remote_credentials.discard_ephemeral(ephemeral_id)
            interactive_password = ""
            raise
        except Exception as exc:
            if ephemeral_id:
                remote_credentials.discard_ephemeral(ephemeral_id)
            interactive_password = ""
            security.audit(
                identity.username, "remote.session.retry", "FAILED", str(exc), request_security.remote_ip(request),
                resource=session_id, role=identity.role,
            )
            raise HTTPException(409, str(exc))

    def _ws_origin_allowed(websocket: WebSocket) -> bool:
        origin = str(websocket.headers.get("origin") or "").strip().lower().rstrip("/")
        configured = [str(x).strip().lower().rstrip("/") for x in ((config.get("remote_sessions") or {}).get("allowed_origins") or []) if str(x).strip()]
        if configured:
            return origin in configured
        host = str(websocket.headers.get("host") or "").strip().lower()
        if not host or not origin:
            return False
        if bool(config.get("trust_proxy_headers", False)):
            proto = str(websocket.headers.get("x-forwarded-proto") or "https").split(",")[0].strip().lower()
        else:
            proto = "https" if websocket.url.scheme == "wss" else "http"
        return origin == f"{proto}://{host}".rstrip("/")

    def _ws_remote_ip(websocket: WebSocket) -> str:
        if bool(config.get("trust_proxy_headers", False)):
            forwarded = str(websocket.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            if forwarded:
                return forwarded
        return str(websocket.client.host if websocket.client else "")

    @app.websocket("/remote/ws/{session_id}")
    async def remote_websocket(websocket: WebSocket, session_id: str):
        identity = security.identity_for_session(websocket.cookies.get(SESSION_COOKIE, ""))
        raw_ticket = str(websocket.cookies.get("gideon_remote_ticket") or "")
        if (
            identity is None
            or not identity.can("remote.control")
            or (bool(config.get("require_mfa", True)) and (not identity.mfa_enabled or not identity.mfa_complete))
            or not _ws_origin_allowed(websocket)
        ):
            await websocket.close(code=4403)
            return
        try:
            row = remote_sessions.consume(
                session_id=session_id,
                raw_ticket=raw_ticket,
                user_id=identity.user_id,
                web_session_id=identity.session_id,
                username=identity.username,
                client_ip=_ws_remote_ip(websocket),
            )
        except Exception as exc:
            security.audit(
                identity.username,
                "remote.session.connect",
                "FAILED",
                str(exc),
                _ws_remote_ip(websocket),
                resource=session_id,
                role=identity.role,
            )
            await websocket.close(code=4403)
            return

        requested_protocols = [x.strip() for x in str(websocket.headers.get("sec-websocket-protocol") or "").split(",") if x.strip()]
        await websocket.accept(subprotocol="guacamole" if "guacamole" in requested_protocols else None)
        writer = None
        close_reason = "DISCONNECTED"
        server_flow = {
            "graphics_seen": False,
            "last_opcode": "",
            "remote_disconnect": False,
            "client_disconnect_requested": False,
            "server_syncs": 0,
            "client_syncs": 0,
            "last_server_sync": "",
            "last_client_sync": "",
            # A FreeRDP worker can keep the guacd control socket open after
            # XRDP has dropped the RDP socket. Track actual bidirectional
            # activity so that one frozen relay cannot spin forever.
            "last_server_activity": time.monotonic(),
            "last_meaningful_server_activity": time.monotonic(),
            "last_visual_activity": 0.0,
            "last_interactive_input": 0.0,
            "interactive_inputs_since_meaningful_server": 0,
        }
        try:
            def viewport_dimension(name: str, default: int, minimum: int, maximum: int) -> int:
                try:
                    value = int(str(websocket.query_params.get(name) or default))
                except (TypeError, ValueError):
                    value = default
                value = max(minimum, min(value, maximum))
                return value - (value % 2)

            viewport_width = viewport_dimension("width", 1440, 640, 3840)
            viewport_height = viewport_dimension("height", 900, 480, 2160)
            viewport_dpi = viewport_dimension("dpi", 96, 72, 240)
            credential = remote_credentials.reveal_for_session(
                str(row.get("credential_id") or ""),
                protocol=str(row.get("protocol") or ""),
                user_id=identity.user_id,
                web_session_id=identity.session_id,
            )
            try:
                reader, writer, guac_parser, connection_id = await guacd.connect_and_handshake(
                    protocol=str(row.get("protocol") or "").lower(),
                    target_host=str(row.get("target_host") or ""),
                    target_port=int(row.get("target_port") or 0),
                    credential=credential,
                    width=viewport_width,
                    height=viewport_height,
                    dpi=viewport_dpi,
                    session_id=str(row.get("session_id") or session_id),
                    clipboard_enabled=bool(row.get("clipboard_enabled", 1)),
                    file_transfer_enabled=bool(row.get("file_transfer_enabled", 1)),
                    rdp_security=str(row.get("rdp_security") or "any"),
                    rdp_session_mode=str(row.get("rdp_session_mode") or "STANDARD"),
                )
            finally:
                # Also clear the local secret when handshake/authentication fails.
                # The ephemeral vault entry was already consumed by reveal_for_session.
                credential.clear()
            security.audit(
                identity.username,
                "remote.session.connected",
                "SUCCESS",
                f"Protocol={row.get('protocol')}; Target={row.get('target_host')}:{row.get('target_port')}; GuacdId={connection_id[:80]}",
                _ws_remote_ip(websocket),
                resource=session_id,
                role=identity.role,
            )

            async def browser_to_guacd() -> None:
                client_parser = type(guac_parser)()
                allowed = {"mouse", "key", "size", "sync", "ack", "nop", "disconnect", "clipboard", "file", "blob", "end"}
                clipboard_enabled = bool(row.get("clipboard_enabled", 1))
                file_transfer_enabled = bool(row.get("file_transfer_enabled", 1)) and str(row.get("protocol") or "").upper() == "RDP"
                client_streams: dict[str, dict[str, Any]] = {}
                # guacamole-common-js emits 3.nop; roughly every 5 seconds as a
                # legitimate tunnel keepalive. Rejecting it kills otherwise healthy
                # RDP sessions after graphics have already started rendering.
                while True:
                    message = await websocket.receive()
                    if message.get("type") == "websocket.disconnect":
                        raise WebSocketDisconnect(message.get("code") or 1000)
                    if message.get("bytes") is not None:
                        raise GuacamoleError("El túnel GIDEON Guacamole solo admite frames WebSocket de texto.")
                    text = str(message.get("text") or "")
                    if len(text) > 1024 * 1024:
                        raise GuacamoleError("Frame Guacamole del navegador demasiado grande.")
                    # Some browsers/libraries emit an empty WebSocket text frame
                    # while the Guacamole tunnel is closing after an RDP error.
                    # It carries no Guacamole instruction and must not mask the
                    # server-side authentication/certificate/network cause.
                    if text == "":
                        continue
                    client_parser.feed(text.encode("utf-8"))
                    pending = client_parser.drain_pending()
                    # WebSocket framing and Guacamole instruction framing are
                    # independent.  Keep a partial instruction buffered until a
                    # later WebSocket frame completes it instead of treating
                    # benign fragmentation as an attack.
                    if not pending:
                        continue
                    for instruction in pending:
                        parts = parse_guac_instruction(instruction)
                        opcode = parts[0] if parts else ""
                        if not opcode:
                            # A parser no-op during tunnel shutdown is harmless.
                            # Never promote it to REMOTE_SESSION_RUNTIME.
                            continue
                        if opcode not in allowed:
                            raise GuacamoleError(f"Opcode Guacamole del navegador no permitido: {opcode}")
                        if opcode == "sync":
                            server_flow["client_syncs"] = int(server_flow["client_syncs"]) + 1
                            server_flow["last_client_sync"] = str(parts[1] if len(parts) > 1 else "")[:80]
                        if opcode in {"key", "mouse"} and server_flow["graphics_seen"]:
                            # Silence is legitimate on a static desktop. Several
                            # unanswered operator inputs are not.
                            server_flow["last_interactive_input"] = time.monotonic()
                            server_flow["interactive_inputs_since_meaningful_server"] = (
                                int(server_flow["interactive_inputs_since_meaningful_server"]) + 1
                            )
                        if opcode == "disconnect":
                            server_flow["client_disconnect_requested"] = True
                        if opcode == "clipboard":
                            if not clipboard_enabled:
                                raise GuacamoleError("REMOTE_CLIPBOARD_DISABLED: el portapapeles no está autorizado para esta sesión.")
                            if len(parts) != 3 or not str(parts[1]).isdigit() or not str(parts[2]).lower().startswith("text/"):
                                raise GuacamoleError("Stream de portapapeles Guacamole inválido.")
                            client_streams[str(parts[1])] = {"kind": "clipboard", "bytes": 0}
                        elif opcode == "file":
                            if not file_transfer_enabled:
                                raise GuacamoleError("REMOTE_FILE_TRANSFER_DISABLED: la transferencia de archivos no está autorizada para esta sesión.")
                            if len(parts) != 4 or not str(parts[1]).isdigit():
                                raise GuacamoleError("Stream de archivo Guacamole inválido.")
                            filename = str(parts[3] or "")
                            if (
                                not filename or len(filename) > 240
                                or filename in {".", ".."}
                                or "/" in filename or "\\" in filename
                                or any(ord(ch) < 32 for ch in filename)
                            ):
                                raise GuacamoleError("Nombre de archivo remoto inválido.")
                            client_streams[str(parts[1])] = {"kind": "file", "bytes": 0, "name": filename}
                        elif opcode == "blob":
                            if len(parts) != 3 or str(parts[1]) not in client_streams:
                                raise GuacamoleError("Blob Guacamole sin stream autorizado.")
                            stream = client_streams[str(parts[1])]
                            try:
                                decoded_bytes = len(base64.b64decode(str(parts[2]).encode("ascii"), validate=True))
                            except Exception as exc:
                                raise GuacamoleError("Blob Guacamole Base64 inválido.") from exc
                            stream["bytes"] = int(stream.get("bytes") or 0) + decoded_bytes
                            maximum = (
                                int(remote_sessions.policy.max_file_transfer_bytes)
                                if stream.get("kind") == "file"
                                else int(remote_sessions.policy.max_clipboard_bytes)
                            )
                            if int(stream["bytes"]) > maximum:
                                raise GuacamoleError(f"Stream Guacamole excede el límite autorizado de {maximum} bytes.")
                        elif opcode == "end":
                            if len(parts) != 2 or str(parts[1]) not in client_streams:
                                raise GuacamoleError("Fin de stream Guacamole no autorizado.")
                            finished = client_streams.pop(str(parts[1]))
                            if finished.get("kind") == "file":
                                security.audit(
                                    identity.username, "remote.session.file_upload", "SUCCESS",
                                    f"Name={finished.get('name')}; Bytes={int(finished.get('bytes') or 0)}",
                                    _ws_remote_ip(websocket), resource=session_id, role=identity.role,
                                )
                        writer.write(instruction.encode("utf-8"))
                    await writer.drain()

            server_streams: dict[str, dict[str, Any]] = {}

            async def guacd_to_browser() -> None:
                # Handshake and initial display instructions can share one TCP read.
                # RC30.95.31 records Guacamole error metadata before attempting to
                # write to the browser. This preserves the real RDP cause even if
                # the browser closes its WebSocket a few milliseconds earlier.
                async def forward(instruction: str) -> None:
                    parts = parse_guac_instruction(instruction)
                    opcode = parts[0] if parts else ""
                    server_flow["last_server_activity"] = time.monotonic()
                    server_flow["last_opcode"] = opcode
                    # Guacamole sync/nop/ack traffic only proves that the local
                    # guacd control socket is alive. It does NOT prove the RDP
                    # socket behind it is still usable. FreeRDP can emit/control
                    # these while spinning forever on a closed XRDP descriptor.
                    if opcode not in {"", "sync", "nop", "ack"}:
                        server_flow["last_meaningful_server_activity"] = time.monotonic()
                        server_flow["interactive_inputs_since_meaningful_server"] = 0
                    if opcode == "sync":
                        server_flow["server_syncs"] = int(server_flow["server_syncs"]) + 1
                        server_flow["last_server_sync"] = str(parts[1] if len(parts) > 1 else "")[:80]
                    if opcode == "clipboard":
                        if not bool(row.get("clipboard_enabled", 1)):
                            raise GuacamoleError("REMOTE_CLIPBOARD_DISABLED: guacd inició un stream no autorizado.")
                        if len(parts) != 3 or not str(parts[1]).isdigit() or not str(parts[2]).lower().startswith("text/"):
                            raise GuacamoleError("Stream remoto de portapapeles Guacamole inválido.")
                        server_streams[str(parts[1])] = {"kind": "clipboard", "bytes": 0}
                    elif opcode == "file":
                        if not bool(row.get("file_transfer_enabled", 1)) or str(row.get("protocol") or "").upper() != "RDP":
                            raise GuacamoleError("REMOTE_FILE_TRANSFER_DISABLED: guacd inició un stream no autorizado.")
                        if len(parts) != 4 or not str(parts[1]).isdigit():
                            raise GuacamoleError("Stream remoto de archivo Guacamole inválido.")
                        filename = str(parts[3] or "")
                        if not filename or len(filename) > 240 or "/" in filename or "\\" in filename or any(ord(ch) < 32 for ch in filename):
                            raise GuacamoleError("Nombre de descarga remota inválido.")
                        server_streams[str(parts[1])] = {"kind": "file", "bytes": 0, "name": filename}
                    elif opcode == "blob" and len(parts) == 3 and str(parts[1]) in server_streams:
                        stream = server_streams[str(parts[1])]
                        try:
                            decoded_bytes = len(base64.b64decode(str(parts[2]).encode("ascii"), validate=True))
                        except Exception as exc:
                            raise GuacamoleError("Blob remoto Guacamole Base64 inválido.") from exc
                        stream["bytes"] = int(stream.get("bytes") or 0) + decoded_bytes
                        maximum = (
                            int(remote_sessions.policy.max_file_transfer_bytes)
                            if stream.get("kind") == "file"
                            else int(remote_sessions.policy.max_clipboard_bytes)
                        )
                        if int(stream["bytes"]) > maximum:
                            raise GuacamoleError(f"Stream remoto Guacamole excede el límite autorizado de {maximum} bytes.")
                    elif opcode == "end" and len(parts) == 2 and str(parts[1]) in server_streams:
                        finished = server_streams.pop(str(parts[1]))
                        if finished.get("kind") == "file":
                            security.audit(
                                identity.username, "remote.session.file_download", "SUCCESS",
                                f"Name={finished.get('name')}; Bytes={int(finished.get('bytes') or 0)}",
                                _ws_remote_ip(websocket), resource=session_id, role=identity.role,
                            )
                    if opcode in {"size", "rect", "cfill", "copy", "png", "jpeg", "img", "video"}:
                        if not server_flow["graphics_seen"]:
                            # A real frame proves that one security/credential
                            # combination worked.  A first connection that must
                            # displace another Windows console user keeps exactly
                            # one short-lived read for the automatic transport
                            # reattach; all other sessions erase it immediately.
                            if int(row.get("handoff_reconnect_attempt") or 0) >= int(row.get("max_handoff_reconnects") or 0):
                                remote_credentials.discard_ephemeral(str(row.get("credential_id") or ""))
                        server_flow["graphics_seen"] = True
                        server_flow["last_visual_activity"] = time.monotonic()
                    remote_error: GuacamoleError | None = None
                    if opcode == "error":
                        message = parts[1] if len(parts) > 1 else "guacd devolvió un error remoto"
                        code = parts[2] if len(parts) > 2 else ""
                        if str(code) == "776" and "aborted" in str(message).casefold():
                            remote_error = GuacamoleError(
                                "GUACD_CLIENT_UNRESPONSIVE: guacd cerró porque el navegador dejó de confirmar cuadros; "
                                f"server_syncs={server_flow['server_syncs']}; client_syncs={server_flow['client_syncs']}; "
                                f"last_server_sync={server_flow['last_server_sync'] or '-'}; "
                                f"last_client_sync={server_flow['last_client_sync'] or '-'}; original={message} ({code})"
                            )
                        else:
                            remote_error = GuacamoleError(f"GUACD_REMOTE_ERROR: {message} ({code})")
                    if opcode == "disconnect":
                        server_flow["remote_disconnect"] = True
                    try:
                        await websocket.send_text(instruction)
                    except Exception:
                        if remote_error is not None:
                            raise remote_error
                        raise
                    if remote_error is not None:
                        raise remote_error

                for instruction in guac_parser.drain_pending():
                    await forward(instruction)
                    if server_flow["remote_disconnect"]:
                        return
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        if not server_flow["graphics_seen"]:
                            raise GuacamoleError(
                                "GUACD_EOF_BEFORE_DISPLAY: guacd cerró el flujo antes de enviar imagen; "
                                f"last_opcode={server_flow['last_opcode'] or '-'}"
                            )
                        server_flow["remote_disconnect"] = True
                        return
                    guac_parser.feed(chunk)
                    for instruction in guac_parser.drain_pending():
                        await forward(instruction)
                        if server_flow["remote_disconnect"]:
                            return

            async def rdp_stall_watchdog() -> None:
                """Release a proven frozen FreeRDP relay without false idle timeouts."""
                if str(row.get("protocol") or "").upper() != "RDP":
                    await asyncio.Future()
                while True:
                    await asyncio.sleep(2.0)
                    if not server_flow["graphics_seen"]:
                        continue
                    now = time.monotonic()
                    server_idle = now - float(server_flow["last_server_activity"])
                    meaningful_idle = now - float(server_flow["last_meaningful_server_activity"])
                    input_age = now - float(server_flow["last_interactive_input"] or 0.0)
                    pending_inputs = int(server_flow["interactive_inputs_since_meaningful_server"])
                    if pending_inputs >= 3 and meaningful_idle >= 15.0 and input_age <= 10.0:
                        raise GuacamoleError(
                            "GUACD_RDP_STALLED: guacd dejó de responder después de mostrar imagen; "
                            f"server_idle={server_idle:.1f}s; meaningful_idle={meaningful_idle:.1f}s; "
                            f"pending_inputs={pending_inputs}; "
                            f"last_opcode={server_flow['last_opcode'] or '-'}"
                        )

            browser_task = asyncio.create_task(browser_to_guacd(), name=f"remote-browser-{session_id}")
            server_task = asyncio.create_task(guacd_to_browser(), name=f"remote-guacd-{session_id}")
            watchdog_task = asyncio.create_task(rdp_stall_watchdog(), name=f"remote-watchdog-{session_id}")
            tasks = [browser_task, server_task, watchdog_task]
            done, pending = await asyncio.wait(
                tasks,
                timeout=float(remote_sessions.policy.max_session_seconds),
                return_when=asyncio.FIRST_COMPLETED,
            )

            # If the browser side closes first before the first frame, guacd may
            # be only milliseconds away from reporting the actual RDP failure
            # (most importantly bad credentials). Give the server flow a short
            # bounded grace period instead of cancelling it immediately.
            if browser_task in done and server_task in pending and not server_flow.get("graphics_seen"):
                server_done, _ = await asyncio.wait({server_task}, timeout=1.25)
                if server_done:
                    done.update(server_done)
                    pending.discard(server_task)

            # Always cancel pending tasks and retrieve every completed
            # exception before propagating the server result.  Otherwise a
            # simultaneous browser disconnect leaves an unobserved Task and
            # asyncio logs "Task exception was never retrieved".
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            server_error = None
            client_error = None
            for task in done:
                if task.cancelled():
                    continue
                error = task.exception()
                if task is server_task:
                    server_error = error
                elif task is watchdog_task and error is not None:
                    server_error = error
                elif error is not None and not isinstance(error, WebSocketDisconnect):
                    client_error = error

            # Server-side errors have diagnostic priority over a simultaneous
            # browser disconnect. This avoids false GuacamoleError/<vacío>.
            if server_error is not None:
                raise server_error
            if client_error is not None:
                raise client_error

            if not done:
                close_reason = "MAX_SESSION_AGE"
            elif server_flow.get("client_disconnect_requested"):
                close_reason = "CLIENT_REQUESTED_DISCONNECT"
            elif server_flow.get("remote_disconnect") and not server_flow.get("graphics_seen"):
                close_reason = "GUACD_REMOTE_DISCONNECT_BEFORE_DISPLAY"
            elif server_flow.get("remote_disconnect"):
                close_reason = "GUACD_REMOTE_DISCONNECT"

        except WebSocketDisconnect:
            close_reason = "CLIENT_DISCONNECTED"
        except Exception as exc:
            close_reason = _remote_runtime_close_reason(exc)
            security.audit(
                identity.username,
                "remote.session.runtime",
                "FAILED",
                str(exc),
                _ws_remote_ip(websocket),
                resource=session_id,
                role=identity.role,
            )
            try:
                await websocket.close(code=4511, reason="Sesión remota finalizada por el servidor")
            except Exception:
                pass
        finally:
            persisted = remote_sessions.get_for_user(session_id, identity.user_id) or {}
            persisted_reason = str(persisted.get("end_reason") or "").upper()
            handoff_remaining = (
                int(row.get("handoff_reconnect_attempt") or 0)
                < int(row.get("max_handoff_reconnects") or 0)
            )
            preserve_for_handoff = bool(
                persisted_reason == "RDP_SESSION_HANDOFF_RECONNECT"
                or (
                    handoff_remaining
                    and close_reason in {
                        "GUACD_REMOTE_DISCONNECT", "GUACD_REMOTE_DISCONNECT_BEFORE_DISPLAY",
                        "GUACD_REMOTE_ERROR", "GUACD_EOF_BEFORE_DISPLAY",
                    }
                )
            )
            if not preserve_for_handoff and (
                server_flow.get("graphics_seen") or close_reason not in REMOTE_AUTOMATIC_SECURITY_END_REASONS
            ):
                remote_credentials.discard_ephemeral(str(row.get("credential_id") or ""))
            if writer is not None:
                try:
                    writer.write(b"10.disconnect;")
                    await asyncio.wait_for(writer.drain(), timeout=1.5)
                except Exception:
                    pass
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except Exception:
                    pass
            remote_sessions.close(session_id, reason=close_reason)
            security.audit(
                identity.username,
                "remote.session.disconnected",
                "SUCCESS",
                f"Reason={close_reason}",
                _ws_remote_ip(websocket),
                resource=session_id,
                role=identity.role,
            )

    @app.get("/transfers", response_class=HTMLResponse)
    def transfers_page(request: Request):
        require(request, "transfers.view")
        available, reason = operations.execution_available()
        return template(request, "transfers.html", {
            "title": "Transferencias", "agents": gateway.agents(), "groups": security.list_groups(),
            "execution_available": available, "execution_reason": reason, "result": None,
            "recent_jobs": operations.transfer_jobs(limit=5),
        })

    @app.post("/transfers", response_class=HTMLResponse)
    async def transfers_submit(request: Request, file: UploadFile = File(...), destination: str = Form(...)):
        identity = require(request, "transfers.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        agent_ids = [str(x) for x in form.getlist("agent_id")]
        temp = operations.transfer_dir / f".upload-{secrets.token_hex(12)}.part"
        size = 0
        limit = int(config.get("max_transfer_upload_bytes", 1024 * 1024 * 1024))
        try:
            with temp.open("wb") as fh:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"El archivo excede el máximo de {limit} bytes.")
                    fh.write(chunk)
            os.chmod(temp, 0o640)
            job = operations.enqueue_transfer(
                filename=file.filename or "archivo", source_path=temp, destination_dir=destination,
                agent_ids=agent_ids, actor=identity.username,
            )
            security.audit(
                identity.username, "transfers.queue", "SUCCESS",
                f"File={job['File']} Targets={job['TargetCount']} PreparationJob={job['JobId']}",
                request_security.remote_ip(request), resource=str(job["JobId"]), role=identity.role,
            )
        except Exception as exc:
            temp.unlink(missing_ok=True)
            security.audit(identity.username, "transfers.queue", "FAILED", str(exc), request_security.remote_ip(request), resource=str(file.filename or ""), role=identity.role)
            raise HTTPException(409, str(exc))
        return RedirectResponse(f"/jobs/{job['JobId']}", status_code=303)


    @app.get("/system-updates", response_class=HTMLResponse)
    def system_updates_page(request: Request):
        require(request, "system_updates.manage")
        return template(request, "system_updates.html", {
            "title": "Actualización del sistema",
            "current_version": PRODUCT_VERSION,
            "statuses": product_updates.statuses(),
            "trusted_update_keys": product_updates.trusted_keys(),
            "update_trust_dir": str(product_updates.trust_dir),
            "queued": str(request.query_params.get("queued") or ""),
        })

    @app.post("/system-updates/upload")
    async def system_updates_upload(request: Request, file: UploadFile = File(...), current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "system_updates.manage")
        await validate_csrf(request, identity)
        await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
        filename = str(file.filename or "")
        if not filename.lower().endswith(".zip"):
            raise HTTPException(400, "La actualización de producto debe ser un paquete .zip con manifest y hashes SHA-256 válidos.")
        temp = product_updates.new_quarantine_path(filename)
        size = 0
        try:
            with temp.open("wb") as fh:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > product_updates.max_bytes:
                        raise ValueError(f"El paquete excede el máximo permitido de {product_updates.max_bytes} bytes.")
                    fh.write(chunk)
            os.chmod(temp, 0o640)
            summary = await asyncio.to_thread(product_updates.inspect, temp)
            from_versions = {str(v) for v in summary.get("from_versions", [])}
            to_version = str(summary.get("to_version") or "")
            try:
                transition = validate_update_transition(PRODUCT_VERSION, to_version, sorted(from_versions))
            except UpdateError as exc:
                raise ValueError(str(exc)) from exc
            if transition == "ALREADY_APPLIED":
                raise ValueError(
                    f"El paquete ya corresponde a la versión instalada {PRODUCT_VERSION}; no se encolará nuevamente."
                )
            scan_status, scan_detail = await asyncio.to_thread(operations.scan_script, temp)
            if str(scan_status).upper() != "CLEAN":
                raise ValueError(f"El paquete no superó el análisis antimalware aislado de GIDEON: {scan_status} - {scan_detail}")
            queued = await asyncio.to_thread(product_updates.enqueue, temp, summary)
            security.audit(identity.username, "system_updates.upload", "SUCCESS",
                           f"Queue={queued.get('queue_id')} From={sorted(from_versions)} To={to_version} Bytes={size}",
                           request_security.remote_ip(request), resource=filename, role=identity.role)
            return RedirectResponse(f"/system-updates?queued={queued.get('queue_id')}", status_code=303)
        except Exception as exc:
            temp.unlink(missing_ok=True)
            security.audit(identity.username, "system_updates.upload", "FAILED", str(exc),
                           request_security.remote_ip(request), resource=filename, role=identity.role)
            raise HTTPException(409, str(exc))

    @app.get("/updates", response_class=HTMLResponse)
    def updates_page(request: Request):
        require(request, "agents.view")
        agents = gateway.agents(); releases = gateway.releases()
        approved = _approved_agent_releases(releases)
        for a in agents:
            rel=approved.get((str(a.get("platform") or "").lower(),str(a.get("architecture") or "").lower()))
            _decorate_agent_update(a, rel)
        requested = str(request.query_params.get("requested") or "").strip()
        return template(request, "updates.html", {"title":"Actualizaciones", "agents":agents, "approved":approved, "requested":requested})

    @app.post("/agents/{agent_id}/update")
    async def agent_force_update(request: Request, agent_id: str):
        identity = require(request, "agents.operate")
        await validate_csrf(request, identity)
        form = await request.form()
        target_version = str(form.get("target_version") or "").strip()
        try:
            result = await asyncio.to_thread(
                gateway.request_agent_update, agent_id, actor=identity.username, target_version=target_version,
            )
            update_request = result.get("UpdateRequest") if isinstance(result.get("UpdateRequest"), dict) else {}
            request_id = str(update_request.get("request_id") or "")
            security.audit(identity.username, "agents.update.force", "SUCCESS", f"RequestId={request_id}; Target={target_version or '-'}", request_security.remote_ip(request), resource=agent_id, role=identity.role)
        except Exception as exc:
            security.audit(identity.username, "agents.update.force", "FAILED", str(exc), request_security.remote_ip(request), resource=agent_id, role=identity.role)
            raise HTTPException(409, redact_error(exc))
        return RedirectResponse(f"/updates?requested={agent_id}", status_code=303)

    @app.post("/agents/{agent_id}/vlc-offline/install")
    async def agent_offline_vlc_install(request: Request, agent_id: str):
        """Issue one explicit, short-lived signed installation approval.

        VLC artifacts are already embedded and verified in the Agent's own
        release. This endpoint never accepts a package path, download URL, or
        command from the browser; it only signs a reviewed catalog hash the
        Agent reported in an authenticated heartbeat.
        """
        identity = require(request, "agents.operate")
        await validate_csrf(request, identity)
        form = await request.form()
        if str(form.get("accept_vlc_gpl") or "") != "on":
            raise HTTPException(400, "Confirme la licencia GPL de VLC antes de continuar.")
        row = next((item for item in gateway.agents() if str(item.get("agent_id") or "") == agent_id), None)
        if row is None:
            raise HTTPException(404, "Agent no encontrado")
        capabilities = row.get("Capabilities") if isinstance(row.get("Capabilities"), dict) else {}
        player = capabilities.get("Player") if isinstance(capabilities.get("Player"), dict) else {}
        offline = player.get("OfflineVlc") if isinstance(player.get("OfflineVlc"), dict) else {}
        if str(offline.get("State") or "") != "READY_FOR_EXPLICIT_INSTALL":
            raise HTTPException(409, "Este Agent no tiene un catálogo VLC offline válido y listo para instalar.")
        catalog_sha256 = str(offline.get("CatalogSha256") or "").strip().lower()
        try:
            envelope = await asyncio.to_thread(
                build_install_authorization,
                agent_id=agent_id,
                catalog_sha256=catalog_sha256,
                security_assets=security_assets,
                gpl_acknowledged=True,
            )
            result = await asyncio.to_thread(
                gateway.request_agent_offline_vlc_install,
                agent_id,
                authorization=envelope,
                actor=identity.username,
            )
            request_info = result.get("OfflineVlcInstallRequest") if isinstance(result.get("OfflineVlcInstallRequest"), dict) else {}
            audit_info = authorization_audit_metadata(envelope)
            security.audit(
                identity.username, "agents.vlc_offline.install.request", "SUCCESS",
                f"RequestId={audit_info.get('RequestId') or '-'}; Catalog={str(audit_info.get('CatalogSha256') or '-')[:16]}; Status={request_info.get('Status') or 'REQUESTED'}",
                request_security.remote_ip(request), resource=agent_id, role=identity.role,
            )
        except OfflineVlcAuthorizationError as exc:
            security.audit(identity.username, "agents.vlc_offline.install.request", "FAILED", redact_error(exc), request_security.remote_ip(request), resource=agent_id, role=identity.role)
            raise HTTPException(409, redact_error(exc))
        except Exception as exc:
            security.audit(identity.username, "agents.vlc_offline.install.request", "FAILED", redact_error(exc), request_security.remote_ip(request), resource=agent_id, role=identity.role)
            raise HTTPException(409, redact_error(exc))
        return RedirectResponse(f"/agents/{quote(agent_id, safe='')}?vlc_requested=1", status_code=303)

    def sites_context(*, message: str = "", error: str = "", site_form: dict[str, str] | None = None) -> dict[str, Any]:
        gateway_error = ""
        try:
            agents = gateway.agents()
        except Exception as exc:
            agents = []
            gateway_error = redact_error(exc)
        grouped: dict[str, dict[str, Any]] = {}
        for catalog_site in agent_installers.sites():
            code = str(catalog_site.get("code") or "").strip().upper()
            if not code:
                continue
            grouped[code.casefold()] = {
                "site_code": code,
                "site_name": str(catalog_site.get("name") or code),
                "description": str(catalog_site.get("description") or ""),
                "managed": bool(catalog_site.get("managed")),
                "source": str(catalog_site.get("source") or "agent"),
                "agents": [],
                "platforms": set(),
            }
        for agent in agents:
            code = str(agent.get("site_code") or "SIN_SEDE").strip().upper()
            key = code.casefold()
            row = grouped.setdefault(key, {
                "site_code": code,
                "site_name": str(agent.get("site_name") or code),
                "description": "",
                "managed": False,
                "source": "agent",
                "agents": [],
                "platforms": set(),
            })
            row["agents"].append(agent)
            row["platforms"].add(str(agent.get("platform") or "-"))
        sites = []
        for row in grouped.values():
            row["platforms"] = ", ".join(sorted(row["platforms"])) if row["platforms"] else "—"
            sites.append(row)
        sites.sort(key=lambda item: str(item["site_code"]).casefold())
        return {
            "title": "Sedes", "sites": sites, "message": message, "error": error,
            "gateway_error": gateway_error, "site_form": site_form or {},
        }

    @app.get("/sites", response_class=HTMLResponse)
    def sites_page(request: Request):
        require(request, "groups.view")
        created = str(request.query_params.get("created") or "").strip()
        message = f"La sede {created} fue creada y ya está disponible en el Generador de Agents." if created else ""
        return template(request, "sites.html", sites_context(message=message))

    @app.post("/sites/create", response_class=HTMLResponse)
    async def sites_create(request: Request):
        identity = require(request, "groups.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        values = {
            "site_code": str(form.get("site_code") or ""),
            "site_name": str(form.get("site_name") or ""),
            "description": str(form.get("description") or ""),
        }
        remote_ip = request_security.remote_ip(request)
        try:
            code = security.create_site(
                values["site_code"], values["site_name"], values["description"],
                actor=identity.username, remote_ip=remote_ip,
            )
        except ValueError as exc:
            security.audit(identity.username, "sites.create", "FAILED", str(exc), remote_ip, role=identity.role)
            return template(request, "sites.html", sites_context(error=str(exc), site_form=values), 409)
        return RedirectResponse(f"/sites?created={code}", status_code=303)

    # ------------------------------------------------------------------
    # GIDEON Media: screen inventory and campaign planning.  This phase is
    # intentionally data-only: no player, transfer, or Agent action occurs
    # from these routes.  The existing Gateway heartbeat is read only.
    # ------------------------------------------------------------------
    def media_catalog_page_args(request: Request, *, default_size: int = 25) -> tuple[int, int, str]:
        """Normalize bounded catalog paging once for pages and picker APIs."""
        try:
            page = int(str(request.query_params.get("page") or "1"))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(str(request.query_params.get("page_size") or default_size))
        except (TypeError, ValueError):
            page_size = default_size
        page = max(1, min(page, 10_000))
        page_size = max(10, min(page_size, 100))
        query = str(request.query_params.get("q") or request.query_params.get("query") or "").strip()
        return page, page_size, query

    def media_context(
        request: Request, *, include_campaigns: bool = True, include_archived: bool = False,
        include_media_assets: bool = False, include_screens: bool = True,
    ) -> dict[str, Any]:
        gateway_error = ""
        try:
            agents = [dict(item) for item in gateway.agents() if isinstance(item, dict)]
        except Exception as exc:
            agents = []
            gateway_error = redact_error(exc)
        platform_by_agent = {
            str(item.get("agent_id") or ""): str(item.get("platform") or "").strip().lower()
            for item in agents if str(item.get("agent_id") or "").strip()
        }
        agent_options: list[dict[str, Any]] = []
        for item in agents:
            agent_id = str(item.get("agent_id") or "").strip()
            if not agent_id:
                continue
            site_code = str(item.get("site_code") or "SIN_SEDE").strip().upper()
            site_name = str(item.get("site_name") or site_code).strip()
            device = str(item.get("agent_name") or item.get("hostname") or "Equipo").strip()
            outputs = campaigns.normalized_display_outputs(item)
            capabilities = item.get("Capabilities") or item.get("capabilities") or {}
            display = capabilities.get("Display") or capabilities.get("Displays") or {} if isinstance(capabilities, dict) else {}
            session = display.get("Session") if isinstance(display, dict) and isinstance(display.get("Session"), dict) else {}
            session_type = str(session.get("Type") or "").strip()
            session_available = bool(session.get("Available"))
            agent_options.append({
                "agent_id": agent_id,
                "label": " · ".join(part for part in (site_code, site_name, device) if part),
                "device_name": device,
                "site_code": site_code,
                "platform": platform_by_agent.get(agent_id, ""),
                "outputs": outputs,
                "registered_outputs": [],
                "has_display_report": bool(outputs),
                "session_summary": (
                    f"Sesión {session_type} detectada" if session_available and session_type
                    else "Sesión gráfica no confirmada; se conserva la última salida registrada"
                ),
            })
        agent_options.sort(key=lambda item: item["label"].casefold())

        site_rows = security.list_sites()
        sites: dict[str, dict[str, str]] = {
            str(item.get("site_code") or "").upper(): {
                "site_code": str(item.get("site_code") or "").upper(),
                "site_name": str(item.get("site_name") or item.get("site_code") or ""),
            }
            for item in site_rows if str(item.get("site_code") or "").strip()
        }
        for item in agent_options:
            code = str(item["site_code"] or "").upper()
            if code and code not in sites:
                sites[code] = {"site_code": code, "site_name": code}
        site_options = sorted(sites.values(), key=lambda item: (item["site_code"].casefold(), item["site_name"].casefold()))

        groups = security.list_groups()
        selected_group = str(request.query_params.get("group") or "").strip()
        group_members: list[str] | None = None
        if selected_group:
            found = next((item for item in groups if str(item.get("id")) == selected_group), None)
            group_members = [str(value) for value in (found or {}).get("agent_ids", [])]
        selected_site = str(request.query_params.get("site") or "").strip().upper()
        selected_os = str(request.query_params.get("os") or "").strip().lower()
        selected_state = str(request.query_params.get("state") or "").strip().upper()
        selected_screen = str(request.query_params.get("screen") or "").strip()
        screen_state_filter = selected_state if selected_state in {"READY", "OFFLINE", "NEEDS_REVIEW", "DISABLED", "ARCHIVED"} else ""
        campaign_state_filter = selected_state if selected_state in {"DRAFT", "PENDING_APPROVAL", "SCHEDULED", "ACTIVE", "PAUSED", "EXPIRED", "ARCHIVED"} else ""
        screens: list[dict[str, Any]] = []
        # A wizard no longer needs the whole Screen inventory just to render a
        # blank campaign form.  Keep the historic inventory projection for its
        # dedicated pages, while callers that use the lazy picker explicitly
        # opt out and fetch only selected Screen IDs below.
        if include_screens:
            try:
                screens = campaigns.list_screens(
                    site_code=selected_site, group_agent_ids=group_members, os_name=selected_os,
                    state=screen_state_filter, agent_platforms=platform_by_agent, include_archived=include_archived,
                )
            except CampaignStoreError as exc:
                gateway_error = (gateway_error + " · " if gateway_error else "") + str(exc)
            # A service-mode Agent may temporarily lose access to Wayland or
            # the Windows interactive desktop even though a Screen was already
            # registered.  Feed the last registered output back into the
            # registration form so the operator can see and edit the session
            # binding instead of receiving an empty selector.
            registered_outputs: dict[str, list[dict[str, Any]]] = {}
            for screen in screens:
                agent_id = str(screen.get("agent_id") or "").strip()
                output_key = str(screen.get("output_key") or "").strip()
                if not agent_id or not output_key or bool(screen.get("archived")):
                    continue
                registered_outputs.setdefault(agent_id, []).append({
                    "output_key": output_key,
                    "label": str(screen.get("output_label") or screen.get("commercial_name") or output_key),
                    "connected": bool(screen.get("connected")),
                    "enabled": True,
                    "physical": str(screen.get("target_kind") or "PHYSICAL_CONNECTOR") == "PHYSICAL_CONNECTOR",
                    "virtual": str(screen.get("target_kind") or "") == "LOCAL_WAYLAND_SESSION",
                    "resolution": str(screen.get("resolution") or ""),
                    "orientation": str(screen.get("orientation") or "LANDSCAPE"),
                    "primary": False,
                    "output_identity": str(screen.get("output_identity") or ""),
                    "target_kind": str(screen.get("target_kind") or "PHYSICAL_CONNECTOR"),
                    "target_kind_label": str(screen.get("target_kind_label") or "HDMI físico"),
                    "last_known": True,
                })
            for option in agent_options:
                option["registered_outputs"] = sorted({
                    str(item.get("output_key") or "").strip()
                    for item in (registered_outputs.get(str(option["agent_id"])) or [])
                    if str(item.get("output_key") or "").strip()
                })
                if option["outputs"]:
                    continue
                fallback = registered_outputs.get(str(option["agent_id"])) or []
                if fallback:
                    option["outputs"] = fallback
                    option["has_display_report"] = False
                    option["session_summary"] = "Sin telemetría actual; mostrando la última salida registrada"
        campaign_rows: list[dict[str, Any]] = []
        if include_campaigns:
            try:
                campaign_rows = campaigns.list_campaigns(
                    state=campaign_state_filter, site_code=selected_site, group_agent_ids=group_members,
                    screen_id=selected_screen, os_name=selected_os, agent_platforms=platform_by_agent,
                    include_archived=include_archived,
                )
            except CampaignStoreError as exc:
                gateway_error = (gateway_error + " · " if gateway_error else "") + str(exc)
        media_assets: list[dict[str, Any]] = []
        # The old shared context loaded 500 assets for every Media route, even
        # when a page never rendered a video picker.  Library and wizard now
        # use their own bounded/pageable source below; retain this opt-in only
        # for a narrow backwards-compatible caller.
        if include_media_assets:
            try:
                media_assets = campaigns.list_media_assets(include_archived=include_archived, limit=50)
            except CampaignStoreError as exc:
                gateway_error = (gateway_error + " · " if gateway_error else "") + str(exc)
        return {
            "agents": agent_options,
            "sites": site_options,
            "groups": groups,
            # Internal filter projection only; templates still receive human
            # group labels and never Agent identifiers by default.
            "group_agent_ids": group_members,
            "screens": screens,
            "campaigns": campaign_rows,
            "media_assets": media_assets,
            "assets_by_id": {str(item.get("asset_id") or ""): item for item in media_assets},
            "gateway_error": gateway_error,
            "filters": {
                "site": selected_site, "group": selected_group, "os": selected_os,
                "state": selected_state, "screen": selected_screen,
            },
            "campaign_states": ["DRAFT", "PENDING_APPROVAL", "SCHEDULED", "ACTIVE", "PAUSED", "EXPIRED", "ARCHIVED"],
            "screen_states": ["READY", "OFFLINE", "NEEDS_REVIEW", "DISABLED", "ARCHIVED"],
        }

    def media_wizard_context(
        request: Request, *, campaign: dict[str, Any] | None = None, form: Any | None = None,
    ) -> dict[str, Any]:
        """Build a campaign editor context without hydrating every Screen.

        Existing campaign assignments (or a rejected form submission) remain
        visible and editable, but the rest of the inventory is discovered via
        the paginated Screen catalog API only when Marketing searches for it.
        """
        context = media_context(request, include_campaigns=False, include_screens=False)
        selected_ids: list[str] = []
        if form is not None:
            try:
                selected_ids = [str(value).strip() for value in form.getlist("screen_id") if str(value).strip()]
            except (AttributeError, TypeError):
                selected_ids = []
        if not selected_ids and campaign:
            selected_ids = [
                str(item.get("screen_id") or "").strip()
                for item in (campaign.get("assignments") or []) if str(item.get("screen_id") or "").strip()
            ]
        try:
            selected_screens = campaigns.screens_by_ids(selected_ids, include_archived=False)
        except CampaignStoreError as exc:
            selected_screens = []
            context["gateway_error"] = (
                (context.get("gateway_error") + " · ") if context.get("gateway_error") else ""
            ) + str(exc)
        # ``screens`` remains a selected-only compatibility projection for the
        # form validator. Templates use ``selected_screens`` to make the
        # distinction explicit.
        context["selected_screens"] = selected_screens
        context["screens"] = selected_screens
        return context

    def media_assignments_from_form(
        form: Any, *, screens: list[dict[str, Any]], default_playlist: str,
        assets_by_id: dict[str, dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        available = {str(item.get("screen_id") or ""): item for item in screens if not item.get("archived")}
        selected = [str(value).strip() for value in form.getlist("screen_id") if str(value).strip()]
        if not selected:
            raise CampaignStoreError("Seleccione por lo menos una pantalla.")
        missing_screen_ids = [screen_id for screen_id in selected if screen_id not in available]
        if missing_screen_ids:
            # The picker is intentionally lazy. Resolve all submitted Screen
            # IDs in one bounded read rather than hydrating the full inventory
            # on every create/revise request.
            available.update({
                str(item.get("screen_id") or ""): item
                for item in campaigns.screens_by_ids(missing_screen_ids, include_archived=False)
            })
        if any(screen_id not in available for screen_id in selected):
            raise CampaignStoreError("Una pantalla seleccionada ya no está disponible.")
        weekdays = [str(value) for value in form.getlist("weekday") if str(value).strip()]
        if not weekdays:
            weekdays = [value.strip() for value in str(form.get("schedule_weekdays") or "").split(",") if value.strip()]
        # The visual calendar emits both canonical inputs (for a no-JavaScript
        # fallback) and an intent projection.  CampaignStore validates and
        # persists both, keeping revision history readable to Marketing.
        schedule = {
            "start_date": str(form.get("start_date") or ""),
            "end_date": str(form.get("end_date") or ""),
            "weekdays": weekdays,
            "start_time": str(form.get("start_time") or ""),
            "end_time": str(form.get("end_time") or ""),
            "blackout_dates": str(form.get("blackout_dates") or ""),
            # Marketing operates in Peru.  Keep the canonical campaign clock
            # independent from the VM/browser timezone (the form also renders
            # this as a readonly value so Chile/UTC hosts cannot shift it).
            "timezone": "America/Lima",
            "preset": str(form.get("schedule_preset") or "CUSTOM"),
            "start_at": str(form.get("schedule_start_at") or ""),
            "end_at": str(form.get("schedule_end_at") or ""),
            "date_range": str(form.get("schedule_date_range") or ""),
        }
        assignments: list[dict[str, Any]] = []
        asset_lookup = assets_by_id or {}
        submitted_asset_ids = [str(form.get(f"asset_id_{screen_id}") or "").strip() for screen_id in selected]
        missing_asset_ids = [asset_id for asset_id in submitted_asset_ids if asset_id and asset_id not in asset_lookup]
        if missing_asset_ids:
            # Resolve the lazy picker selections as one bounded storage read;
            # no page request or screen count can produce N asset queries.
            asset_lookup = {
                **asset_lookup,
                **campaigns.media_assets_by_ids(missing_asset_ids, include_archived=False),
            }
        for screen_id in selected:
            screen = available[screen_id]
            asset_id = str(form.get(f"asset_id_{screen_id}") or "").strip()
            asset = asset_lookup.get(asset_id) or {}
            if asset_id and not asset:
                raise CampaignStoreError("Un video seleccionado ya no está disponible. Actualiza la lista antes de publicar.")
            assignments.append({
                "screen_id": screen_id,
                "playlist_name": str(form.get(f"playlist_name_{screen_id}") or default_playlist or "Contenido de campaña"),
                "content_title": str(form.get(f"content_title_{screen_id}") or asset.get("display_name") or "Video de campaña"),
                "content_note": str(form.get(f"content_note_{screen_id}") or ""),
                "asset_id": asset_id,
                "emergency": str(form.get(f"emergency_{screen_id}") or "").strip().lower() in {"1", "true", "on", "yes"},
                "priority": str(form.get(f"priority_{screen_id}") or form.get("priority") or ""),
                "schedule": dict(schedule),
            })
        return assignments

    def media_form_snapshot(form: Any) -> dict[str, Any]:
        """Preserve multi-select wizard values when validation returns a form.

        Starlette's form mapping returns only one value through ``dict(form)``.
        Keeping all selected screens and weekdays prevents an understandable
        validation error from silently deselecting the rest of a Marketing
        campaign draft.
        """
        values = dict(form)
        for key in ("screen_id", "weekday"):
            try:
                values[key] = [str(value) for value in form.getlist(key)]
            except (AttributeError, TypeError):
                values[key] = []
        return values

    def _gateway_agent_online(agent: dict[str, Any]) -> bool:
        """Interpret only explicit live state; unknown is never advertised online."""
        for key in ("online", "is_online", "connected"):
            if isinstance(agent.get(key), bool):
                return bool(agent[key])
        state = str(agent.get("status") or agent.get("state") or agent.get("connection_state") or "").upper()
        return state in {"ONLINE", "CONNECTED", "ACTIVE"}

    # All state-changing delivery work is serialized per WebAdmin process. It
    # protects the outbox from two simultaneous page/API background tasks
    # enqueuing the same Agent+hash before its durable delivery row is marked.
    # The Gateway remains the authority for the already queued signed job.
    media_distribution_lock = threading.Lock()
    app.state.media_distribution_lock = media_distribution_lock

    # Screen edits can arrive in a burst (for example when an installer or an
    # operator corrects several outputs).  Coalesce their manifest refreshes
    # into one bounded worker instead of creating an unbounded thread per
    # request.  The signed manifest remains the only Agent-facing result.
    media_manifest_refresh_lock = threading.Lock()
    media_manifest_refresh_pending: set[str] = set()
    media_manifest_refresh_worker: threading.Thread | None = None
    app.state.media_manifest_refresh_lock = media_manifest_refresh_lock

    def _media_gateway_state(job: dict[str, Any]) -> tuple[str, str]:
        """Treat a nested Agent error as an error even under RESULT_READY."""
        status = str(job.get("status") or job.get("Status") or "").upper()
        nested = job.get("AgentStatus") if isinstance(job.get("AgentStatus"), dict) else {}
        nested_state = str(nested.get("State") or nested.get("state") or nested.get("Status") or "").upper()
        error = str(job.get("error") or job.get("Error") or nested.get("Error") or nested.get("error") or "")
        failed = {"FAILED", "CANCELLED", "CANCELED", "RESULT_READY_WITH_ERRORS", "ERROR", "ABORTED", "EXPIRED", "REJECTED"}
        if status in failed or status.startswith("FAILED_") or nested_state in failed or nested_state.startswith("FAILED_"):
            return "FAILED", error
        if status == "RESULT_READY":
            if nested_state and nested_state not in {"RESULT_READY", "COMPLETED", "SUCCESS", "OK"}:
                return "FAILED", error or nested_state
            if nested.get("Ok") is False or nested.get("ok") is False:
                return "FAILED", error or "El Agent no confirmó la integridad del video."
            return "RESULT_READY", ""
        if status in {"RUNNING", "CLAIMED", "STARTING", "DOWNLOADING", "VERIFYING", "EXECUTING"}:
            return "RUNNING", ""
        return "QUEUED", error

    def reconcile_media_distribution(
        campaign_id: str, *, gateway_jobs: list[dict[str, Any]] | None = None,
        gateway_agents: list[dict[str, Any]] | None = None,
    ) -> None:
        """Project supplied Gateway snapshots without network work in a request.

        A page view only reads local delivery/preparation records.  The bounded
        scheduler below obtains the cached Gateway snapshots in the background
        and passes them here, preventing N synchronous ``gateway.job`` calls
        from making a Marketing page depend on every remote Agent.
        """
        try:
            agents = {
                str(row.get("agent_id") or ""): row for row in (gateway_agents or [])
                if isinstance(row, dict)
            }
            jobs_by_key = {
                (str(row.get("job_id") or row.get("JobId") or ""), str(row.get("agent_id") or row.get("AgentId") or "")): row
                for row in (gateway_jobs or []) if isinstance(row, dict) and str(row.get("job_id") or row.get("JobId") or "")
            }
            rows = campaigns.list_campaign_distribution(campaign_id)
            seen: set[str] = set()
            for row in rows:
                preparation = str(row.get("preparation_job_id") or "")
                gateway_job = str(row.get("gateway_job_id") or "")
                with campaigns.connect() as con:
                    found = con.execute(
                        "SELECT delivery_id,agent_id FROM media_distribution_targets WHERE target_id=?", (str(row.get("target_id") or ""),)
                    ).fetchone()
                if found is None:
                    continue
                delivery_id = str(found["delivery_id"] or "")
                agent_id = str(found["agent_id"] or "")
                if not delivery_id or delivery_id in seen:
                    continue
                seen.add(delivery_id)
                online = _gateway_agent_online(agents.get(agent_id, {})) if gateway_agents is not None else True
                if preparation and not gateway_job:
                    prep = operations.transfer_job(preparation) or {}
                    status = str(prep.get("Status") or "").upper()
                    if status == "COMPLETED":
                        results = [item for item in (prep.get("Results") or []) if isinstance(item, dict)]
                        candidate = str(next((item.get("JobId") for item in results if str(item.get("AgentId") or "") == agent_id), "") or "")
                        if candidate:
                            campaigns.set_media_delivery_gateway_job(delivery_id, candidate)
                            gateway_job = candidate
                        else:
                            campaigns.reconcile_media_delivery(delivery_id, gateway_state="FAILED", agent_online=online,
                                                               error="No se pudo crear el Job de distribución.")
                            continue
                    elif status == "FAILED":
                        campaigns.reconcile_media_delivery(delivery_id, gateway_state="FAILED", agent_online=online,
                                                           error="No se pudo preparar el envío seguro del video.")
                        continue
                    else:
                        campaigns.reconcile_media_delivery(delivery_id, gateway_state="RUNNING", agent_online=online)
                        continue
                # No supplied snapshot means no remote assertion.  Preserve
                # the durable state rather than inventing OFFLINE/QUEUED from a
                # transient Gateway read failure.
                if not gateway_job or gateway_jobs is None:
                    continue
                job = jobs_by_key.get((gateway_job, agent_id)) or jobs_by_key.get((gateway_job, ""))
                if job is None:
                    # A bounded cached list may not include an old job.  The
                    # next scheduler snapshot will eventually include its
                    # terminal result; do not duplicate delivery meanwhile.
                    continue
                state, error = _media_gateway_state(job)
                campaigns.reconcile_media_delivery(delivery_id, gateway_state=state, agent_online=online, error=error)
        except Exception as exc:
            LOG.warning("GIDEON Media distribution reconciliation skipped: %s", redact_error(exc))

    def publish_media_manifest_for_agent(
        agent_id: str, *, actor: str, campaign_id: str = "", reason: str = "",
    ) -> bool:
        """Publish one resolved signed state without holding an HTTP request.

        An explicit screen edit can remove the last eligible assignment for an
        Agent. In that case the empty, signed manifest is significant: it
        stops only the affected Player instead of leaving its last offline
        campaign running. ``None`` still means transfer verification is not
        ready and preserves the previous valid manifest.
        """
        clean_agent = str(agent_id or "").strip()
        if not clean_agent:
            return False
        try:
            inputs = campaigns.agent_player_manifest_inputs(clean_agent)
            if inputs is None:
                return False
            payload = build_player_manifest_payload(clean_agent, inputs.get("assignments") or [])
            envelope = sign_player_manifest(
                payload, security_assets, manifest_version=int(inputs.get("manifest_version") or 0),
            )
            published = gateway.publish_agent_media_manifest(clean_agent, envelope)
            if bool(published.get("created")):
                detail = f"Campaign={campaign_id or '-'}; Agent={clean_agent}; Version={published.get('manifest_version')}"
                if reason:
                    detail += f"; Reason={reason}"
                security.audit(
                    str(actor or "system"), "media.player_manifest.publish", "SUCCESS", detail, "", resource=clean_agent,
                )
            return True
        except (CampaignStoreError, MediaManifestError, ValueError) as exc:
            LOG.warning("GIDEON Player manifest not published for campaign=%s agent=%s: %s", campaign_id, clean_agent, redact_error(exc))
        except Exception as exc:
            LOG.warning("GIDEON Player manifest gateway publish deferred for campaign=%s agent=%s: %s", campaign_id, clean_agent, redact_error(exc))
        return False

    def publish_media_manifests_for_agents(
        agent_ids: list[str] | set[str] | tuple[str, ...], *, actor: str, campaign_id: str = "", reason: str = "",
    ) -> None:
        for agent_id in sorted({str(value).strip() for value in agent_ids if str(value).strip()}):
            publish_media_manifest_for_agent(agent_id, actor=actor, campaign_id=campaign_id, reason=reason)

    def queue_screen_manifest_refresh(
        screen: dict[str, Any], *, identity: Any, request: Request, reason: str,
    ) -> None:
        """Publish an affected Screen's resolved manifest outside the request.

        Editing, archiving, or restoring an inventory mapping may remove a
        physical output from the Player's resolved state.  Keep the web form
        responsive, but still enqueue a signed replacement (including an
        intentional empty manifest) for both the old and current Agent.
        """
        if not bool(screen.get("manifest_refresh_required")):
            return
        manifest_agents = {
            str(screen.get("agent_id") or "").strip(),
            str(screen.get("previous_agent_id") or "").strip(),
        }
        manifest_agents.discard("")
        if not manifest_agents:
            return
        screen_id = str(screen.get("screen_id") or "")
        security.audit(
            identity.username, "media.player_manifest.refresh_queued", "SUCCESS",
            f"Screen={screen_id}; Agents={len(manifest_agents)}; Reason={reason}",
            request_security.remote_ip(request), resource=screen_id, role=identity.role,
        )
        nonlocal media_manifest_refresh_worker
        with media_manifest_refresh_lock:
            media_manifest_refresh_pending.update(manifest_agents)
            running = bool(media_manifest_refresh_worker and media_manifest_refresh_worker.is_alive())
            if running:
                return

            def _drain_manifest_refreshes() -> None:
                nonlocal media_manifest_refresh_worker
                while True:
                    with media_manifest_refresh_lock:
                        queued = set(media_manifest_refresh_pending)
                        media_manifest_refresh_pending.clear()
                    if not queued:
                        with media_manifest_refresh_lock:
                            # A producer may have queued a new Agent between
                            # the previous empty check and this lock.
                            if media_manifest_refresh_pending:
                                continue
                            media_manifest_refresh_worker = None
                        return
                    publish_media_manifests_for_agents(
                        queued, actor=identity.username, reason="SCREEN_CONFIGURATION_CHANGED",
                    )

            media_manifest_refresh_worker = threading.Thread(
                target=_drain_manifest_refreshes,
                name="gideon-player-screen-manifest-refresh",
                daemon=True,
            )
            media_manifest_refresh_worker.start()

    def publish_media_manifests_for_campaign(campaign_id: str, *, actor: str) -> None:
        """Publish only resolved, signed Player state after Phase 2 delivery.

        This runs from the existing background distributor/scheduler, never in
        a Marketing request. A missing/unready selected cache deliberately
        retains the previous valid manifest, preserving offline continuity.
        """
        try:
            agent_ids = campaigns.agent_ids_for_campaign(campaign_id)
        except CampaignStoreError:
            return
        publish_media_manifests_for_agents(agent_ids, actor=actor, campaign_id=campaign_id, reason="CAMPAIGN_RESOLUTION")

    def _dispatch_media_distribution_unlocked(campaign_id: str, *, actor: str) -> None:
        """Turn a durable campaign outbox into signed async Transfers."""
        try:
            for delivery in campaigns.pending_media_deliveries(campaign_id=campaign_id, limit=100):
                delivery_id = str(delivery.get("delivery_id") or "")
                try:
                    rel = str(delivery.get("blob_relpath") or "")
                    blob = (operations.media_asset_dir / rel).resolve()
                    if operations.media_asset_dir not in blob.parents or not blob.is_file():
                        raise RuntimeError("MEDIA_LIBRARY_FILE_UNAVAILABLE")
                    job = operations.enqueue_media_delivery(
                        asset_path=blob, asset_id=str(delivery.get("asset_id") or ""), sha256=str(delivery.get("sha256") or ""),
                        size_bytes=int(delivery.get("size_bytes") or 0), agent_id=str(delivery.get("agent_id") or ""),
                        actor=actor, delivery_id=delivery_id,
                    )
                    campaigns.mark_media_delivery_dispatched(
                        delivery_id, preparation_job_id=str(job.get("JobId") or ""), actor=actor,
                    )
                except Exception as exc:
                    campaigns.reconcile_media_delivery(
                        delivery_id, gateway_state="FAILED", agent_online=False,
                        error="No se pudo preparar el envío seguro; GIDEON lo reintentará cuando el destino esté disponible.", actor=actor,
                    )
                    LOG.warning("GIDEON Media delivery enqueue failed: %s", redact_error(exc))
        finally:
            # Local preparation records are safe to inspect synchronously and
            # do not turn an HTTP response into a Gateway round trip.
            reconcile_media_distribution(campaign_id)
            publish_media_manifests_for_campaign(campaign_id, actor=actor)

    def dispatch_media_distribution(campaign_id: str, *, actor: str) -> None:
        if not media_distribution_lock.acquire(blocking=False):
            return
        try:
            _dispatch_media_distribution_unlocked(campaign_id, actor=actor)
        finally:
            media_distribution_lock.release()

    media_scheduler_stop = threading.Event()
    app.state.media_distribution_scheduler_stop = media_scheduler_stop

    def _media_distribution_cycle() -> None:
        """One bounded, background-only attempt to resume due deliveries."""
        if not media_distribution_lock.acquire(blocking=False):
            return
        try:
            # GatewayFacade supplies stale cache on transient failure; these
            # calls are intentionally outside HTTP route handling.
            agent_snapshot: list[dict[str, Any]] | None
            try:
                agent_snapshot = [row for row in gateway.agents() if isinstance(row, dict)]
            except Exception as exc:
                LOG.warning("GIDEON Media scheduler could not read Agents: %s", redact_error(exc))
                agent_snapshot = None
            if agent_snapshot is not None:
                try:
                    # Capability ingestion belongs to the bounded scheduler,
                    # never to a Marketing GET. It can also repair exactly one
                    # unambiguous legacy SCREEN-N binding. Publish that Agent's
                    # newly resolved signed state immediately; active campaigns
                    # keep retrying through the normal cycle if Gateway is
                    # temporarily unavailable.
                    capability_result = campaigns.reconcile_screen_capabilities(
                        agent_snapshot, actor="system",
                    )
                    if capability_result.manifest_agent_ids:
                        publish_media_manifests_for_agents(
                            capability_result.manifest_agent_ids, actor="system",
                            reason="SCREEN_OUTPUT_AUTO_RECONCILED",
                        )
                except Exception as exc:
                    LOG.warning("GIDEON Media display capability observation skipped: %s", redact_error(exc))
            try:
                limit = max(50, min(int(config.get("media_distribution_gateway_job_limit", 500)), 1000))
                job_snapshot = [row for row in gateway.jobs_fast(limit=limit) if isinstance(row, dict)]
            except Exception as exc:
                LOG.warning("GIDEON Media scheduler could not read Jobs: %s", redact_error(exc))
                job_snapshot = None
            campaigns_to_resume = [
                str(row.get("campaign_id") or "") for row in campaigns.list_campaigns()
                if str(row.get("state") or "").upper() in {"SCHEDULED", "ACTIVE"}
            ]
            for campaign_id in campaigns_to_resume:
                if not campaign_id:
                    continue
                reconcile_media_distribution(
                    campaign_id, gateway_jobs=job_snapshot, gateway_agents=agent_snapshot,
                )
                _dispatch_media_distribution_unlocked(campaign_id, actor="system")
        except Exception as exc:
            LOG.warning("GIDEON Media scheduler cycle skipped: %s", redact_error(exc))
        finally:
            media_distribution_lock.release()

    def _media_distribution_scheduler() -> None:
        interval = max(30, min(int(config.get("media_distribution_retry_seconds", 60)), 900))
        # A short initial wait lets the Web/Gateway services publish their
        # first caches without delaying recovery for a full interval.
        if media_scheduler_stop.wait(5):
            return
        while not media_scheduler_stop.is_set():
            _media_distribution_cycle()
            media_scheduler_stop.wait(interval)

    @app.on_event("startup")
    async def start_media_distribution_scheduler() -> None:
        if not bool(config.get("media_distribution_scheduler_enabled", True)):
            return
        existing = getattr(app.state, "media_distribution_scheduler_thread", None)
        if isinstance(existing, threading.Thread) and existing.is_alive():
            return
        media_scheduler_stop.clear()
        thread = threading.Thread(target=_media_distribution_scheduler, name="gideon-media-distribution", daemon=True)
        app.state.media_distribution_scheduler_thread = thread
        thread.start()

    @app.on_event("shutdown")
    async def stop_media_distribution_scheduler() -> None:
        media_scheduler_stop.set()
        thread = getattr(app.state, "media_distribution_scheduler_thread", None)
        if isinstance(thread, threading.Thread) and thread.is_alive():
            thread.join(timeout=2.0)

    @app.get("/media", response_class=HTMLResponse)
    def media_home(request: Request):
        require(request, "media.view")
        return RedirectResponse("/media/campaigns", status_code=303)

    @app.get("/media/library", response_class=HTMLResponse)
    def media_library(request: Request):
        require(request, "media.view")
        context = media_context(request, include_campaigns=False, include_archived=bool(request.query_params.get("archived")))
        page, page_size, query = media_catalog_page_args(request)
        asset_state = str(request.query_params.get("asset_state") or "").strip().upper()
        try:
            asset_page = campaigns.list_media_assets_page(
                include_archived=bool(request.query_params.get("archived")), state=asset_state,
                query=query, page=page, page_size=page_size,
            )
        except CampaignStoreError as exc:
            asset_page = {"items": [], "pagination": {"page": 1, "pages": 0, "total": 0, "has_previous": False, "has_next": False}, "query": query}
            context["gateway_error"] = (context.get("gateway_error") + " · " if context.get("gateway_error") else "") + str(exc)
        context.update({
            "title": "Biblioteca de medios", "message": str(request.query_params.get("message") or ""),
            "error": str(request.query_params.get("error") or ""), "media_upload_url": "/media/assets/upload",
            "media_assets": asset_page.get("items", []), "asset_page": asset_page,
            "asset_filters": {"q": query, "state": asset_state},
        })
        return template(request, "media_library.html", context)

    @app.post("/media/assets/upload", response_class=JSONResponse)
    async def media_asset_upload(request: Request, file: UploadFile = File(...)):
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        filename = Path(str(file.filename or "video.mp4")).name
        display_name = str(form.get("display_name") or Path(filename).stem or "Video GIDEON")
        temp = operations.transfer_dir / f".media-upload-{secrets.token_hex(12)}.part"
        size = 0
        limit = int(config.get("max_media_upload_bytes", config.get("max_transfer_upload_bytes", 1024 * 1024 * 1024)))
        asset: dict[str, Any] | None = None
        try:
            with temp.open("wb") as fh:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise ValueError(f"El video excede el máximo de {limit} bytes.")
                    fh.write(chunk)
            if size <= 0:
                raise ValueError("Seleccione un video MP4 que no esté vacío.")
            os.chmod(temp, 0o640)
            asset = campaigns.create_media_asset(
                display_name=display_name, actor=identity.username,
                origin_campaign_id=str(form.get("campaign_id") or ""),
                valid_from=str(form.get("valid_from") or ""), valid_until=str(form.get("valid_until") or ""),
                remote_ip=request_security.remote_ip(request),
            )
            job = operations.enqueue_media_asset(
                filename=filename, source_path=temp, asset_id=str(asset["asset_id"]), actor=identity.username,
            )
            campaigns.attach_media_asset_job(str(asset["asset_id"]), str(job["JobId"]), actor=identity.username)
            security.audit(
                identity.username, "media.assets.upload", "SUCCESS",
                f"Asset={asset['asset_id']}; PreparationJob={job['JobId']}; Bytes={size}",
                request_security.remote_ip(request), resource=str(asset["asset_id"]), role=identity.role,
            )
            # The upload is intentionally asynchronous.  Do not return the
            # operational Job identifier here: Marketing can follow the
            # human-readable asset state, while the protected Jobs area keeps
            # its existing role-gated technical audit trail.
            return JSONResponse({
                "asset_id": asset["asset_id"], "state": "ANALYZING",
                "message": "Video recibido. GIDEON lo analiza en segundo plano antes de permitir su publicación.",
            }, status_code=202, headers={"Cache-Control": "no-store"})
        except Exception as exc:
            temp.unlink(missing_ok=True)
            if asset is not None:
                try:
                    campaigns.reject_media_asset(str(asset["asset_id"]), message="No se pudo preparar el video para análisis.", actor=identity.username, error=True)
                except Exception:
                    pass
            security.audit(identity.username, "media.assets.upload", "FAILED", redact_error(exc), request_security.remote_ip(request), role=identity.role)
            # Keep filesystem, parser and worker details in the protected
            # audit record.  The Marketing-facing endpoint returns an action
            # the user can safely understand without exposing server internals.
            raise HTTPException(409, "No se pudo preparar el video para análisis. Revise el archivo MP4 o intente nuevamente.") from exc

    @app.get("/api/v1/media/assets", response_class=JSONResponse)
    def media_assets_api(request: Request):
        """Page the safe asset picker; never ship the full library to a form."""
        require(request, "media.view")
        page, page_size, query = media_catalog_page_args(request, default_size=25)
        state = str(request.query_params.get("state") or "READY").strip().upper()
        if str(request.query_params.get("all_states") or "").strip().lower() in {"1", "true", "yes"}:
            state = ""
        include_archived = str(request.query_params.get("archived") or "").strip().lower() in {"1", "true", "yes"}
        try:
            result = campaigns.search_media_assets_compact(
                query=query, state=state, include_archived=include_archived, page=page, page_size=page_size,
            )
        except CampaignStoreError as exc:
            raise HTTPException(422, str(exc)) from exc
        return JSONResponse({
            "Assets": result.get("items", []), "Pagination": result.get("pagination", {}),
            "Query": result.get("query", query),
        }, headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/media/assets/{asset_id}", response_class=JSONResponse)
    def media_asset_api(request: Request, asset_id: str):
        require(request, "media.view")
        try:
            asset = campaigns.media_asset_detail(asset_id)
            references = campaigns.media_asset_references(asset_id)
        except CampaignStoreError as exc:
            raise HTTPException(404, str(exc)) from exc
        # Marketing-safe response: technical paths, hashes and Agent data stay
        # in protected operational diagnostics and never leave this endpoint.
        return JSONResponse({
            "asset_id": asset["asset_id"], "name": asset["display_name"], "state": asset["status"],
            "message": asset.get("error_message") or "", "duration_seconds": asset["duration_seconds"],
            "resolution": asset["resolution"], "format": asset.get("container") or "MP4",
            "has_audio": bool(asset.get("has_audio")),
            "warning": str(asset.get("playback_warning") or ""),
            "valid_from": asset.get("valid_from") or "", "valid_until": asset.get("valid_until") or "",
            "version_token": asset.get("version_token") or "",
            "usage": {
                "current_campaign_count": int(references["current_count"]),
                "active_campaign_count": int(references["active_count"]),
                "can_archive": bool(references["can_archive"]),
            },
        }, headers={
            "Cache-Control": "no-store",
            "ETag": '"' + str(asset.get("version_token") or "") + '"',
        })

    @app.get("/media/assets/{asset_id}/edit", response_class=HTMLResponse)
    def media_asset_edit(request: Request, asset_id: str):
        identity = require(request, "media.manage")
        try:
            asset = campaigns.media_asset_detail(asset_id)
            references = campaigns.media_asset_references(asset_id)
        except CampaignStoreError as exc:
            return RedirectResponse("/media/library?error=" + quote(str(exc), safe=""), status_code=303)
        if bool(asset.get("archived")):
            return RedirectResponse(
                "/media/library?archived=1&error=" + quote(
                    "El video está archivado. Su historial se conserva y no puede modificarse.", safe=""
                ),
                status_code=303,
            )
        context = {
            "title": "Editar video", "asset": asset, "references": references,
            "error": str(request.query_params.get("error") or ""), "identity": identity,
            "form_action": "/media/assets/" + quote(str(asset["asset_id"]), safe="") + "/edit",
        }
        return template(request, "media_asset_edit.html", context)

    @app.post("/media/assets/{asset_id}/edit")
    async def media_asset_edit_submit(request: Request, asset_id: str):
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        encoded_asset = quote(str(asset_id or ""), safe="")
        try:
            campaigns.update_media_asset(
                asset_id, display_name=str(form.get("display_name") or ""),
                valid_from=str(form.get("valid_from") or ""), valid_until=str(form.get("valid_until") or ""),
                actor=identity.username, remote_ip=request_security.remote_ip(request),
                expected_updated_at=str(form.get("expected_updated_at") or ""),
                expected_version_token=str(form.get("version_token") or ""),
            )
        except CampaignStoreError as exc:
            return RedirectResponse(
                "/media/assets/" + encoded_asset + "/edit?error=" + quote(str(exc), safe=""), status_code=303,
            )
        return RedirectResponse("/media/library?message=" + quote("Video actualizado", safe=""), status_code=303)

    @app.patch("/api/v1/media/assets/{asset_id}", response_class=JSONResponse)
    async def media_asset_api_update(request: Request, asset_id: str):
        """Edit Marketing metadata through an ETag-aware API contract."""
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        try:
            payload = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(422, "El cuerpo debe ser un objeto JSON válido.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(422, "El cuerpo debe ser un objeto JSON.")
        try:
            existing = campaigns.media_asset_detail(asset_id)
            updated = campaigns.update_media_asset(
                asset_id,
                display_name=str(payload.get("display_name", existing.get("display_name") or "")),
                valid_from=str(payload.get("valid_from", existing.get("valid_from") or "")),
                valid_until=str(payload.get("valid_until", existing.get("valid_until") or "")),
                actor=identity.username,
                remote_ip=request_security.remote_ip(request),
                expected_updated_at=str(payload.get("expected_updated_at") or ""),
                expected_version_token=_request_version_token(request, payload),
            )
        except CampaignStoreError as exc:
            security.audit(identity.username, "media.assets.edit", "FAILED", str(exc), request_security.remote_ip(request), resource=asset_id, role=identity.role)
            raise HTTPException(409, str(exc)) from exc
        result = {
            "asset_id": updated["asset_id"], "name": updated["display_name"],
            "valid_from": updated.get("valid_from") or "", "valid_until": updated.get("valid_until") or "",
            "state": updated.get("status") or "", "version_token": updated.get("version_token") or "",
        }
        return JSONResponse({"Asset": result, "Updated": True}, headers={
            "Cache-Control": "no-store",
            "ETag": '"' + str(updated.get("version_token") or "") + '"',
        })

    @app.post("/media/assets/{asset_id}/archive")
    async def media_asset_archive(request: Request, asset_id: str):
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        try:
            campaigns.archive_media_asset(asset_id, actor=identity.username, remote_ip=request_security.remote_ip(request))
        except CampaignStoreError as exc:
            # This is a browser form, not a JSON client.  Return to the
            # library with a clear explanation instead of exposing a raw 409
            # page that makes the safe logical-delete rule look broken.
            return RedirectResponse("/media/library?error=" + quote(str(exc), safe=""), status_code=303)
        return RedirectResponse("/media/library?message=" + quote("Video archivado", safe=""), status_code=303)

    @app.get("/transfers/{job_id}/create-campaign")
    def transfer_create_campaign_offer(request: Request, job_id: str):
        identity = require(request, "media.manage")
        job = operations.transfer_job(job_id)
        candidate = (job or {}).get("MediaCampaignCandidate") if isinstance(job, dict) else {}
        asset_id = str((candidate or {}).get("AssetId") or "")
        if str((candidate or {}).get("Status") or "").upper() != "READY" or not asset_id:
            raise HTTPException(409, "Este archivo aún no es un video aprobado para campañas.")
        security.audit(identity.username, "media.assets.transfer_offer", "SUCCESS", f"TransferJob={job_id}; Asset={asset_id}",
                       request_security.remote_ip(request), resource=asset_id, role=identity.role)
        return RedirectResponse(f"/media/campaigns/new?asset={asset_id}", status_code=303)

    @app.get("/media/campaigns", response_class=HTMLResponse)
    def media_campaigns_page(request: Request):
        require(request, "media.view")
        context = media_context(request, include_campaigns=False)
        page, page_size, query = media_catalog_page_args(request)
        try:
            campaign_page = campaigns.list_campaigns_page(
                state=context["filters"]["state"] if context["filters"]["state"] in context["campaign_states"] else "",
                site_code=context["filters"]["site"], group_agent_ids=context["group_agent_ids"],
                screen_id=context["filters"]["screen"], os_name=context["filters"]["os"],
                agent_platforms={str(item["agent_id"]): str(item["platform"]) for item in context["agents"]},
                include_archived=bool(request.query_params.get("archived")), query=query, page=page, page_size=page_size,
            )
        except CampaignStoreError as exc:
            campaign_page = {"items": [], "pagination": {"page": 1, "pages": 0, "total": 0, "has_previous": False, "has_next": False}, "query": query}
            context["gateway_error"] = (context.get("gateway_error") + " · " if context.get("gateway_error") else "") + str(exc)
        context.update({
            "title": "Campañas", "message": str(request.query_params.get("message") or ""), "error": "",
            "campaigns": campaign_page.get("items", []), "campaign_page": campaign_page,
            "campaign_query": query,
        })
        return template(request, "media_campaigns.html", context)

    @app.get("/media/campaigns/new", response_class=HTMLResponse)
    def media_campaign_new(request: Request):
        identity = require(request, "media.manage")
        context = media_wizard_context(request)
        selected_asset_id = str(request.query_params.get("asset") or "").strip()
        selected_asset = None
        if selected_asset_id:
            try:
                selected_asset = campaigns.media_asset_detail(selected_asset_id)
            except CampaignStoreError:
                selected_asset_id = ""
        context.update({
            "title": "Nueva campaña", "campaign": None, "form_action": "/media/campaigns/new",
            "submit_label": "Crear campaña", "error": "", "identity": identity,
            "selected_asset_id": selected_asset_id, "selected_asset": selected_asset,
        })
        return template(request, "media_campaign_wizard.html", context)

    @app.post("/media/campaigns/new", response_class=HTMLResponse)
    async def media_campaign_create(request: Request):
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        state = str(form.get("publication_state") or "DRAFT").strip().upper()
        if state == "ACTIVE" and not identity.can("campaigns.approve"):
            raise HTTPException(403, "Su rol puede preparar campañas, pero no activarlas directamente.")
        # Do not read the full Screen inventory for a form submission. The
        # helper resolves only posted IDs when it validates assignments.
        context = media_wizard_context(request, form=form)
        try:
            assignments = media_assignments_from_form(
                form, screens=context["screens"], default_playlist=str(form.get("title") or ""), assets_by_id=context["assets_by_id"],
            )
            if state in {"SCHEDULED", "ACTIVE"}:
                campaigns.assert_assignments_media_ready(assignments, require_assets=True)
            result = campaigns.create_campaign_draft(
                title=str(form.get("title") or ""), objective=str(form.get("objective") or ""), assignments=assignments,
                actor=identity.username, state=state, change_note=str(form.get("change_note") or ""),
                remote_ip=request_security.remote_ip(request),
            )
        except (CampaignStoreError, CampaignConflictError) as exc:
            security.audit(identity.username, "campaigns.create", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            context.update({"title": "Nueva campaña", "campaign": None, "form_action": "/media/campaigns/new", "submit_label": "Crear campaña", "error": str(exc), "form": media_form_snapshot(form)})
            return template(request, "media_campaign_wizard.html", context, 409)
        if state in {"SCHEDULED", "ACTIVE"}:
            campaigns.queue_campaign_distribution(result["campaign_id"], actor=identity.username, remote_ip=request_security.remote_ip(request))
            return RedirectResponse(
                f"/media/campaigns/{result['campaign_id']}?message=Campaña+creada+y+distribución+encolada",
                status_code=303,
            )
        return RedirectResponse(f"/media/campaigns/{result['campaign_id']}?message=Campaña+creada", status_code=303)

    @app.get("/media/campaigns/{campaign_id}", response_class=HTMLResponse)
    def media_campaign_detail(request: Request, campaign_id: str):
        require(request, "media.view")
        try:
            campaign = campaigns.campaign_detail(campaign_id)
        except CampaignStoreError as exc:
            raise HTTPException(404, str(exc)) from exc
        context = media_context(request, include_campaigns=False, include_archived=True)
        context.update({
            "title": campaign["title"], "campaign": campaign, "message": str(request.query_params.get("message") or ""),
            "history": campaigns.list_history(campaign_id=campaign_id),
        })
        # Campaign detail is intentionally a read-only projection.  The
        # scheduler reconciles durable delivery rows in the background; merely
        # opening this page cannot contend with transfers or alter state.
        return template(request, "media_campaign_detail.html", context)

    @app.get("/media/campaigns/{campaign_id}/revise", response_class=HTMLResponse)
    def media_campaign_revise_page(request: Request, campaign_id: str):
        require(request, "media.manage")
        try:
            campaign = campaigns.campaign_detail(campaign_id)
        except CampaignStoreError as exc:
            raise HTTPException(404, str(exc)) from exc
        context = media_wizard_context(request, campaign=campaign)
        context.update({
            "title": f"Revisar {campaign['title']}", "campaign": campaign,
            "form_action": f"/media/campaigns/{campaign_id}/revise", "submit_label": "Crear nueva revisión", "error": "",
        })
        return template(request, "media_campaign_wizard.html", context)

    @app.post("/media/campaigns/{campaign_id}/revise", response_class=HTMLResponse)
    async def media_campaign_revise(request: Request, campaign_id: str):
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        state = str(form.get("publication_state") or "DRAFT").strip().upper()
        if state == "ACTIVE" and not identity.can("campaigns.approve"):
            raise HTTPException(403, "Su rol puede preparar campañas, pero no activarlas directamente.")
        context = media_wizard_context(request, form=form)
        try:
            assignments = media_assignments_from_form(
                form, screens=context["screens"], default_playlist=str(form.get("title") or ""), assets_by_id=context["assets_by_id"],
            )
            if state in {"SCHEDULED", "ACTIVE"}:
                campaigns.assert_assignments_media_ready(assignments, require_assets=True)
            result = campaigns.save_campaign_revision(
                campaign_id, title=str(form.get("title") or ""), objective=str(form.get("objective") or ""),
                assignments=assignments, state=state, change_note=str(form.get("change_note") or ""), actor=identity.username,
                remote_ip=request_security.remote_ip(request),
                expected_updated_at=str(form.get("expected_updated_at") or ""),
                expected_version_token=str(form.get("version_token") or ""),
            )
        except (CampaignStoreError, CampaignConflictError) as exc:
            security.audit(identity.username, "campaigns.edit", "FAILED", str(exc), request_security.remote_ip(request), resource=campaign_id, role=identity.role)
            try:
                campaign = campaigns.campaign_detail(campaign_id)
            except CampaignStoreError:
                campaign = None
            context = media_wizard_context(request, campaign=campaign, form=form)
            context.update({"title": "Nueva revisión", "campaign": campaign, "form_action": f"/media/campaigns/{campaign_id}/revise", "submit_label": "Crear nueva revisión", "error": str(exc), "form": media_form_snapshot(form)})
            return template(request, "media_campaign_wizard.html", context, 409)
        if state in {"SCHEDULED", "ACTIVE"}:
            campaigns.queue_campaign_distribution(result["campaign_id"], actor=identity.username, remote_ip=request_security.remote_ip(request))
            return RedirectResponse(
                f"/media/campaigns/{result['campaign_id']}?message=Revisión+{result['current_revision_no']}+creada+y+distribución+encolada",
                status_code=303,
            )
        return RedirectResponse(f"/media/campaigns/{result['campaign_id']}?message=Revisión+{result['current_revision_no']}+creada", status_code=303)

    @app.post("/media/campaigns/{campaign_id}/{action}")
    async def media_campaign_action(request: Request, campaign_id: str, action: str):
        identity = require(request, "media.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        action_name = str(action or "").strip().lower()
        if action_name not in {"activate", "pause", "archive", "reactivate", "duplicate"}:
            raise HTTPException(404, "Acción de campaña no reconocida.")
        if action_name in {"activate", "reactivate"} and not identity.can("campaigns.approve"):
            raise HTTPException(403, "Su rol no puede activar campañas.")
        try:
            if action_name == "activate":
                campaigns.assert_publishable(campaign_id)
                result = campaigns.activate_campaign(
                    campaign_id, actor=identity.username, remote_ip=request_security.remote_ip(request),
                    expected_updated_at=str(form.get("expected_updated_at") or ""),
                    expected_version_token=str(form.get("version_token") or ""),
                )
            elif action_name == "pause":
                result = campaigns.pause_campaign(
                    campaign_id, actor=identity.username, remote_ip=request_security.remote_ip(request),
                    expected_updated_at=str(form.get("expected_updated_at") or ""),
                    expected_version_token=str(form.get("version_token") or ""),
                )
            elif action_name == "archive":
                result = campaigns.archive_campaign(
                    campaign_id, actor=identity.username, remote_ip=request_security.remote_ip(request),
                    expected_updated_at=str(form.get("expected_updated_at") or ""),
                    expected_version_token=str(form.get("version_token") or ""),
                )
            elif action_name == "reactivate":
                campaigns.assert_publishable(campaign_id)
                result = campaigns.reactivate_campaign(
                    campaign_id, actor=identity.username, remote_ip=request_security.remote_ip(request),
                    expected_updated_at=str(form.get("expected_updated_at") or ""),
                    expected_version_token=str(form.get("version_token") or ""),
                )
            else:
                result = campaigns.duplicate_campaign(
                    campaign_id, actor=identity.username, remote_ip=request_security.remote_ip(request),
                    expected_updated_at=str(form.get("expected_updated_at") or ""),
                    expected_version_token=str(form.get("version_token") or ""),
                )
        except (CampaignStoreError, CampaignConflictError) as exc:
            security.audit(identity.username, f"campaigns.{action_name}", "FAILED", str(exc), request_security.remote_ip(request), resource=campaign_id, role=identity.role)
            # Keep implementation detail out of a URL (and out of the browser
            # history).  The full, immutable reason is already in the audit
            # trail above; Marketing gets a safe, actionable message.
            return RedirectResponse(
                f"/media/campaigns/{campaign_id}?message=No+se+pudo+registrar+la+acción.+Revise+el+detalle+de+la+campaña.",
                status_code=303,
            )
        destination = result["campaign_id"]
        if action_name in {"activate", "reactivate"}:
            campaigns.queue_campaign_distribution(destination, actor=identity.username, remote_ip=request_security.remote_ip(request))
            return RedirectResponse(
                f"/media/campaigns/{destination}?message=Acción+registrada+y+distribución+encolada",
                status_code=303,
            )
        if action_name in {"pause", "archive"}:
            # A pause/archive must issue a signed empty replacement manifest
            # for the previously targeted Agent(s); no user request waits for
            # the Gateway round trip.
            return RedirectResponse(
                f"/media/campaigns/{destination}?message=Acción+registrada",
                status_code=303,
            )
        return RedirectResponse(f"/media/campaigns/{destination}?message=Acción+registrada+en+una+nueva+revisión", status_code=303)

    @app.get("/media/screens", response_class=HTMLResponse)
    def media_screens_page(request: Request):
        require(request, "screens.view")
        context = media_context(request, include_campaigns=False, include_archived=True)
        screen_edit = None
        edit_error = ""
        page_error = str(request.query_params.get("error") or "")
        edit_id = str(request.query_params.get("edit") or "").strip()
        if edit_id:
            try:
                candidate = campaigns.screen_detail(edit_id)
                if candidate.get("archived"):
                    edit_error = "La pantalla está archivada. Restáurela para revisión antes de corregir su configuración."
                else:
                    screen_edit = candidate
            except CampaignStoreError as exc:
                edit_error = str(exc)
        context.update({
            "title": "Pantallas", "message": str(request.query_params.get("message") or ""), "error": edit_error or page_error,
            "screen_edit": screen_edit,
        })
        return template(request, "media_screens.html", context)

    def screen_registration_defaults(context: dict[str, Any], agent_id: str, output_key: str, commercial_name: str, resolution: str) -> tuple[str, str]:
        """Apply the same friendly defaults used by the Screen form.

        The browser fills these values for a smoother workflow, but keeping
        the rule server-side also makes retries and no-JavaScript submissions
        deterministic.
        """
        agent = next((item for item in context.get("agents", []) if str(item.get("agent_id") or "") == str(agent_id or "")), None)
        name = str(commercial_name or "").strip()
        detected_resolution = ""
        if agent:
            name = name or str(agent.get("device_name") or agent.get("label") or "").strip()
            for output in agent.get("outputs") or []:
                if str(output.get("output_key") or "") == str(output_key or ""):
                    detected_resolution = str(output.get("resolution") or "").strip()
                    break
        return name, str(resolution or "").strip() or detected_resolution

    @app.post("/media/screens/create", response_class=HTMLResponse)
    async def media_screen_create(request: Request):
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        context = media_context(request, include_campaigns=False, include_archived=True)
        agent_id = str(form.get("agent_id") or "").strip()
        output_key = str(form.get("output_key") or "").strip()
        commercial_name, resolution = screen_registration_defaults(
            context, agent_id, output_key, str(form.get("commercial_name") or ""), str(form.get("resolution") or ""),
        )
        try:
            campaigns.create_screen(
                site_code=str(form.get("site_code") or ""), commercial_name=commercial_name,
                physical_location=str(form.get("physical_location") or ""), agent_id=agent_id,
                output_key=output_key, output_label=str(form.get("output_label") or ""),
                output_identity=str(form.get("output_identity") or ""),
                target_kind=str(form.get("target_kind") or "PHYSICAL_CONNECTOR"),
                orientation=str(form.get("orientation") or "LANDSCAPE"), resolution=resolution,
                state=str(form.get("state") or "READY"), actor=identity.username,
                playback_mode=str(form.get("playback_policy") or "DEDICATED"),
                remote_ip=request_security.remote_ip(request), valid_site_codes=[item["site_code"] for item in context["sites"]],
            )
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.create", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            context.update({"title": "Pantallas", "error": str(exc), "screen_form": dict(form)})
            return template(request, "media_screens.html", context, 409)
        return RedirectResponse("/media/screens?message=Pantalla+creada", status_code=303)

    @app.post("/media/screens/{screen_id}/edit", response_class=HTMLResponse)
    async def media_screen_update(request: Request, screen_id: str):
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        context = media_context(request, include_campaigns=False, include_archived=True)
        agent_id = str(form.get("agent_id") or "").strip()
        output_key = str(form.get("output_key") or "").strip()
        commercial_name, resolution = screen_registration_defaults(
            context, agent_id, output_key, str(form.get("commercial_name") or ""), str(form.get("resolution") or ""),
        )
        try:
            updated_screen = campaigns.update_screen(
                screen_id, commercial_name=commercial_name,
                physical_location=str(form.get("physical_location") or ""), agent_id=agent_id,
                output_key=output_key, output_label=str(form.get("output_label") or ""),
                output_identity=str(form.get("output_identity") or ""),
                target_kind=str(form.get("target_kind") or "PHYSICAL_CONNECTOR"),
                orientation=str(form.get("orientation") or "LANDSCAPE"), resolution=resolution,
                state=str(form.get("state") or "READY"), actor=identity.username,
                playback_mode=str(form.get("playback_policy") or "DEDICATED"),
                remote_ip=request_security.remote_ip(request),
                expected_updated_at=str(form.get("expected_updated_at") or ""),
                expected_version_token=str(form.get("version_token") or ""),
            )
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.edit", "FAILED", str(exc), request_security.remote_ip(request), resource=screen_id, role=identity.role)
            try:
                screen_edit = campaigns.screen_detail(screen_id)
            except CampaignStoreError:
                screen_edit = None
            context.update({"title": "Pantallas", "error": str(exc), "screen_form": dict(form), "screen_edit": screen_edit})
            return template(request, "media_screens.html", context, 409)
        queue_screen_manifest_refresh(
            updated_screen, identity=identity, request=request, reason="SCREEN_CONFIGURATION_CHANGED",
        )
        return RedirectResponse("/media/screens?message=Pantalla+actualizada", status_code=303)

    @app.post("/media/screens/{screen_id}/archive")
    async def media_screen_archive(request: Request, screen_id: str):
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        try:
            archived_screen = campaigns.archive_screen(screen_id, actor=identity.username, remote_ip=request_security.remote_ip(request))
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.archive", "FAILED", str(exc), request_security.remote_ip(request), resource=screen_id, role=identity.role)
            raise HTTPException(409, str(exc)) from exc
        queue_screen_manifest_refresh(
            archived_screen, identity=identity, request=request, reason="SCREEN_LOGICAL_ARCHIVE",
        )
        return RedirectResponse("/media/screens?message=Pantalla+archivada", status_code=303)

    @app.post("/media/screens/{screen_id}/restore")
    async def media_screen_restore(request: Request, screen_id: str):
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        try:
            restored_screen = campaigns.restore_screen(screen_id, actor=identity.username, remote_ip=request_security.remote_ip(request))
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.restore", "FAILED", str(exc), request_security.remote_ip(request), resource=screen_id, role=identity.role)
            # This is a browser form action. Preserve the safe audit outcome,
            # then return to the inventory with a readable alert instead of a
            # raw framework page. No Screen or campaign data was changed.
            return RedirectResponse(
                f"/media/screens?error={quote(str(exc), safe='')}",
                status_code=303,
            )
        # The asynchronous refresh publishes only a signed state manifest. It
        # neither receives nor stages MediaAsset bytes, and it remains necessary
        # to keep a restored NEEDS_REVIEW mapping fail-closed on the Player.
        queue_screen_manifest_refresh(
            restored_screen, identity=identity, request=request, reason="SCREEN_RESTORED_FOR_REVIEW",
        )
        return RedirectResponse(
            f"/media/screens?edit={quote(screen_id, safe='')}&message=Pantalla+restaurada+para+revisión",
            status_code=303,
        )

    @app.get("/media/schedule", response_class=HTMLResponse)
    def media_schedule_page(request: Request):
        require(request, "media.view")
        context = media_context(request, include_campaigns=True)
        context.update({"title": "Programación", "scheduled": [row for row in context["campaigns"] if row.get("state") in {"SCHEDULED", "ACTIVE", "PAUSED"}]})
        return template(request, "media_schedule.html", context)

    @app.get("/media/history", response_class=HTMLResponse)
    def media_history_page(request: Request):
        require(request, "media.view")
        # History only renders the immutable event log. Do not load the agent,
        # screen, site or campaign inventories just to build the shared media
        # context; that made this read-only tab slow and vulnerable to a cold
        # Gateway delay even though it never displayed those collections.
        return template(request, "media_history.html", {
            "title": "Historial de campañas",
            "history": campaigns.list_history(),
        })

    def media_screen_api_projection(item: dict[str, Any]) -> dict[str, Any]:
        """Return a Marketing-safe inventory record for API consumers.

        Agent identifiers, connector identities and physical paths remain
        absent even from the editable API.  The form/API receive only the
        stable GIDEON screen reference and commercial fields needed to manage it.
        """
        return {
            "screen_id": str(item.get("screen_id") or ""),
            "site_code": str(item.get("site_code") or ""),
            "name": str(item.get("commercial_name") or ""),
            "location": str(item.get("physical_location") or ""),
            "output_label": str(item.get("output_label") or ""),
            "orientation": str(item.get("orientation") or "LANDSCAPE"),
            "resolution": str(item.get("resolution") or ""),
            "state": str(item.get("state") or ""),
            "archived": bool(item.get("archived")),
            "last_sync_at": item.get("last_sync_at"),
            "connected": bool(item.get("connected", False)),
            "playback_policy": str(item.get("playback_policy") or "DEDICATED"),
            "target_type": str(item.get("target_kind_label") or "HDMI físico"),
            "version_token": str(item.get("version_token") or ""),
        }

    async def media_screen_api_payload(request: Request) -> dict[str, Any]:
        try:
            payload = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(422, "El cuerpo debe ser un objeto JSON válido.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(422, "El cuerpo debe ser un objeto JSON.")
        return payload

    @app.get("/api/v1/media/screens", response_class=JSONResponse)
    def media_screens_api(request: Request):
        require(request, "screens.view")
        include_archived = str(request.query_params.get("archived") or "").strip().lower() in {"1", "true", "yes"}
        context = media_context(
            request, include_campaigns=False, include_archived=include_archived, include_screens=False,
        )
        page, page_size, query = media_catalog_page_args(request, default_size=20)
        try:
            catalog = campaigns.list_screens_page(
                site_code=context["filters"]["site"], group_agent_ids=context["group_agent_ids"],
                os_name=context["filters"]["os"],
                state=context["filters"]["state"] if context["filters"]["state"] in context["screen_states"] else "",
                agent_platforms={str(item["agent_id"]): str(item["platform"]) for item in context["agents"]},
                include_archived=include_archived, query=query, page=page, page_size=page_size,
            )
        except CampaignStoreError as exc:
            raise HTTPException(422, str(exc)) from exc
        rows = [media_screen_api_projection(item) for item in catalog.get("items", [])]
        return JSONResponse({
            "Screens": rows,
            "Count": int(catalog.get("total") or 0),
            "Pagination": catalog.get("pagination") or {},
            "Query": str(catalog.get("query") or ""),
        })

    @app.get("/api/v1/media/screens/{screen_id}", response_class=JSONResponse)
    def media_screen_api_detail(request: Request, screen_id: str):
        require(request, "screens.view")
        try:
            screen = campaigns.screen_detail(screen_id)
        except CampaignStoreError as exc:
            raise HTTPException(404, str(exc)) from exc
        projection = media_screen_api_projection(screen)
        return JSONResponse({"Screen": projection}, headers={
            "Cache-Control": "no-store",
            "ETag": '"' + str(projection.get("version_token") or "") + '"',
        })

    @app.patch("/api/v1/media/screens/{screen_id}", response_class=JSONResponse)
    async def media_screen_api_update(request: Request, screen_id: str):
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        payload = await media_screen_api_payload(request)
        try:
            existing = campaigns.screen_detail(screen_id)
            requested_site = str(payload.get("site_code") if "site_code" in payload else existing.get("site_code") or "").strip().upper()
            if requested_site != str(existing.get("site_code") or "").upper():
                raise CampaignStoreError("La sede no se cambia al editar una pantalla. Archive el registro y cree uno nuevo en la sede correcta.")
            updated_screen = campaigns.update_screen(
                screen_id,
                commercial_name=payload["commercial_name"] if "commercial_name" in payload else existing.get("commercial_name", ""),
                physical_location=payload["physical_location"] if "physical_location" in payload else existing.get("physical_location", ""),
                agent_id=payload["agent_id"] if "agent_id" in payload else existing.get("agent_id", ""),
                output_key=payload["output_key"] if "output_key" in payload else existing.get("output_key", ""),
                output_label=payload["output_label"] if "output_label" in payload else existing.get("output_label", ""),
                output_identity=payload["output_identity"] if "output_identity" in payload else existing.get("output_identity", ""),
                target_kind=payload["target_kind"] if "target_kind" in payload else existing.get("target_kind", "PHYSICAL_CONNECTOR"),
                orientation=payload["orientation"] if "orientation" in payload else existing.get("orientation", "LANDSCAPE"),
                resolution=payload["resolution"] if "resolution" in payload else existing.get("resolution", ""),
                state=payload["state"] if "state" in payload else existing.get("state", "READY"),
                playback_mode=payload["playback_policy"] if "playback_policy" in payload else existing.get("playback_policy", "DEDICATED"),
                emergency_takeover_enabled=(
                    payload["emergency_takeover_enabled"]
                    if "emergency_takeover_enabled" in payload
                    else existing.get("emergency_takeover_enabled", True)
                ),
                actor=identity.username, remote_ip=request_security.remote_ip(request),
                expected_updated_at=str(payload.get("expected_updated_at") or ""),
                expected_version_token=_request_version_token(request, payload),
            )
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.edit", "FAILED", str(exc), request_security.remote_ip(request), resource=screen_id, role=identity.role)
            raise HTTPException(409, str(exc)) from exc
        queue_screen_manifest_refresh(
            updated_screen, identity=identity, request=request, reason="SCREEN_CONFIGURATION_CHANGED_API",
        )
        projection = media_screen_api_projection(updated_screen)
        return JSONResponse({"Screen": projection, "Updated": True}, headers={
            "Cache-Control": "no-store",
            "ETag": '"' + str(projection.get("version_token") or "") + '"',
        })

    @app.delete("/api/v1/media/screens/{screen_id}", response_class=JSONResponse)
    async def media_screen_api_archive(request: Request, screen_id: str):
        """Perform a logical deletion; the Screen row and audit remain intact."""
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        try:
            archived_screen = campaigns.archive_screen(screen_id, actor=identity.username, remote_ip=request_security.remote_ip(request))
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.archive", "FAILED", str(exc), request_security.remote_ip(request), resource=screen_id, role=identity.role)
            raise HTTPException(409, str(exc)) from exc
        queue_screen_manifest_refresh(
            archived_screen, identity=identity, request=request, reason="SCREEN_LOGICAL_ARCHIVE_API",
        )
        return JSONResponse({
            "Screen": media_screen_api_projection(archived_screen),
            "Archived": True,
            "LogicalDeletion": True,
        })

    @app.post("/api/v1/media/screens/{screen_id}/restore", response_class=JSONResponse)
    async def media_screen_api_restore(request: Request, screen_id: str):
        identity = require(request, "screens.manage")
        await validate_csrf(request, identity)
        try:
            restored_screen = campaigns.restore_screen(screen_id, actor=identity.username, remote_ip=request_security.remote_ip(request))
        except CampaignStoreError as exc:
            security.audit(identity.username, "screens.restore", "FAILED", str(exc), request_security.remote_ip(request), resource=screen_id, role=identity.role)
            raise HTTPException(409, str(exc)) from exc
        queue_screen_manifest_refresh(
            restored_screen, identity=identity, request=request, reason="SCREEN_RESTORED_FOR_REVIEW_API",
        )
        return JSONResponse({
            "Screen": media_screen_api_projection(restored_screen),
            "Restored": True,
            "State": "NEEDS_REVIEW",
        })

    @app.get("/api/v1/media/campaigns", response_class=JSONResponse)
    def media_campaigns_api(request: Request):
        require(request, "media.view")
        context = media_context(request, include_campaigns=False, include_archived=bool(request.query_params.get("archived")))
        page, page_size, query = media_catalog_page_args(request, default_size=25)
        try:
            campaign_page = campaigns.list_campaigns_page(
                state=context["filters"]["state"] if context["filters"]["state"] in context["campaign_states"] else "",
                site_code=context["filters"]["site"], group_agent_ids=context["group_agent_ids"],
                screen_id=context["filters"]["screen"], os_name=context["filters"]["os"],
                agent_platforms={str(item["agent_id"]): str(item["platform"]) for item in context["agents"]},
                include_archived=bool(request.query_params.get("archived")), query=query, page=page, page_size=page_size,
            )
        except CampaignStoreError as exc:
            raise HTTPException(422, str(exc)) from exc
        rows = [{
            "campaign_id": item["campaign_id"], "title": item["title"], "objective": item["objective"], "state": item["state"],
            "revision": item["current_revision_no"], "screen_count": item["screen_count"], "updated_at": item["updated_at"],
            "version_token": item.get("version_token") or "",
        } for item in campaign_page.get("items", [])]
        return JSONResponse({
            "Campaigns": rows, "Count": len(rows), "Total": int(campaign_page.get("total") or len(rows)),
            "Pagination": campaign_page.get("pagination", {}), "Query": campaign_page.get("query", query),
        }, headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/media/calendar", response_class=JSONResponse)
    def media_calendar_api(request: Request):
        """Return the global Marketing calendar without hydrating the page.

        The browser asks only for the visible calendar window.  This keeps the
        scheduling page responsive even when a site has many campaigns and
        preserves the existing permission boundary: no Agent, endpoint, hash
        or protocol information is included in the response.
        """
        require(request, "media.view")
        today = dt.datetime.now().date()
        default_start = today.replace(day=1)
        default_end = default_start + dt.timedelta(days=62)
        raw_start = str(request.query_params.get("from") or default_start.isoformat()).strip()
        raw_end = str(request.query_params.get("to") or default_end.isoformat()).strip()
        try:
            start = dt.date.fromisoformat(raw_start)
            end = dt.date.fromisoformat(raw_end)
        except ValueError as exc:
            raise HTTPException(422, "El intervalo del calendario debe usar fechas AAAA-MM-DD.") from exc
        if end < start or (end - start).days > 93:
            raise HTTPException(422, "El intervalo del calendario debe estar entre 1 y 94 días.")
        state = str(request.query_params.get("state") or "").strip().upper()
        if state in {"ALL", "TODOS", "TODAS"}:
            state = ""
        allowed_states = {"DRAFT", "PENDING_APPROVAL", "SCHEDULED", "ACTIVE", "PAUSED", "EXPIRED", "ARCHIVED"}
        if state and state not in allowed_states:
            raise HTTPException(422, "El estado de campaña no es válido.")
        site_code = str(request.query_params.get("site") or "").strip().upper()
        screen_id = str(request.query_params.get("screen") or "").strip()
        query = str(request.query_params.get("q") or request.query_params.get("query") or "").strip()
        include_archived = str(request.query_params.get("archived") or "").strip().lower() in {"1", "true", "yes"}
        try:
            entries = campaigns.calendar_entries(
                start_date=start.isoformat(), end_date=end.isoformat(), state=state,
                site_code=site_code, screen_id=screen_id, search=query,
                include_archived=include_archived,
            )
        except CampaignStoreError as exc:
            raise HTTPException(422, str(exc)) from exc
        sites = {
            str(item.get("site_code") or "").upper(): str(item.get("site_name") or item.get("site_code") or "")
            for item in security.list_sites()
        }
        rows: list[dict[str, Any]] = []
        for item in entries:
            rows.append({
                "campaign_id": str(item.get("campaign_id") or ""),
                "title": str(item.get("title") or ""),
                "state": str(item.get("state") or ""),
                "revision": int(item.get("current_revision_no") or 0),
                "updated_at": item.get("updated_at"),
                "screen_id": str(item.get("screen_id") or ""),
                "screen_name": str(item.get("commercial_name") or ""),
                "location": str(item.get("physical_location") or ""),
                "site_code": str(item.get("site_code") or ""),
                "site_name": sites.get(str(item.get("site_code") or "").upper(), str(item.get("site_code") or "")),
                "orientation": str(item.get("orientation") or "LANDSCAPE"),
                "resolution": str(item.get("resolution") or ""),
                "playlist": str(item.get("playlist_name") or ""),
                "asset_name": str(item.get("asset_name") or ""),
                "priority": int(item.get("priority") or 0),
                "emergency": bool(item.get("emergency")),
                "timezone": str(item.get("timezone") or "America/Lima"),
                "start_date": str(item.get("start_date") or ""),
                "end_date": str(item.get("end_date") or ""),
                "weekdays": [int(day) for day in (item.get("weekdays") or []) if str(day).isdigit() and 0 <= int(day) <= 6],
                "start_time": str(item.get("start_time") or ""),
                "end_time": str(item.get("end_time") or ""),
                "blackout_dates": [str(day) for day in (item.get("blackout_dates") or []) if str(day).strip()],
            })
        return JSONResponse({
            "Entries": rows, "Count": len(rows),
            "Range": {"from": start.isoformat(), "to": end.isoformat()},
            "Query": query, "State": state or "ALL", "Site": site_code,
        }, headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/media/campaigns/{campaign_id}/distribution", response_class=JSONResponse)
    def media_campaign_distribution_api(request: Request, campaign_id: str):
        identity = require(request, "media.view")
        try:
            rows = campaigns.list_campaign_distribution(campaign_id)
        except CampaignStoreError as exc:
            raise HTTPException(404, str(exc)) from exc
        # The campaign API intentionally exposes only what Marketing needs to
        # follow the rollout.  Agent IDs, paths, hashes and protocol state
        # remain available only through an explicit operational diagnostic.
        safe_rows = []
        for item in rows:
            job_id = str(item.get("gateway_job_id") or item.get("preparation_job_id") or "")
            safe_rows.append({
                "screen": item["screen_name"], "site": item["site_code"], "video": item["display_name"],
                "state": item["state"], "updated_at": item["updated_at"],
                # Only a role already entitled to Jobs receives a navigable
                # operation reference.  Marketing sees the same useful state
                # without receiving an internal ID or infrastructure detail.
                "job_url": f"/jobs/{quote(job_id, safe='')}" if job_id and identity.can("jobs.view") else "",
                "message": item.get("last_error") or "",
            })
        return JSONResponse(
            {"CampaignId": campaign_id, "Targets": safe_rows, "Count": len(safe_rows)},
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/groups", response_class=HTMLResponse)
    def groups_page(request: Request):
        require(request,"groups.view")
        agents=gateway.agents(); by_id={str(a.get("agent_id") or ""):a for a in agents}
        groups=security.list_groups()
        for g in groups:
            g["members"]=[by_id[x] for x in g.get("agent_ids",[]) if x in by_id]
        return template(request,"groups.html",{"title":"Grupos","groups":groups,"agents":agents})

    @app.post("/groups/create")
    async def groups_create(request: Request):
        identity=require(request,"groups.manage"); await validate_csrf(request,identity); form=await request.form()
        security.create_group(str(form.get("name") or ""),str(form.get("description") or ""),[str(x) for x in form.getlist("agent_id")],actor=identity.username,remote_ip=request_security.remote_ip(request))
        return RedirectResponse("/groups",303)

    @app.post("/groups/{group_id}/delete")
    async def groups_delete(request: Request, group_id: int):
        identity=require(request,"groups.manage"); await validate_csrf(request,identity)
        security.delete_group(group_id,actor=identity.username,remote_ip=request_security.remote_ip(request)); return RedirectResponse("/groups",303)

    @app.get("/releases",response_class=HTMLResponse)
    def releases_page(request: Request):
        require(request,"releases.view")
        gateway_error = ""
        try:
            published = gateway.releases()
        except Exception as exc:
            published = []
            gateway_error = redact_error(exc)
        return template(request,"releases.html",{
            "title":"Versiones / Releases", "releases":published,
            "local_releases":release_manager.local_releases(), "gateway_error":gateway_error,
            "stable_agent_version":AGENT_VERSION, "release_targets":stable_release_targets(),
            "source_companions":agent_installers.source_companions(50),
        })

    @app.get("/api/v1/releases/source-companions", response_class=JSONResponse)
    def releases_source_companions_api(request: Request):
        require(request, "releases.view")
        rows = agent_installers.source_companions(200)
        return JSONResponse(
            {"Schema": "gideon-release-source-companions/v1", "SourceCompanions": rows, "Count": len(rows)},
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/releases/build")
    async def releases_build(request: Request, platform: str = Form("windows"), architecture: str = Form("x86_64")):
        identity=require(request,"releases.approve"); await validate_csrf(request,identity)
        try:
            row = await asyncio.to_thread(
                release_manager.build_stable,
                platform=platform, architecture=architecture, version=AGENT_VERSION,
            )
        except Exception as exc:
            detail = redact_error(exc)
            security.audit(identity.username,"releases.build","FAILED",detail,request_security.remote_ip(request),resource=f"{platform}/{architecture}/stable/{AGENT_VERSION}",role=identity.role)
            try:
                published = gateway.releases()
            except Exception as gateway_exc:
                published = []
                detail = f"{detail} · Gateway: {redact_error(gateway_exc)}"
            return template(request,"releases.html",{
                "title":"Versiones / Releases", "releases":published,
                "local_releases":release_manager.local_releases(), "gateway_error":detail,
                "stable_agent_version":AGENT_VERSION, "release_targets":stable_release_targets(),
                "source_companions":agent_installers.source_companions(50),
            }, status_code=422)
        security.audit(identity.username,"releases.build","SUCCESS",f"Sha256={row.get('sha256')}",request_security.remote_ip(request),resource=f"{platform}/{architecture}/stable/{AGENT_VERSION}",role=identity.role)
        return RedirectResponse("/releases",status_code=303)

    @app.post("/releases/publish")
    async def releases_publish(request: Request, platform: str = Form(...), architecture: str = Form(...), version: str = Form(...), sha256: str = Form(...), distribute: str = Form("false"), note: str = Form("")):
        identity=require(request,"releases.approve"); await validate_csrf(request,identity)
        row, _ = await asyncio.to_thread(
            release_manager.publish,
            version=version, platform=platform, architecture=architecture, sha256=sha256,
        )
        do_distribute=str(distribute).lower() in {"1","true","yes","approve","approved"}
        if do_distribute:
            await asyncio.to_thread(
                gateway.approve_release, row, True, actor=identity.username,
                note=note or "Publicación y distribución estable desde WebAdmin",
            )
        security.audit(identity.username,"releases.publish","SUCCESS",f"Distribute={do_distribute}; Sha256={sha256}",request_security.remote_ip(request),resource=f"{platform}/{architecture}/stable/{version}",role=identity.role)
        return RedirectResponse("/releases",status_code=303)

    @app.post("/releases/approval")
    async def releases_approval(request: Request, platform: str = Form(...), architecture: str = Form(...), channel: str = Form(...), version: str = Form(...), approved: str = Form(...), note: str = Form("")):
        identity=require(request,"releases.approve"); await validate_csrf(request,identity); flag=str(approved).lower() in {"1","true","yes","approve","approved"}
        row={"platform":platform,"architecture":architecture,"channel":channel,"version":version}
        await asyncio.to_thread(
            gateway.approve_release, row, flag, actor=identity.username, note=note,
        )
        security.audit(identity.username,"releases.approval","SUCCESS",f"Approved={flag}",request_security.remote_ip(request),resource=f"{platform}/{architecture}/{channel}/{version}",role=identity.role)
        return RedirectResponse("/releases",status_code=303)

    @app.post("/releases/cleanup")
    async def releases_cleanup(request: Request, keep_per_target: str = Form("2")):
        identity=require(request,"releases.approve"); await validate_csrf(request,identity)
        try:
            keep=max(1,min(int(keep_per_target or 2),20))
        except (TypeError,ValueError):
            raise HTTPException(400,"Cantidad de releases a conservar inválida.")
        try:
            # Ask the Gateway for a plan first.  It knows which releases are
            # approved or currently targeted by an Agent update; the local
            # artifact store must never race ahead of that authority.
            plan=await asyncio.to_thread(
                gateway.cleanup_releases, keep_per_target=keep, actor=identity.username, dry_run=True,
            )
            if not bool(plan.get("Ok", True)):
                raise RuntimeError("El Gateway rechazó el plan de limpieza de releases.")
            planned={WebAgentReleaseManager.release_key(dict(row)) for row in (plan.get("Deleted") or []) if isinstance(row,dict)}
            remote=await asyncio.to_thread(
                gateway.cleanup_releases, keep_per_target=keep, actor=identity.username, dry_run=False,
            )
            if not bool(remote.get("Ok", True)):
                raise RuntimeError("El Gateway no confirmó la limpieza de releases; se conservaron los bundles locales.")
            deleted_remote={WebAgentReleaseManager.release_key(dict(row)) for row in (remote.get("Deleted") or []) if isinstance(row,dict)}
            if not deleted_remote.issubset(planned):
                raise RuntimeError("El resultado de limpieza del Gateway cambió durante la operación; se conservaron los bundles locales.")
            # cleanup_releases() invalidates the facade cache after a mutation,
            # so this is a fresh protection set, not a stale dashboard view.
            remaining=await asyncio.to_thread(gateway.releases)
            protected_remote={WebAgentReleaseManager.release_key(dict(row)) for row in remaining if isinstance(row,dict)}
            local=await asyncio.to_thread(
                release_manager.cleanup,
                keep_per_target=keep,
                protected_releases=protected_remote,
                allowed_releases=deleted_remote,
                dry_run=False,
            )
            detail=(
                f"PlanGateway={len(planned)}; Gateway={remote.get('DeletedCount',0)} "
                f"({remote.get('DeletedBytes',0)} bytes); Local={local.get('DeletedCount',0)} "
                f"({local.get('DeletedBytes',0)} bytes); keep={keep}"
            )
            if not bool(local.get("Ok", False)):
                security.audit(identity.username,"releases.cleanup","PARTIAL",detail,request_security.remote_ip(request),resource="releases",role=identity.role)
                raise RuntimeError("El Gateway terminó, pero la limpieza local requiere revisión: " + redact_error(local.get("Failures") or "estado local inconsistente"))
            security.audit(identity.username,"releases.cleanup","SUCCESS",detail,request_security.remote_ip(request),resource="releases",role=identity.role)
        except Exception as exc:
            detail=redact_error(exc)
            security.audit(identity.username,"releases.cleanup","FAILED",detail,request_security.remote_ip(request),resource="releases",role=identity.role)
            raise HTTPException(502,f"No se pudo completar la limpieza segura: {detail}") from exc
        return RedirectResponse("/releases",status_code=303)

    def installers_context(
        *, build_query: str = "", build_status: str = "all", build_sort: str = "created_desc", **extra: Any
    ) -> dict[str, Any]:
        history_all = [dict(row) for row in agent_installers.history(40)]
        history, normalized_query, normalized_status, normalized_sort = filter_installer_history(
            history_all, query=build_query, status=build_status, sort=build_sort,
        )
        active = any(str(x.get("status") or "") in {"QUEUED", "BUILDING"} for x in history_all)
        endpoint_rows = gateway_endpoints.endpoints()
        default_endpoint = gateway_endpoints.default_endpoint()
        context = {
            "title": "Instaladores de Agents",
            "grant": None,
            "signing": security_assets.signing_status(),
            "targets": agent_installers.targets(),
            "builder_catalog": agent_installers.builder_catalog(),
            "sites": agent_installers.sites(),
            "builds": history,
            "build_total_count": len(history_all),
            "build_filtered_count": len(history),
            "build_filter_query": normalized_query,
            "build_filter_status": normalized_status,
            "build_filter_sort": normalized_sort,
            "build_active": active,
            "build_queue": agent_installers.queue_status(),
            "gateway_endpoints": endpoint_rows,
            "gateway_default_endpoint": default_endpoint or {},
            "gateway_default": str((default_endpoint or {}).get("url") or ""),
            "agent_current_version": AGENT_VERSION,
            "error": "",
            "message": "",
        }
        context.update(extra)
        return context

    @app.get("/installers", response_class=HTMLResponse)
    def installers_page(request: Request):
        require(request, "agents.view")
        selected = str(request.query_params.get("build") or "")
        return template(
            request,
            "installers.html",
            installers_context(
                selected_build=selected,
                build_query=str(request.query_params.get("q") or ""),
                build_status=str(request.query_params.get("status") or "all"),
                build_sort=str(request.query_params.get("sort") or "created_desc"),
            ),
        )

    @app.post("/installers/build", response_class=HTMLResponse)
    async def installers_build(request: Request):
        identity = require(request, "agents.operate")
        await validate_csrf(request, identity)
        form = await request.form()
        remote_ip = request_security.remote_ip(request)
        try:
            queued = installer_orchestrator.queue(form, actor=identity.username, remote_ip=remote_ip)
            row = queued["row"]
            target_id = str(queued["target_id"])
            security.audit(
                identity.username,
                "agent_installer.queue",
                "SUCCESS",
                f"Build={row['build_id']}; Target={target_id}; Package={queued['package_choice']}; "
                f"Profile={queued['builder_profile']}; Enrollment={row.get('enrollment_mode','individual')}; "
                f"Uses={row['grant_max_uses']}",
                remote_ip,
                resource=target_id,
                role=identity.role,
            )
            return RedirectResponse(f"/installers?build={row['build_id']}", status_code=303)
        except Exception as exc:
            security.audit(identity.username, "agent_installer.queue", "FAILED", str(exc), remote_ip, role=identity.role)
            return template(request, "installers.html", installers_context(error=str(exc)), 400)


    @app.post("/installers/gateway/test")
    async def installers_gateway_test(request: Request):
        # This endpoint performs server-side network I/O, including for a manual
        # operator-supplied HTTPS URL. Keep it behind the operate permission rather
        # than granting an arbitrary probe primitive to read-only viewers.
        identity = require(request, "agents.operate")
        await validate_csrf(request, identity)
        form = await request.form()
        try:
            endpoint_id = str(form.get("gateway_endpoint_id") or "")
            gateway_mode = str(form.get("gateway_mode") or "production")
            gateway_input = str(form.get("gateway_url") or "")
            resolved_gateway, resolved_mode = gateway_endpoints.resolve_selection(endpoint_id, gateway_input, gateway_mode)
            result = await asyncio.to_thread(
                gateway_endpoints.probe,
                resolved_gateway,
                local_test=(resolved_mode == "local_test"),
            )
            security.audit(identity.username, "gateway.endpoint.test", "SUCCESS" if result.get("status") == "ONLINE" else "FAILED",
                           f"Mode={resolved_mode}; Status={result.get('status')}; Url={resolved_gateway}",
                           request_security.remote_ip(request), resource=resolved_gateway, role=identity.role)
            return result
        except Exception as exc:
            security.audit(identity.username, "gateway.endpoint.test", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return {"status": "ERROR", "tls": "NO_VERIFICADO", "detail": str(exc), "last_checked": dt.datetime.now().astimezone().isoformat(timespec="seconds")}

    @app.post("/installers/gateway/save")
    async def installers_gateway_save(request: Request):
        identity = require(request, "agents.operate")
        await validate_csrf(request, identity)
        form = await request.form()
        try:
            row = gateway_endpoints.save_manual(
                str(form.get("gateway_url") or ""),
                label=str(form.get("gateway_label") or "Gateway manual"),
            )
            security.audit(identity.username, "gateway.endpoint.save", "SUCCESS", f"Url={row['url']}", request_security.remote_ip(request), resource=row["url"], role=identity.role)
            return {"ok": True, **row}
        except Exception as exc:
            security.audit(identity.username, "gateway.endpoint.save", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return {"ok": False, "detail": str(exc)}

    @app.post("/installers/gateway/local-diagnostics")
    async def installers_gateway_local_diagnostics(request: Request):
        identity = require(request, "agents.view")
        await validate_csrf(request, identity)
        result = await asyncio.to_thread(gateway_endpoints.local_diagnostics)
        security.audit(identity.username, "gateway.local_test.diagnostics", "SUCCESS" if result.get("ok") else "ATTENTION",
                       f"Local={result.get('local_url')}; Ok={result.get('ok')}", request_security.remote_ip(request), role=identity.role)
        return result

    @app.get("/installers/builds/{build_id}/download")
    def installers_download(request: Request, build_id: str):
        identity = require(request, "agents.view")
        try:
            path = agent_installers.artifact_path(build_id)
        except (FileNotFoundError, AgentInstallerError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        security.audit(identity.username, "agent_installer.download", "SUCCESS", f"Build={build_id}", request_security.remote_ip(request), resource=path.name, role=identity.role)
        return FileResponse(path, filename=path.name, media_type="application/octet-stream")

    @app.get("/api/v1/installers/builds/{build_id}/artifacts", response_class=JSONResponse)
    def installers_artifacts_api(request: Request, build_id: str):
        require(request, "agents.view")
        try:
            document = agent_installers.artifact_document(build_id)
        except (FileNotFoundError, AgentInstallerError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return JSONResponse(document, headers={"Cache-Control": "no-store"})

    @app.get("/installers/builds/{build_id}/sources/download")
    def installers_source_companion_download(request: Request, build_id: str):
        identity = require(request, "agents.view")
        try:
            path = agent_installers.source_companion_path(build_id)
        except (FileNotFoundError, AgentInstallerError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        security.audit(
            identity.username, "agent_installer.source_companion_download", "SUCCESS", f"Build={build_id}",
            request_security.remote_ip(request), resource=path.name, role=identity.role,
        )
        return FileResponse(path, filename=path.name, media_type="application/zip")

    @app.get("/installers/builds/{build_id}/sources/signature.json")
    def installers_source_companion_signature(request: Request, build_id: str):
        require(request, "agents.view")
        try:
            content = agent_installers.source_companion_signature_document(build_id)
        except (FileNotFoundError, AgentInstallerError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="GIDEON-Agent-{build_id}-source-companion-signature.json"'},
        )

    @app.get("/installers/builds/{build_id}/support.zip")
    def installers_support_bundle(request: Request, build_id: str):
        identity = require(request, "agents.view")
        try:
            path = agent_installers.support_bundle_path(build_id)
        except (FileNotFoundError, AgentInstallerError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        security.audit(
            identity.username, "agent_installer.support_download", "SUCCESS", f"Build={build_id}",
            request_security.remote_ip(request), resource=path.name, role=identity.role,
        )
        return FileResponse(path, filename=path.name, media_type="application/zip")

    @app.get("/installers/builds/{build_id}/signature.json")
    def installers_signature(request: Request, build_id: str):
        require(request, "agents.view")
        try:
            content = agent_installers.signature_document(build_id)
        except (FileNotFoundError, AgentInstallerError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(content=content, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="GIDEON-Agent-{build_id}-signature.json"'})

    @app.post("/installers/builds/{build_id}/revoke-grant")
    async def installers_revoke_grant(request: Request, build_id: str):
        identity=require(request,"agents.operate"); await validate_csrf(request,identity)
        row=agent_installers.get(build_id)
        if row is None: raise HTTPException(404,"Build no encontrado")
        grant_id=str(row.get("grant_id") or "").strip()
        if not grant_id: raise HTTPException(409,"Este build no conserva un GrantId revocable (puede ser anterior a P6).")
        try:
            result = await asyncio.to_thread(
                gateway.revoke_enrollment_grant,
                grant_id,
                reason=f"web-admin:{identity.username}:build:{build_id}",
            )
            agent_installers.mark_grant_revoked(build_id,str(result.get("RevokedAt") or dt.datetime.now().astimezone().isoformat(timespec="seconds")))
            security.audit(identity.username,"enrollment.grant.revoke","SUCCESS",f"Build={build_id}; GrantId={grant_id}",request_security.remote_ip(request),resource=build_id,role=identity.role)
        except Exception as exc:
            security.audit(identity.username,"enrollment.grant.revoke","FAILED",str(exc),request_security.remote_ip(request),resource=build_id,role=identity.role)
            raise HTTPException(409,str(exc))
        return RedirectResponse(f"/installers?build={build_id}",status_code=303)

    @app.post("/installers/grant", response_class=HTMLResponse)
    async def installers_grant(request: Request, ttl_hours: int = Form(24), max_uses: int = Form(1), label: str = Form("web-installer")):
        identity=require(request,"agents.operate"); await validate_csrf(request,identity)
        result = await asyncio.to_thread(
            gateway.issue_enrollment_grant,
            ttl_seconds=max(300,min(int(ttl_hours)*3600,30*86400)),
            max_uses=max(1,min(int(max_uses),100)), label=label,
        )
        security.audit(identity.username,"enrollment.grant","SUCCESS",f"TTL={ttl_hours}h Uses={max_uses}",request_security.remote_ip(request),resource=label,role=identity.role)
        return template(request,"installers.html",installers_context(grant=result))

    @app.get("/gateway",response_class=HTMLResponse)
    def gateway_page(request: Request):
        require(request,"gateway.view")
        try: health=gateway.health(); error=""
        except Exception as exc: health={}; error=f"{type(exc).__name__}: {exc}"
        runtime_configs = gateway_endpoints.discovered_configs()
        return template(request,"gateway.html",{
            "title":"Infraestructura · Gateway",
            "health":health,
            "error":error,
            "web_config":config,
            "gateway_runtime": runtime_configs[0] if runtime_configs else {},
            "gateway_endpoints": gateway_endpoints.endpoints(),
        })


    @app.get("/infrastructure/pki", response_class=HTMLResponse)
    def pki_page(request: Request):
        require(request,"gateway.view")
        try: health=gateway.health(); error=""
        except Exception as exc: health={}; error=f"{type(exc).__name__}: {exc}"
        sec=health.get("Security") if isinstance(health.get("Security"),dict) else {}
        return template(request,"pki.html",{"title":"TLS / PKI","health":health,"security":sec,"error":error,"web_config":config})

    # GIDEON_DEPENDENCY_CENTER_RC30_95_22
    @app.get("/system/dependencies", response_class=HTMLResponse)
    def system_dependencies_page(request: Request):
        require(request, "security_assets.manage")
        report = DependencyInventory(app_root, data_dir).scan()
        return template(request, "dependencies.html", {
            "title": "Entorno y dependencias",
            "dependency_report": report,
        })

    @app.get("/system/dependencies/windows-remediation.ps1", response_class=FileResponse)
    def system_dependencies_windows_script(request: Request):
        require(request, "security_assets.manage")
        path = (app_root / "tools" / "dependencies" / "Install-GIDEONDependencies-Windows.ps1").resolve()
        if not path.is_file():
            raise HTTPException(404, "Remediador Windows no disponible.")
        return FileResponse(str(path), media_type="text/plain", filename="Install-GIDEONDependencies-Windows.ps1")

    @app.get("/system/dependencies/linux-remediation.sh", response_class=FileResponse)
    def system_dependencies_linux_script(request: Request):
        require(request, "security_assets.manage")
        path = (app_root / "tools" / "dependencies" / "install-gideon-dependencies-linux.sh").resolve()
        if not path.is_file():
            raise HTTPException(404, "Remediador Linux no disponible.")
        return FileResponse(str(path), media_type="text/x-shellscript", filename="install-gideon-dependencies-linux.sh")

    @app.get("/system/dependencies/macos-remediation.sh", response_class=FileResponse)
    def system_dependencies_macos_script(request: Request):
        require(request, "security_assets.manage")
        path = (app_root / "tools" / "dependencies" / "install-gideon-dependencies-macos.sh").resolve()
        if not path.is_file():
            raise HTTPException(404, "Remediador macOS no disponible.")
        return FileResponse(str(path), media_type="text/x-shellscript", filename="install-gideon-dependencies-macos.sh")

    @app.get("/system/dependencies/manifest.json", response_class=FileResponse)
    def system_dependencies_manifest(request: Request):
        require(request, "security_assets.manage")
        path = (app_root / "tools" / "dependencies" / "gideon-dependencies.json").resolve()
        if not path.is_file():
            raise HTTPException(404, "Manifest de dependencias no disponible.")
        return FileResponse(str(path), media_type="application/json", filename="gideon-dependencies.json")

    def security_assets_page_context(**extra: Any) -> dict[str, Any]:
        context: dict[str, Any] = {
            "title": "Claves y secretos",
            "asset_status": security_assets.status(),
            "ssh_identities": ssh_vault.list_identities(),
            "ssh_sites": ssh_probe.sites(),
            "remote_credentials": remote_credentials.list_credentials(),
            "guacamole_client": guacamole_assets.status(),
            "guacd_status": guacd.health(),
            "execution_available": operations.execution_available(),
            "recovery_code": "",
            "recovery_expires": "",
            "message": "",
            "error": "",
        }
        context.update(extra)
        return context

    @app.get("/security/assets", response_class=HTMLResponse)
    def security_assets_page(request: Request):
        identity = require(request, "security_assets.manage")
        if identity.role != "SUPERADMIN":
            raise HTTPException(403, "Solo SuperAdmin puede administrar claves y secretos.")
        return template(request, "security_assets.html", security_assets_page_context())

    @app.post("/security/assets/signing/generate", response_class=HTMLResponse)
    async def security_signing_generate(request: Request, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            row = security_assets.generate_signing_key()
            security.audit(identity.username, "security.signing_key.generate", "SUCCESS", f"KeyId={row.get('key_id')}; Fingerprint={row.get('fingerprint')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Clave Ed25519 generada y protegida correctamente."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.signing_key.generate", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/signing/import", response_class=HTMLResponse)
    async def security_signing_import(request: Request, file: UploadFile = File(...), current_password: str = Form(...), mfa_code: str = Form(...), key_passphrase: str = Form("")):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            content = await file.read(MAX_PRIVATE_KEY_BYTES + 1)
            if len(content) > MAX_PRIVATE_KEY_BYTES:
                raise SecurityAssetError("La clave privada excede 64 KiB.")
            row = security_assets.import_signing_key(content, passphrase=key_passphrase)
            security.audit(identity.username, "security.signing_key.import", "SUCCESS", f"KeyId={row.get('key_id')}; Fingerprint={row.get('fingerprint')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Clave Ed25519 importada; la passphrase no se almacenó."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.signing_key.import", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)
        finally:
            await file.close()

    @app.post("/security/assets/signing/external", response_class=HTMLResponse)
    async def security_signing_external(request: Request, external_path: str = Form(...), current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            row = security_assets.configure_external_signing_key(external_path)
            security.audit(identity.username, "security.signing_key.external", "SUCCESS", f"KeyId={row.get('key_id')}; Path={external_path}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Ruta externa de firma configurada y validada."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.signing_key.external", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/signing/test", response_class=HTMLResponse)
    async def security_signing_test(request: Request, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            result = security_assets.test_signing()
            security.audit(identity.username, "security.signing_key.test", "SUCCESS", f"KeyId={result.get('key_id')}; Fingerprint={result.get('fingerprint')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Prueba criptográfica de firma/verificación: OK."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.signing_key.test", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/signing/remove", response_class=HTMLResponse)
    async def security_signing_remove(request: Request, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            security_assets.remove_signing_key()
            security.audit(identity.username, "security.signing_key.remove", "SUCCESS", "Clave de ejecución deshabilitada", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Firma de ejecuciones deshabilitada."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.signing_key.remove", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.get("/security/assets/signing/public.pem")
    def security_signing_public(request: Request):
        require(request, "security_assets.manage")
        content = security_assets.signing_public_key_bytes()
        return Response(content=content, media_type="application/x-pem-file", headers={"Content-Disposition": "attachment; filename=gideon-agent-signing-public.pem"})

    @app.post("/security/assets/ca/upload", response_class=HTMLResponse)
    async def security_ca_upload(request: Request, file: UploadFile = File(...), current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            content = await file.read(MAX_CA_BYTES + 1)
            if len(content) > MAX_CA_BYTES:
                raise SecurityAssetError("El bundle CA excede 2 MiB.")
            row = security_assets.import_gateway_ca(content)
            # Verify the currently configured Gateway immediately; Web stays usable even if it fails.
            try:
                await asyncio.to_thread(gateway.health)
                verify_note = " Gateway verificado correctamente."
            except Exception as verify_exc:
                verify_note = f" CA guardada, pero la verificación del Gateway falló: {verify_exc}"
            security.audit(identity.username, "security.gateway_ca.upload", "SUCCESS", f"Sha256={row.get('sha256')}; Subjects={len(row.get('subjects') or [])}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Bundle CA cargado." + verify_note))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.gateway_ca.upload", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)
        finally:
            await file.close()

    @app.post("/security/assets/ca/disable", response_class=HTMLResponse)
    async def security_ca_disable(request: Request, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            security_assets.disable_gateway_ca_override()
            # Return to the installation-configured CA without rewriting config files.
            config["gateway_ca_file"] = str(load_web_config(path).get("gateway_ca_file") or "")
            security.audit(identity.username, "security.gateway_ca.disable", "SUCCESS", "Override CA desactivado", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Override CA desactivado; se usa la CA configurada por la instalación."))
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/yara/upload", response_class=HTMLResponse)
    async def security_yara_upload(request: Request, file: UploadFile = File(...), current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            content = await file.read(MAX_YARA_BYTES + 1)
            if len(content) > MAX_YARA_BYTES:
                raise SecurityAssetError("Las reglas YARA exceden 1 MiB.")
            row = security_assets.import_yara_rules(content)
            security.audit(identity.username, "security.yara.upload", "SUCCESS", f"Sha256={row.get('sha256')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Política YARA cargada. GIDEON no modificó servicios ni configuración global de YARA."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.yara.upload", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)
        finally:
            await file.close()

    @app.post("/security/assets/yara/disable", response_class=HTMLResponse)
    async def security_yara_disable(request: Request, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            security_assets.disable_yara()
            config["yara_rules_file"] = str(load_web_config(path).get("yara_rules_file") or "")
            security.audit(identity.username, "security.yara.disable", "SUCCESS", "YARA administrado por Web desactivado", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Política YARA administrada por Web desactivada."))
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/ssh-public/upload", response_class=HTMLResponse)
    async def security_ssh_public_upload(request: Request, file: UploadFile = File(...), label: str = Form("SSH public key"), current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            content = await file.read(MAX_SSH_PUBLIC_KEY_BYTES + 1)
            if len(content) > MAX_SSH_PUBLIC_KEY_BYTES:
                raise SecurityAssetError("La clave pública SSH excede 64 KiB.")
            row = security_assets.import_ssh_public_key(content, label=label)
            security.audit(identity.username, "security.ssh_public.upload", "SUCCESS", f"Id={row.get('id')}; Fingerprint={row.get('fingerprint')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Clave pública SSH registrada. No se modificó sshd ni authorized_keys del sistema."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.ssh_public.upload", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)
        finally:
            await file.close()

    @app.post("/security/assets/ssh-identity/upload", response_class=HTMLResponse)
    async def security_ssh_identity_upload(request: Request, file: UploadFile = File(...), label: str = Form("Administración GIDEON"), key_passphrase: str = Form(""), current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            content = await file.read(MAX_SSH_PRIVATE_KEY_BYTES + 1)
            if len(content) > MAX_SSH_PRIVATE_KEY_BYTES:
                raise SshVaultError("La clave SSH privada excede 128 KiB.")
            row = ssh_vault.import_identity(content, label=label, passphrase=key_passphrase)
            security.audit(identity.username, "security.ssh_identity.upload", "SUCCESS", f"Id={row.get('id')}; Fingerprint={row.get('fingerprint')}; Type={row.get('key_type')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Identidad SSH cifrada y registrada en el vault GIDEON. No se modificó ssh-agent, sshd ni authorized_keys."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.ssh_identity.upload", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)
        finally:
            await file.close()

    @app.post("/security/assets/ssh-identity/folder-upload", response_class=HTMLResponse)
    async def security_ssh_identity_folder_upload(
        request: Request,
        files: list[UploadFile] = File(...),
        label: str = Form("Administración GIDEON"),
        key_passphrase: str = Form(""),
        current_password: str = Form(...),
        mfa_code: str = Form(...),
    ):
        """Import private SSH identities selected from a client-side folder.

        Browsers do not reveal a workstation folder path to the server.  The
        webkitdirectory control sends the selected files instead.  GIDEON inspects
        them in memory, ignores public/config/known_hosts material and persists
        only successfully parsed private keys encrypted in the vault.
        """
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        uploaded = list(files or [])
        results: list[str] = []
        imported = 0
        skipped = 0
        failed = 0
        total_bytes = 0
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            if not uploaded:
                raise SshVaultError("Seleccione una carpeta que contenga al menos una identidad SSH.")
            if len(uploaded) > MAX_SSH_FOLDER_FILES:
                raise SshVaultError(f"La carpeta contiene demasiados archivos. Máximo permitido: {MAX_SSH_FOLDER_FILES}.")
            base_label = str(label or "Administración GIDEON").strip()[:90] or "Administración GIDEON"
            for upload in uploaded:
                filename = Path(str(upload.filename or "clave-ssh").replace("\\", "/")).name[:120]
                content = await upload.read(MAX_SSH_PRIVATE_KEY_BYTES + 1)
                total_bytes += len(content)
                if total_bytes > MAX_SSH_FOLDER_TOTAL_BYTES:
                    raise SshVaultError("La selección de carpeta excede el límite total seguro de 2 MiB.")
                if len(content) > MAX_SSH_PRIVATE_KEY_BYTES:
                    failed += 1
                    results.append(f"{filename}: rechazado (más de 128 KiB)")
                    continue
                kind = classify_private_key_blob(content)
                if kind in {"empty", "other", "public-key"}:
                    skipped += 1
                    continue
                if kind == "putty-ppk":
                    failed += 1
                    results.append(f"{filename}: PPK detectado; expórtelo como OpenSSH/PEM")
                    continue
                try:
                    key_label = f"{base_label} · {filename}" if len(uploaded) > 1 else base_label
                    row = ssh_vault.import_identity(content, label=key_label, passphrase=key_passphrase)
                    imported += 1
                    results.append(f"{filename}: {row.get('key_type')} · {row.get('fingerprint')}")
                except Exception as exc:
                    failed += 1
                    results.append(f"{filename}: {redact_error(exc)}")
            if imported == 0:
                detail = "; ".join(results[:6]) or "No se detectaron claves privadas OpenSSH/PEM en la carpeta."
                raise SshVaultError(detail)
            security.audit(
                identity.username, "security.ssh_identity.folder_upload", "SUCCESS",
                f"Imported={imported}; Skipped={skipped}; Failed={failed}",
                request_security.remote_ip(request), role=identity.role,
            )
            suffix = f" Se omitieron {skipped} archivo(s) que no eran claves privadas." if skipped else ""
            if failed:
                suffix += f" {failed} archivo(s) no pudieron importarse; revise el detalle mostrado."
            return template(
                request, "security_assets.html",
                security_assets_page_context(
                    message=f"{imported} identidad(es) SSH cifrada(s) e importada(s) desde la carpeta.{suffix}",
                    ssh_import_results=results[:20],
                ),
            )
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(
                identity.username, "security.ssh_identity.folder_upload", "FAILED", redact_error(exc),
                request_security.remote_ip(request), role=identity.role,
            )
            return template(
                request, "security_assets.html",
                security_assets_page_context(error=str(exc), ssh_import_results=results[:20]),
                400,
            )
        finally:
            for upload in uploaded:
                try:
                    await upload.close()
                except Exception:
                    pass

    @app.post("/security/assets/ssh-identity/{identity_id}/test", response_class=HTMLResponse)
    async def security_ssh_identity_test(request: Request, identity_id: str, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            row = await asyncio.to_thread(ssh_vault.test_identity, identity_id)
            security.audit(identity.username, "security.ssh_identity.test", "SUCCESS", f"Id={row.get('id')}; Fingerprint={row.get('fingerprint')}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message=f"Identidad SSH validada: {row.get('key_type')} · {row.get('fingerprint')}"))
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/ssh-identity/{identity_id}/probe", response_class=HTMLResponse)
    async def security_ssh_identity_probe(
        request: Request,
        identity_id: str,
        site_code: str = Form(...),
        username: str = Form(""),
        port: int = Form(22),
        username_override: str = Form(""),
        port_override: str = Form(""),
        current_password: str = Form(""),
        mfa_code: str = Form(""),
    ):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)

            effective_username = str(username_override or "").strip() or str(username or "").strip() or "damautapp"
            raw_port = str(port_override or "").strip()
            effective_port = int(raw_port) if raw_port else int(port or 22)

            row = await asyncio.to_thread(
                ssh_probe.probe,
                identity_id=identity_id,
                site_code=site_code,
                username=effective_username,
                port=effective_port,
                require_sftp=True,
            )
            if row.get("ok"):
                ssh_vault.set_connection_defaults(
                    identity_id,
                    username=effective_username,
                    port=effective_port,
                    verified_site_code=site_code,
                    ssh_ok=True,
                    sftp_ok=True,
                )
            outcome = "SUCCESS" if row.get("ok") else "FAILED"
            ssh_row = row.get("ssh") if isinstance(row.get("ssh"), dict) else {}
            sftp_row = row.get("sftp") if isinstance(row.get("sftp"), dict) else {}
            security.audit(
                identity.username,
                "security.ssh_identity.probe",
                outcome,
                f"Id={identity_id}; Site={site_code}; Host={row.get('host')}; Port={row.get('port')}; "
                f"User={row.get('username')}; SSH={ssh_row.get('returncode')}; SFTP={sftp_row.get('returncode')}",
                request_security.remote_ip(request),
                resource=site_code,
                role=identity.role,
            )
            message = (
                f"Prueba SSH/SFTP {'correcta. Perfil SSH global guardado' if row.get('ok') else 'fallida'} · "
                f"{row.get('site_code')} {row.get('site_name')} · {row.get('username')}@{row.get('host')}:{row.get('port')} · "
                f"{row.get('detail')}"
            )
            context = security_assets_page_context(message=message) if row.get("ok") else security_assets_page_context(error=message)
            # RC30.95.25.3: return one HTMLResponse with its real HTTP status.
            # Returning (HTMLResponse, status_code) makes FastAPI/Starlette try
            # to serialize a tuple as HTML and results in a raw HTTP 500.
            return template(request, "security_assets.html", context, 200 if row.get("ok") else 400)
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(
                identity.username,
                "security.ssh_identity.probe",
                "FAILED",
                redact_error(exc),
                request_security.remote_ip(request),
                resource=site_code,
                role=identity.role,
            )
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/ssh-identity/{identity_id}/delete", response_class=HTMLResponse)
    async def security_ssh_identity_delete(request: Request, identity_id: str, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            ssh_vault.delete_identity(identity_id)
            security.audit(identity.username, "security.ssh_identity.delete", "SUCCESS", f"Id={identity_id}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Identidad SSH eliminada del vault GIDEON."))
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/ssh-public/{key_id}/delete", response_class=HTMLResponse)
    async def security_ssh_public_delete(request: Request, key_id: str, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            security_assets.delete_ssh_public_key(key_id)
            security.audit(identity.username, "security.ssh_public.delete", "SUCCESS", f"Id={key_id}", request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(message="Clave pública SSH eliminada del repositorio GIDEON."))
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/remote-credential", response_class=HTMLResponse)
    async def security_remote_credential_create(request: Request):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        try:
            await require_superadmin_step_up_async(
                request,
                identity,
                str(form.get("current_password") or ""),
                str(form.get("mfa_code") or ""),
                resource="remote-credential-create",
            )
            row = remote_credentials.create(
                protocol=str(form.get("protocol") or "RDP"),
                label=str(form.get("label") or ""),
                username=str(form.get("username") or ""),
                domain=str(form.get("domain") or ""),
                password=str(form.get("remote_password") or ""),
            )
            security.audit(
                identity.username,
                "security.remote_credential.create",
                "SUCCESS",
                f"Id={row.get('id')}; Protocol={row.get('protocol')}; Label={row.get('label')}",
                request_security.remote_ip(request),
                resource=str(row.get("id") or ""),
                role=identity.role,
            )
            return template(request, "security_assets.html", security_assets_page_context(message="Credencial remota cifrada y almacenada en el vault GIDEON."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.remote_credential.create", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/remote-credential/{credential_id}/delete", response_class=HTMLResponse)
    async def security_remote_credential_delete(request: Request, credential_id: str):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        try:
            await require_superadmin_step_up_async(
                request,
                identity,
                str(form.get("current_password") or ""),
                str(form.get("mfa_code") or ""),
                resource="remote-credential-delete",
            )
            row = remote_credentials.delete(credential_id)
            security.audit(
                identity.username,
                "security.remote_credential.delete",
                "SUCCESS",
                f"Protocol={row.get('protocol')}; Label={row.get('label')}",
                request_security.remote_ip(request),
                resource=credential_id,
                role=identity.role,
            )
            return template(request, "security_assets.html", security_assets_page_context(message="Credencial remota eliminada."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.remote_credential.delete", "FAILED", str(exc), request_security.remote_ip(request), resource=credential_id, role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.post("/security/assets/guacamole-client/upload", response_class=HTMLResponse)
    async def security_guacamole_client_upload(request: Request, file: UploadFile = File(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        form = await request.form()
        try:
            await require_superadmin_step_up_async(
                request,
                identity,
                str(form.get("current_password") or ""),
                str(form.get("mfa_code") or ""),
                resource="guacamole-client-js",
            )
            content = await file.read(MAX_GUAC_CLIENT_JS_BYTES + 1)
            if len(content) > MAX_GUAC_CLIENT_JS_BYTES:
                raise GuacamoleError("guacamole-common-js excede 4 MiB.")
            row = guacamole_assets.install(
                content,
                version=str(form.get("client_version") or ""),
                expected_sha256=str(form.get("expected_sha256") or ""),
            )
            security.audit(
                identity.username,
                "security.guacamole_client.install",
                "SUCCESS",
                f"Version={row.get('version') or '-'}; Sha256={row.get('sha256')}; Bytes={row.get('size_bytes')}",
                request_security.remote_ip(request),
                resource="guacamole-common-js",
                role=identity.role,
            )
            return template(request, "security_assets.html", security_assets_page_context(message="Cliente Guacamole Web instalado y validado."))
        except HTTPException:
            raise
        except Exception as exc:
            security.audit(identity.username, "security.guacamole_client.install", "FAILED", str(exc), request_security.remote_ip(request), role=identity.role)
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)
        finally:
            await file.close()

    @app.post("/security/assets/recovery-code", response_class=HTMLResponse)
    async def security_recovery_code(request: Request, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "security_assets.manage")
        await validate_csrf(request, identity)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            code, expires = security.generate_recovery_code(identity.user_id, actor=identity.username, remote_ip=request_security.remote_ip(request))
            return template(request, "security_assets.html", security_assets_page_context(recovery_code=code, recovery_expires=expires, message="Código de recuperación generado. Se muestra una sola vez."))
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "security_assets.html", security_assets_page_context(error=str(exc)), 400)

    @app.get("/diagnostics", response_class=HTMLResponse)
    def diagnostics_page(request: Request):
        require(request,"diagnostics.view")
        agent_rows=[]
        try:
            ttl=int(config.get("agent_online_ttl_seconds",90))
            for row in gateway.agents():
                item=dict(row)
                item["_state"]=effective_state(item,ttl_seconds=ttl)
                agent_rows.append(item)
        except Exception:
            agent_rows=[]
        return template(request,"diagnostics.html",{
            "title":"Diagnóstico",
            "control_plane": operations.control_plane_health(stale_after_seconds=int(config.get("diagnostics_stale_after_seconds",45))),
            "checks":operations.diagnostics(),
            "agents":agent_rows,
        })

    @app.get("/sessions", response_class=HTMLResponse)
    def sessions_page(request: Request):
        require(request,"sessions.view")
        return template(request,"sessions.html",{"title":"Sesiones","sessions":security.list_sessions()})

    @app.post("/sessions/{session_id}/revoke")
    async def sessions_revoke(request: Request, session_id: int):
        identity=require(request,"sessions.manage"); await validate_csrf(request,identity)
        security.revoke_session(session_id,actor=identity.username,remote_ip=request_security.remote_ip(request))
        return RedirectResponse("/sessions",303)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        require(request,"settings.view")
        return template(request,"settings.html",{
            "title":"Configuración",
            "settings":operations.safe_settings(),
            "runtime":runtime_settings.load(),
        })

    @app.post("/settings/runtime", response_class=HTMLResponse)
    async def settings_runtime(
        request: Request,
        backup_enabled: str = Form(""),
        backup_destination_type: str = Form("local"),
        backup_destination: str = Form(""),
        backup_retention_days: int = Form(14),
        smtp_enabled: str = Form(""),
        smtp_host: str = Form(""),
        smtp_port: int = Form(587),
        smtp_username: str = Form(""),
        smtp_from: str = Form(""),
    ):
        identity=require(request,"settings.view")
        if identity.role != "SUPERADMIN":
            raise HTTPException(403,"Solo SuperAdmin puede modificar la configuración operativa.")
        await validate_csrf(request,identity)
        values = runtime_settings.update({
            "backup_enabled": str(backup_enabled).lower() in {"1","true","yes","on"},
            "backup_destination_type": backup_destination_type,
            "backup_destination": backup_destination,
            "backup_retention_days": backup_retention_days,
            "smtp_enabled": str(smtp_enabled).lower() in {"1","true","yes","on"},
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_username": smtp_username,
            "smtp_from": smtp_from,
        })
        security.audit(identity.username,"settings.runtime","SUCCESS",f"Backup={values.get('backup_destination_type')}; SMTP={values.get('smtp_enabled')}",request_security.remote_ip(request),role=identity.role)
        if request.headers.get("x-gideon-ajax", "").strip() == "1":
            return JSONResponse({"ok": True, "message": "Configuración operativa guardada correctamente."})
        return RedirectResponse("/settings",303)

    @app.get("/audit",response_class=HTMLResponse)
    def audit_page(request: Request):
        require(request,"audit.view"); return template(request,"audit.html",{"title":"Auditoría","events":security.list_audit(500)})

    @app.get("/users",response_class=HTMLResponse)
    def users_page(request: Request):
        require(request,"users.view"); return template(request,"users.html",{"title":"Usuarios y roles","users":security.list_users(),"temporary_password":"","reset_error":""})

    @app.post("/users/create")
    async def users_create(request: Request, username: str=Form(...),display_name: str=Form(...),password: str=Form(...),role: str=Form(...)):
        identity=require(request,"users.view");
        if identity.role!="SUPERADMIN": raise HTTPException(403,"Solo SuperAdmin puede crear usuarios.")
        await validate_csrf(request, identity)
        await asyncio.to_thread(
            security.create_user,
            username,
            display_name,
            password,
            role,
            actor=identity.username,
            remote_ip=request_security.remote_ip(request),
        )
        return RedirectResponse("/users", 303)

    @app.post("/users/{user_id}/active")
    async def users_active(request: Request,user_id:int,active:str=Form(...)):
        identity=require(request,"users.view");
        if identity.role!="SUPERADMIN": raise HTTPException(403,"Solo SuperAdmin puede modificar cuentas.")
        await validate_csrf(request,identity); security.set_user_active(user_id,str(active).lower() in {"1","true","yes","on"},actor=identity.username,remote_ip=request_security.remote_ip(request)); return RedirectResponse("/users",303)

    @app.post("/users/{user_id}/reset-password", response_class=HTMLResponse)
    async def users_reset_password(request: Request, user_id: int, current_password: str = Form(...), mfa_code: str = Form(...)):
        identity = require(request, "users.view")
        await validate_csrf(request, identity)
        if identity.role != "SUPERADMIN":
            raise HTTPException(403, "Solo SuperAdmin puede restablecer contraseñas.")
        if int(user_id) == int(identity.user_id):
            return template(request, "users.html", {"title":"Usuarios y roles", "users":security.list_users(), "temporary_password":"", "reset_error":"Para su propia cuenta use Cambiar contraseña o genere un código de recuperación."}, 400)
        try:
            await require_superadmin_step_up_async(request, identity, current_password, mfa_code)
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
            temporary = "Gideon#" + "".join(secrets.choice(alphabet) for _ in range(18))
            await asyncio.to_thread(
                security.reset_password,
                user_id,
                temporary,
                actor=identity.username,
                remote_ip=request_security.remote_ip(request),
            )
            return template(request, "users.html", {"title":"Usuarios y roles", "users":security.list_users(), "temporary_password":temporary, "reset_error":""})
        except HTTPException:
            raise
        except Exception as exc:
            return template(request, "users.html", {"title":"Usuarios y roles", "users":security.list_users(), "temporary_password":"", "reset_error":str(exc)}, 400)

    @app.get("/account/recovery", response_class=HTMLResponse)
    def recovery_page(request: Request):
        return template(request, "recovery.html", {"title":"Recuperar acceso", "error":"", "success":""})

    @app.post("/account/recovery", response_class=HTMLResponse)
    def recovery_submit(request: Request, username: str = Form(...), recovery_code: str = Form(...), new_password: str = Form(...), confirm: str = Form(...)):
        ip = request_security.remote_ip(request)
        if not login_limiter.check(ip).allowed:
            return template(request, "recovery.html", {"title":"Recuperar acceso", "error":"Demasiados intentos. Intente más tarde.", "success":""}, 429)
        if new_password != confirm:
            login_limiter.failure(ip)
            return template(request, "recovery.html", {"title":"Recuperar acceso", "error":"Las contraseñas no coinciden.", "success":""}, 400)
        try:
            ok = security.recover_password_with_code(username, recovery_code, new_password, remote_ip=ip)
        except Exception as exc:
            login_limiter.failure(ip)
            return template(request, "recovery.html", {"title":"Recuperar acceso", "error":str(exc), "success":""}, 400)
        if not ok:
            login_limiter.failure(ip)
            security.audit(str(username or ""), "account.recovery_password", "FAILED", "Código inválido/expirado", ip, role="RECOVERY")
            return template(request, "recovery.html", {"title":"Recuperar acceso", "error":"Código de recuperación inválido o expirado.", "success":""}, 400)
        login_limiter.success(ip)
        return template(request, "recovery.html", {"title":"Recuperar acceso", "error":"", "success":"Contraseña restablecida. Inicie sesión; MFA continúa siendo obligatorio."})

    @app.get("/account/mfa/setup",response_class=HTMLResponse)
    def mfa_setup_page(request: Request):
        identity=current_identity(request, allow_incomplete=True)
        if identity is None: return RedirectResponse("/login",303)
        secret=security.get_mfa_secret(identity.user_id) or security.begin_mfa_setup(identity.user_id)
        uri=security.otpauth_uri(secret,identity.username)
        return template(request,"mfa_setup.html",{"title":"Configurar MFA","secret":secret,"uri":uri,"error":""})

    @app.post("/account/mfa/setup",response_class=HTMLResponse)
    async def mfa_setup_submit(request: Request,code:str=Form(...)):
        identity=current_identity(request, allow_incomplete=True)
        if identity is None: return RedirectResponse("/login",303)
        await validate_csrf(request, identity)
        if not security.enable_mfa(identity.user_id,code):
            secret=security.get_mfa_secret(identity.user_id); return template(request,"mfa_setup.html",{"title":"Configurar MFA","secret":secret,"uri":security.otpauth_uri(secret,identity.username),"error":"Código inválido."},400)
        rotated = security.rotate_session(request.cookies.get(SESSION_COOKIE, ""), mfa_complete=True)
        if rotated is None:
            return RedirectResponse("/login", 303)
        security.audit(identity.username,"account.mfa_enable","SUCCESS","MFA habilitado; sesión rotada",request_security.remote_ip(request),role=identity.role)
        response = RedirectResponse("/",303)
        set_session_cookie(response, rotated[0])
        return response

    @app.get("/account/password",response_class=HTMLResponse)
    def password_page(request: Request):
        identity=current_identity(request, allow_incomplete=True)
        if identity is None: return RedirectResponse("/login",303)
        return template(request,"password.html",{"title":"Cambiar contraseña","error":""})

    @app.post("/account/password",response_class=HTMLResponse)
    async def password_submit(request: Request,current:str=Form(...),new:str=Form(...),confirm:str=Form(...)):
        identity=current_identity(request, allow_incomplete=True)
        if identity is None: return RedirectResponse("/login",303)
        await validate_csrf(request, identity)
        if new!=confirm: return template(request,"password.html",{"title":"Cambiar contraseña","error":"Las contraseñas no coinciden."},400)
        try:
            await asyncio.to_thread(
                security.change_own_password,
                identity.user_id,
                current,
                new,
                actor=identity.username,
                remote_ip=request_security.remote_ip(request),
            )
        except Exception as exc:
            return template(request,"password.html",{"title":"Cambiar contraseña","error":str(exc)},400)
        rotated = security.rotate_session(request.cookies.get(SESSION_COOKIE, ""), mfa_complete=identity.mfa_complete)
        if rotated is None:
            return RedirectResponse("/login",303)
        response = RedirectResponse("/",303)
        set_session_cookie(response, rotated[0])
        return response

    return app
