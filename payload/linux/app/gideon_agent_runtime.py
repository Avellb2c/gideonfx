from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

_RUNTIME_KEYS = (
    "public_url",
    "admin_api_key_env",
    "admin_api_key",
    "ca_file",
    "tls_trust_bundle_file",
    "tls_ca_fingerprint",
    "tls_cert_fingerprint",
    "network_mode",
    "test_host",
    "production_host",
)


def merged_agent_control_plane(config: Mapping[str, object]) -> dict[str, Any]:
    """Return Agent control-plane settings enriched with local Gateway runtime state.

    Release config stays secret-free. If this controller also hosts/manages the
    Gateway, its persistent runtime config supplies the generated admin token and
    private-CA path. On a separate controller, the token can still be supplied by
    the configured environment variable and the public CA bundle by config.
    """

    raw = config.get("agent_control_plane")
    merged = dict(raw) if isinstance(raw, Mapping) else {}
    # Headless Web/Admin may intentionally target a different/private Gateway
    # than a desktop controller runtime present on the same filesystem.
    if bool(config.get("ignore_local_gateway_runtime", False)):
        return merged
    try:
        # Import lazily: gideon_gateway_bootstrap depends on gideon_infrastructure.
        # Keeping this import out of module initialization prevents a bootstrap
        # cycle when AGENT_HTTPS_PULL loads the file transport package.
        from gideon_gateway_bootstrap import GATEWAY_CONFIG_PATH

        path = Path(GATEWAY_CONFIG_PATH)
        if path.is_file():
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            runtime = value if isinstance(value, dict) else {}
        else:
            runtime = {}
    except Exception:
        runtime = {}

    for key in _RUNTIME_KEYS:
        if runtime.get(key) not in (None, ""):
            merged[key] = runtime[key]
    if runtime.get("public_url"):
        merged["base_url"] = runtime["public_url"]
    return merged


def agent_gateway_connection_label(config: Mapping[str, object], *, observed_ip: str = "") -> str:
    """Human-readable Agent route.

    Agent jobs/files are never pushed to a store/server IP.  The Agent opens an
    outbound HTTPS connection to the Gateway and pulls queued work.  The
    optional observed IP is telemetry only (often NAT/public egress) and must
    never be used as a dispatch target.
    """

    cfg = merged_agent_control_plane(config)
    base = str(cfg.get("base_url") or cfg.get("public_url") or "").strip()
    endpoint = "Gateway"
    if base:
        try:
            parsed = urlparse(base if "://" in base else f"https://{base}")
            endpoint = parsed.netloc or parsed.path or "Gateway"
        except Exception:
            endpoint = base
    label = f"HTTPS/PULL → {endpoint}"
    remote = str(observed_ip or "").strip()
    if remote:
        label += f" · origen observado {remote}"
    return label
