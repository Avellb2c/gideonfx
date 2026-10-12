# GIDEON Remote Control 6.3.4-rc30

RC30 is the stabilization release for the current GIDEON Remote Control architecture. It retains browser RDP/VNC through Apache Guacamole, Fleet Scale, Agents, host-list SSH/SFTP execution, scripts, file transfer, remote restart and stable Agent releases, while hardening WebAdmin startup and Windows Agent installation.

## Components

- Control Plane: **6.3.4-rc30**
- Agent: **2.4.56**
- Gateway: **2.4.3**
- Agent protocol: **2.0**

## WebAdmin resilience

WebAdmin now treats optional subsystems as degradable features. Remote Sessions/Guacamole and stable Agent release storage cannot prevent the core API from serving when their own local initialization fails. `/healthz` remains a local readiness endpoint and reports per-module state without making Gateway or guacd network calls.

RC30 also fixes older `web_admin.json` compatibility for `remote_sessions.allowed_target_cidrs`: missing values use explicit private-network defaults instead of reading a `slots=True` dataclass member descriptor.

On Windows, WebAdmin selects the Selector event-loop policy before application creation to isolate normal browser/proxy connection resets from the application lifecycle.

## Agent 2.4.56 — self-contained installers

The Windows Agent installer is fail-closed. The generated installer must contain the complete private CPython runtime plus its manifest and dependencies. A clean endpoint does **not** need Python, `py.exe`, pip or Internet access.

Player 1.2.0 distinguishes a real DRM/HDMI connector from a verified local Wayland compositor output. Raspberry Pi Connect/WayVNC can therefore target the visible local `NOOP-*` desktop only when the signed campaign explicitly selects “Sesión Wayland local”; it is never treated as proof of an electrically connected HDMI panel.

If an older GIDEON Agent already exists, the installer detects Program Files/ProgramData/registry/task locations and preserves the reusable Agent identity, token, site and Gateway configuration during repair/upgrade. It requests enrollment data only if no valid prior identity is available.

## Fleet Scale

Large campaigns are queued rather than started without control. The current default is **20 active Jobs** at a time; the remainder stays `QUEUED` until capacity becomes available. Gateway TLS handshake isolation, Agent polling/heartbeat jitter, transactional claiming and WebAdmin cache/circuit breaker remain enabled.

## Remote Sessions / Apache Guacamole

Topology: `Browser -> WSS/WebAdmin -> Remote Session Broker -> guacd:4822 private -> RDP/VNC -> target`.

Targets can come from enrolled Agents or separate inventory host lists. Credentials remain in the GIDEON remote-credential vault; the browser receives only an ephemeral one-use session ticket. Same-Origin WebSocket checks, MFA/RBAC step-up and per-user/per-target/global limits remain enforced. `guacd` is intended to remain loopback/private and is never exposed directly to users.

## Security and isolation

RC30 preserves Ed25519/SHA-256 verification, replay/freshness controls, MFA, RBAC and audit. The update does not intentionally modify Defender, global OpenSSH/ssh-agent, Firewall/UFW, VPN routes, ports 22/443 or third-party services.

See `RELEASE-NOTES-6.3.4-rc30.md`, `CHANGELOG.md`, `VALIDATION.md`, and `docs/GUACAMOLE-REMOTE-ACCESS.md`.
