# GIDEON Remote Control 6.3.4-rc30 — Stabilization / Self-contained Runtime

RC30 is a stabilization release after the RC28/RC29 Guacamole rollout. It keeps Remote Sessions, Fleet Scale, Agentless SSH/SFTP, remote restart, stable Agent releases and the existing security controls, while removing startup and endpoint-runtime assumptions that were exposed during the Windows pilot.

## WebAdmin startup resilience

- Fixes backward compatibility in `RemoteSessionPolicy.from_config()` for older `web_admin.json` files that do not contain `remote_sessions.allowed_target_cidrs`.
- `RemoteSessionPolicy` no longer reads dataclass slot descriptors as runtime defaults; missing CIDRs use explicit private-network defaults and invalid values fail only the Remote Sessions module.
- Remote Sessions/Guacamole boot is fail-safe: an SQLite/Vault/config/guacd initialization problem marks the feature `DEGRADED` instead of taking down login, Agents, Jobs, Scripts, Transfers or Updates.
- Agent stable-release storage is also optional at boot; an unavailable release directory degrades release management only.
- `/healthz` is local/readiness-oriented, does not depend on Gateway or guacd network calls, and exposes per-module READY/DEGRADED/DISABLED state.

## Windows socket resilience

- WebAdmin selects `WindowsSelectorEventLoopPolicy` on Windows before creating the FastAPI application. This avoids noisy Proactor callback tracebacks such as `ConnectionResetError [WinError 10054]` when browsers or proxies reset TLS connections.
- A client disconnect is treated as a connection lifecycle event rather than an application-fatal condition.

## Agent 2.4.24 / Gateway 2.4.2 — clean-PC and in-place upgrade hardening

- The generated Windows Agent installer is fail-closed and requires the private CPython payload included by the trusted Agent builder.
- Endpoint installation never falls back to global `py.exe`, global `python.exe`, `pip`, or an Internet download.
- The runtime is verified against `runtime-manifest.json` before the Agent is configured or a task is registered.
- Existing installations are discovered across Program Files, ProgramData, Program Files (x86), registry uninstall metadata and the scheduled task.
- A valid existing Agent identity/configuration is migrated or repaired in-place while preserving AgentId/token/site/Gateway settings; the installer asks for enrollment information only when no reusable identity exists.
- The legacy bundle follows the same fail-closed private-runtime and in-place-upgrade policy.

## Fleet, jobs and remote control retained

- Fleet Scale keeps the default global active-job limit of 20; larger campaigns (including 90 targets) remain queued and consume slots as work completes.
- Gateway TLS handshake isolation, Agent jitter, WebAdmin stale-cache/circuit-breaker behavior and transactional job claiming remain enabled.
- Remote reboot remains an audited signed Agent job.
- Guacamole continues to support both enrolled Agents and inventory host lists through a private guacd connection, ephemeral session tickets, RBAC/MFA, credential vaulting and session limits.

## Release lifecycle retained

- Stable Agent build, publish, approval, distribution and rollback compatibility introduced in RC25 remain available.
- RC30 release-management initialization cannot prevent WebAdmin startup.

## Security / isolation

RC30 does not disable Ed25519, SHA-256, freshness/replay checks, MFA, RBAC or audit. It does not modify Defender, global OpenSSH/ssh-agent, Windows Firewall/UFW, VPN routes, ports 22/443 or third-party services as part of this update.
