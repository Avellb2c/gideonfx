# RC30 Validation

- `PRODUCT_VERSION == 6.3.4-rc30`.
- `AGENT_VERSION == 2.4.56`.
- `GATEWAY_VERSION == 2.4.3`.
- Full installer/runtime regression: **378 tests executed, 374 PASS and 4 expected skips**; the focused Wayland/campaign/manifest set contributes **76 PASS**.
- Latest bounded regression: **42 focused checks PASS, 2 expected Linux-only skips** (runtime handoff, display capability and signed Player manifest).
- Ubuntu WSL: **29 platform-contract tests + 16 Player/Gateway reissue and migration tests PASS**, including POSIX permissions, ZIP executable-mode recovery, DEB permissions and repeated signed manifest states.
- `python -m compileall`: **PASS**.
- `RELEASE-MANIFEST.json`: **PASS** after regeneration.
- `INSTALL-INTEGRITY-MANIFEST.json`: **PASS** after regeneration.
- Regression: older WebAdmin config without `remote_sessions.allowed_target_cidrs` loads explicit private CIDR defaults and does not raise a dataclass `member_descriptor` error.
- Regression: forced Remote Sessions boot failure degrades only that module while `create_app()` remains constructible.
- Regression: Windows Agent installer contains no `Invoke-WebRequest`, endpoint Python fallback or pip-install path; incomplete private runtime fails closed.
- Regression: legacy Agent installer discovers prior Program Files/ProgramData/registry/task installations and preserves reusable identity/token data.
- Existing Fleet Scale behavior remains covered: active-job backpressure, 90-target queue semantics, Gateway resilience and remote restart.
- Existing Guacamole security behavior remains covered: private target policy, one-shot tickets, Same-Origin WebSocket, credential vault and session limits.
- RC30 does not intentionally modify Defender, global OpenSSH/ssh-agent, Firewall/UFW, VPN/routing or unrelated services.
