# Changelog

## Agent 2.4.31 — Production update delivery

- Increments the Agent patch so endpoints already on 2.4.30 can receive the reviewed RC30.96.2 runtime changes through the signed update channel.
- Keeps identity, enrollment, control-plane trust and mTLS material intact during the in-place update.

## 6.3.4-rc30 — Stabilization / Agent 2.4.30 / Gateway 2.4.2

- VNC explicitly suppresses server-side display resizing. Raspberry Pi physical-console sessions keep the WayVNC output fixed while WebAdmin fits the image locally, avoiding a resize request that can destabilize the protected Raspberry Pi Connect socket.

- Raspberry/WayVNC sessions now use Guacamole's local cursor, browser pointer motion is coalesced to the paint cadence, and reverse-tunnel writes survive transient socket backpressure without corrupting a partial WebSocket frame.
- Agent updates now defer while an RDP/VNC stream is active or opening; an atomic tunnel quiesce prevents the updater from racing a newly started remote session and disconnecting the operator.
- Agent 2.4.29 serializes TLS reads and writes on every reverse-tunnel control channel, preventing the Raspberry/WayVNC control stream from aborting when video and pointer traffic arrive simultaneously.
- Reverse-tunnel sockets now use TCP keepalive, stable connections reset their retry backoff, and every stream/channel closure records an explicit reason.
- WebAdmin distinguishes meaningful RDP output from Guacamole keepalives, detects a dead FreeRDP relay after unanswered operator input, and releases the stuck session instead of leaving a false `ACTIVE` screen.
- Raspberry Pi physical-console mode now tunnels directly to the protected Raspberry Pi Connect WayVNC UNIX socket, without publishing a local/LAN VNC port.
- Linux Agents advertise independent XRDP and physical monitor sessions separately so WebAdmin can select the correct protocol and credentials.
- Guacamole keeps the XRDP framebuffer size stable to prevent FreeRDP resize loops and stale frozen frames; disconnected XRDP sessions are cleaned automatically.

- Fixes RC29 startup compatibility when older WebAdmin config omits `remote_sessions.allowed_target_cidrs`.
- Makes Remote Sessions/Guacamole and Agent release storage fail-safe modules instead of WebAdmin startup dependencies.
- `/healthz` reports module readiness without network dependency on Gateway/guacd.
- Uses Windows Selector event loop to prevent normal TLS/client resets from producing Proactor callback failure noise.
- Agent 2.4.24 installer is endpoint-offline and fail-closed: bundled private CPython only; no global Python, pip or Internet fallback.
- Detects and repairs/upgrades existing Agents in-place while preserving identity/token/site configuration.
- Retains RC26 Fleet Scale backpressure, RC28 Guacamole, remote restart, SSH/SFTP host lists and RC25 stable Agent release lifecycle.

## 6.3.4-rc28 — Apache Guacamole / Remote Sessions

- Nuevo módulo **Control remoto** para Agents y listas de hosts sin Agent.
- Broker WebSocket WSS en WebAdmin y handshake Guacamole server-side contra `guacd`.
- Nuevo Vault cifrado para credenciales RDP/VNC; secretos nunca llegan al navegador.
- Tickets HttpOnly de un solo uso, vinculados a usuario, sesión WebAdmin, IP y target, con RBAC + password/TOTP step-up.
- RDP endurecido: NLA, certificado verificado, sin drives/printing/audio-input y sin clipboard por defecto.
- VNC implementado pero deshabilitado por defecto.
- Allowlist CIDR privada y preflight TCP antes de emitir la sesión.
- Límites de sesiones globales/usuario/target para evitar saturación.
- `guacd` se entrega como servicio Docker separado y loopback-only; WebAdmin no expone 4822.
- `guacamole-common-js` se provisiona como activo administrado con SHA-256 en vez de descargarlo silenciosamente de CDN.

## 6.3.4-rc27 — SSH Vault: claves sin extensión + importación por carpeta

- El selector individual deja de filtrar por extensión para aceptar claves OpenSSH estándar como `id_ed25519`, `id_rsa` e `id_ecdsa`.
- La validación de claves pasa a ser por contenido (OpenSSH/PEM) y distingue claves públicas, archivos no relacionados y PuTTY PPK.
- Nueva importación de carpeta `.ssh` desde navegador (`webkitdirectory`): hasta 64 archivos / 2 MiB, procesados en memoria.
- La importación por carpeta ignora `.pub`, `known_hosts`, `config` y otros archivos que no sean claves privadas; solo persiste claves válidas cifradas en el vault GIDEON.
- Step-up obligatorio: contraseña actual + MFA. Los uploads fallidos no se escriben en disco.
- PPK ya no se presenta engañosamente como formato soportado: se detecta y se solicita exportarlo a OpenSSH/PEM.

## 6.3.4-rc26 — Fleet Scale + Remote Restart

- Aísla el handshake TLS del Gateway por request y aumenta backlog/conexiones para flotas grandes.
- Añade scheduler con backpressure atómico: 90 targets pueden encolarse y 20 ejecutarse en paralelo por defecto.
- Elimina N+1 de `GET /api/v1/admin/agents`; una vista de 90 Agents ya no abre ~181 transacciones SQLite.
- Añade jitter de polling/heartbeat en Agent 2.3.9.
- WebAdmin usa cache stale-if-error + circuit breaker y reutiliza SSLContext para no caerse ante un timeout transitorio del Gateway.
- Añade acción auditada **Reiniciar equipo** mediante Job firmado y dirigido por AgentId.

## 6.3.4-rc23 · Agent runtime completeness + Agentless Web

- Corrige `SCRIPT_HOST_MISSING`: `gideon_script_host.ps1` es obligatorio en todo Job PowerShell firmado y la ausencia se detecta antes de encolar.
- Agent 2.3.6 valida el cierre de dependencias locales y empaqueta soporte/runtime completo.
- Corrige empaquetadores explícitos que omitían `gideon_agent_bootstrap.py`.
- WebAdmin incorpora ejecución por lista de hosts con SSH/SFTP, perfiles de transporte y política VPN/directa.
- Vault SSH materializa claves en formato OpenSSH solo durante el Job.

## 6.3.4-rc21 — Agent Operational Contract / ejecución integral

- Unifica en `gideon_agent_job_contract.py` el contrato firmado de todos los Jobs del Agent: scripts, transferencia de archivos y mantenimiento remoto.
- Agent 2.3.4 + Worker 2.2.0 validan identidad Agent/Sede, perfil, freshness, nonce, rutas seguras y SHA-256 antes de ejecutar.
- Los paquetes de scripts usan rutas únicas por índice para evitar colisiones de nombres y verifican el hash del contenido en el endpoint.
- WebAdmin realiza preflight de capacidades/executors cuando el heartbeat moderno los declara, evitando enviar trabajos imposibles.
- Un fallo antes de arrancar el worker se reporta como `FAILED` con resultado diagnóstico; el Agent vuelve a `ACTIVE` y continúa la cola en lugar de quedar silenciosamente en `CLAIMED`.
- Gateway trata `FAILED_*` como estado terminal para que un Job fallido no bloquee los siguientes.
- Transferencias y desinstalación remota reutilizan el mismo contrato de seguridad, eliminando productores de envelope divergentes.
- Los perfiles Windows Server permiten `.cmd/.bat` bajo los mismos controles de aprobación, firma y allowlist.
- Los empaquetadores Windows/Linux y el actualizador transaccional incluyen el nuevo módulo contractual.
- No desactiva firmas Ed25519, SHA-256, freshness, replay protection ni aislamiento; no modifica Defender, OpenSSH, firewall, puertos 22/443, PKI, MFA, usuarios o servicios de terceros.


## 6.3.4-rc20 — Scripts: override SUPERADMIN auditado

- Mantiene doble control para ADMIN y demás roles.
- Permite autoaprobación exclusivamente a SUPERADMIN cuando el script ya está CLEAN.
- Registra `DualControlOverride=True` en auditoría.

## 6.3.4-rc18 — Agent Builder Windows IExpress hardening + support bundle

- Agent Builder: new built-in GIDEON SFX backend uses .NET Framework `csc.exe` before IExpress, embedding the verified payload directly in the EXE.
- IExpress remains only as last-resort fallback with GIDEON-private `TEMP/TMP`, controlled working directory and ANSI-compatible SED.
- Failed Agent builds persist a redacted Support Bundle and expose **Descargar diagnóstico** in WebAdmin.
- Support ZIP excludes `payload.zip`, enrollment grants, private keys, tokens and bootstrap credentials.
- Inno Setup remains the preferred Windows EXE backend when available.

## 6.3.4-rc17 — Windows PKI compatibility + SCM health parser

- RC16 support bundle confirmed the private machine-local Python runtime and venv are healthy.
- All six Windows services reached SCM `RUNNING` on the native Windows 10 pilot.
- Fixes Windows SCM parsing so `TYPE : 10` is not mistaken for the service state; `STATE/ESTADO : 4` is now `RUNNING`.
- Adds a GIDEON-private-CA TLS context for legacy certificates generated before SKI/AKI hardening. CA trust, signature, expiry and hostname validation remain enabled; only OpenSSL `X509_STRICT` profile enforcement is relaxed for GIDEON private-PKI connections.
- Newly generated GIDEON CA/server certificates include `SubjectKeyIdentifier` and `AuthorityKeyIdentifier`.
- Existing PKI certificates and private keys remain preserved during a normal reinstall.
- Windows local endpoint health uses the same private-PKI compatibility behavior as Diagnostics/Agent/Gateway.
- Automatic/manual Windows Support Bundle remains enabled.

## Consolidated Windows hardening retained

RC17 retains the previous native-host corrections: machine-local Python runtime, PowerShell 5.1 compatibility, Registry64, `LocalService + Service SID` isolation, staged `DEMAND_START`, ACL verification, startup rollback, runtime-health publication checks and redacted Support Bundles.

## 6.3.4-rc22 · Agent Windows autocontenido
- Agent 2.3.5 elimina la dependencia de Python preinstalado en endpoints Windows.
- Builder empaqueta CPython 3.11 privado + ruedas Windows dentro del EXE del Agent.
- Verificación SHA-256 integral del runtime antes de ejecutar.
- Contingencia online firmada/aislada para paquetes antiguos sin runtime incluido.
- Sin cambios de PATH, asociaciones Python, Defender, OpenSSH, Firewall ni servicios externos.

## 6.3.4-rc24
- Agent 2.3.7: instalador Windows autocontenido fail-closed; elimina la dependencia de Python global y valida runtime completo antes del build.

## 6.3.4-rc25
- Corrige import path del CPython embebido, upgrade/migración in-place de Agents existentes, navegación Volver y ciclo de releases stable en WebAdmin.

## 6.3.4-rc29
- Aislamiento fail-safe del subsistema Apache Guacamole/Remote Sessions para que una falla opcional no derribe WebAdmin.
- `/healthz` expone estado DEGRADED/READY de sesiones remotas.
- Control remoto tolera indisponibilidad temporal de Gateway.
- Recovery CLI para RC28 con WebAdmin no disponible.
