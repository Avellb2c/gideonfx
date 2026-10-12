# GIDEON Remote Control 6.3.4-rc29 — WebAdmin Recovery / Guacamole Fail-Safe

RC29 corrige un defecto de acoplamiento introducido en RC28: la inicialización del módulo opcional de sesiones remotas (SQLite/Vault/Guacamole) podía impedir el arranque completo de WebAdmin si cualquiera de sus recursos locales fallaba al iniciar.

Cambios principales:

- Guacamole/Remote Sessions queda aislado como subsistema opcional y fail-safe.
- Si el módulo remoto no puede inicializar, WebAdmin sigue operativo y `/healthz` informa `RemoteSessions=DEGRADED` con la causa concreta.
- La página de Control remoto tolera Gateway temporalmente no disponible y muestra el diagnóstico en lugar de derribar la consola.
- Se agrega un gate de salud HTTP para actualizaciones futuras: un servicio en estado RUNNING ya no se considera suficiente si `/healthz` no responde correctamente.
- El recovery pack permite aplicar RC29 incluso cuando la GUI de RC28 está caída.
