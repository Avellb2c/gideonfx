# GIDEON Remote Control 6.3.4-rc28 — Browser Remote Sessions / Apache Guacamole

## Objetivo

RC28 integra un visor de escritorio remoto en WebAdmin usando **Apache Guacamole `guacd`** sin reemplazar al Agent GIDEON. La misma consola puede abrir una sesión contra:

1. **Agents enrolados**, resolviendo únicamente IP privadas autorizadas reportadas por la telemetría actual del Agent.
2. **Equipos de listas/hosts sin Agent**, usando el `ServerIP` del inventario/grupo seleccionado.

RDP queda habilitado por defecto. VNC está implementado pero **deshabilitado por política** hasta que se habilite explícitamente para redes confiables.

## Arquitectura

`Browser -> HTTPS/WSS WebAdmin -> Remote Session Broker -> TCP privado/loopback 4822 -> guacd -> RDP/VNC -> equipo`

- El navegador nunca recibe usuario/contraseña RDP/VNC.
- `guacd:4822` se publica solo en `127.0.0.1` en el compose de referencia.
- No se instala la aplicación web completa de Apache Guacamole; GIDEON usa únicamente `guacd` y `guacamole-common-js`.
- El Agent mantiene sus funciones existentes: Jobs, scripts, transferencias, reinicio, actualización e inventario.

## Seguridad

- RBAC: `remote.view` y `remote.control`.
- Reautenticación fuerte antes de cada sesión: contraseña WebAdmin + TOTP.
- Ticket de sesión aleatorio, HttpOnly, SameSite=Strict, de un solo uso y TTL corto.
- Ticket vinculado a usuario, sesión WebAdmin, IP de origen, target, protocolo y credencial.
- Same-Origin obligatorio para el WebSocket.
- Vault independiente para credenciales RDP/VNC, cifrado con clave derivada por separación de dominio desde `GIDEON_WEB_TOTP_ENCRYPTION_KEY`.
- Destinos limitados a CIDR autorizados; no se permiten loopback, link-local, multicast ni destinos públicos fuera de allowlist.
- RDP: NLA por defecto, verificación de certificado, unidades/impresión/audio-input deshabilitados y clipboard bloqueado por defecto.
- Límites: 10 sesiones globales, 3 por usuario y 1 por target por defecto.
- Auditoría de emisión, conexión, error y desconexión.

## Supply chain del cliente JS

RC28 **no descarga JavaScript desde CDN en runtime**. Un SuperAdmin debe provisionar una versión aprobada de `guacamole-common-js` en `Claves y secretos -> Cliente Web Apache Guacamole`; WebAdmin valida la API mínima y puede exigir un SHA-256 conocido.

## Infraestructura incluida

`deploy/guacamole/docker-compose.yml` levanta únicamente `guacd`, con:

- binding `127.0.0.1:4822:4822`;
- filesystem read-only y `/tmp` tmpfs;
- `no-new-privileges`;
- capabilities eliminadas;
- límites de PIDs, memoria y CPU;
- rotación de logs.

## Compatibilidad

- Control Plane: **6.3.4-rc28**.
- Agent: **2.3.9** (sin cambio binario).
- Gateway: **2.4.1** (sin cambio binario).

La conectividad gráfica requiere que el host donde corre `guacd` tenga ruta TCP hacia RDP/VNC del destino (LAN/VPN/ruta corporativa). GIDEON no modifica VPN, rutas ni firewall automáticamente.
