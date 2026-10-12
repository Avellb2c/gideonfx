# Control remoto web con Apache Guacamole

## Topología GIDEON

```text
Browser
  | HTTPS / WSS
  v
GIDEON WebAdmin
  | ticket efímero + RBAC + MFA
  v
Remote Session Broker
  | TCP privado 4822
  v
guacd
  | RDP 3389 / VNC 5900
  v
Agent target o Host de lista
```

El Agent GIDEON **no se reemplaza**. Cuando el destino es un Agent, WebAdmin toma exclusivamente las IP privadas autorizadas reportadas en `Diagnostics.network`. Cuando el destino es un host sin Agent, se usa el `ServerIP` del inventario de hosts/grupos existente.

## Puesta en marcha

1. Aplicar RC28 y verificar `APPLIED`.
2. En Linux/Ubuntu del Control Plane, ejecutar `docker compose up -d` dentro de `deploy/guacamole`.
3. Verificar que `127.0.0.1:4822` responde. No publicar 4822 en la LAN o Internet.
4. Obtener una versión aprobada de `guacamole-common-js`, verificar su SHA-256 y cargarla en `Claves y secretos`.
5. Crear una credencial RDP/VNC en el Vault GIDEON. La contraseña queda cifrada server-side.
6. Entrar a `Control remoto`, seleccionar **Agent** o **Lista de equipos/hosts**, protocolo, IP, credencial, y reautenticar con contraseña + MFA.
7. Confirmar que el Control Plane/guacd tiene ruta hacia el puerto 3389/5900 del destino.

## Defaults de seguridad

- RDP NLA.
- `ignore-cert=false`.
- VNC deshabilitado.
- Clipboard, unidades e impresión RDP deshabilitados.
- Destinos privados allowlisted.
- ticket 60 s, un solo uso.
- 10 sesiones globales / 3 por usuario / 1 por equipo.
- Same-Origin WebSocket.
- auditoría completa.

## Diagnóstico

Si WebAdmin muestra `guacd OFFLINE`, revisar Docker y `127.0.0.1:4822`.
Si muestra `REMOTE_TARGET_UNREACHABLE`, probar la ruta del **Control Plane** al equipo, no la ruta del navegador. El flujo gráfico sale desde `guacd` hacia el destino.
Si un Agent no aparece como `RDP/VNC`, revisar que el heartbeat reporte una IP privada perteneciente a `allowed_target_cidrs`.
