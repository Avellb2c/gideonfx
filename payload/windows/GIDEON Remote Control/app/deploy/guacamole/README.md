# GIDEON Remote Control · guacd

RC28 usa **solo `guacd`** como proxy RDP/VNC. No instala la aplicación web completa de Apache Guacamole.
El navegador nunca se conecta a `guacd`: Browser → WSS/WebAdmin → TCP loopback 4822 → guacd → RDP/VNC.

## Inicio

En el Control Plane Linux/Ubuntu:

```bash
cd deploy/guacamole
docker compose pull
docker compose up -d
```

El `docker-compose.yml` publica **solo `127.0.0.1:4822`**. No cambie esto a `0.0.0.0:4822`.
La imagen está pinneada a una versión conocida por el código de esta RC, pero la organización puede sustituir
`GUACD_IMAGE` por una imagen aprobada internamente después de validar compatibilidad y CVE.

## Ruta hacia tiendas

`guacd` debe poder llegar a los destinos RDP/VNC. Para Agents, WebAdmin usa la IP privada que el Agent reporta
en su heartbeat. Para equipos sin Agent, usa `ServerIP` del inventario seleccionado. Si la VPN del host no se
propaga al bridge de Docker, configure la ruta/NAT en Docker/host de acuerdo con su FortiGate/VPN. GIDEON no abre
firewall ni modifica la VPN automáticamente.

Pruebe desde el host y desde el contenedor antes de habilitar producción:

```bash
# host
nc -vz 10.x.x.x 3389

# contenedor (si la imagen dispone de una shell/herramienta TCP)
docker exec gideon-guacd sh -lc 'timeout 3 sh -c "</dev/tcp/10.x.x.x/3389"' || true
```

## Seguridad

- 4822 nunca debe exponerse a Internet/LAN.
- RDP usa NLA por defecto y validación de certificado (`rdp_ignore_cert=false`).
- VNC está deshabilitado por defecto. Habilítelo solo sobre una red/VPN confiable.
- Las credenciales se guardan cifradas en el Vault GIDEON y se descifran solo para el handshake con guacd.
- Las sesiones Web usan ticket HttpOnly, SameSite=Strict, de un solo uso y TTL 60 s.
- Límites por defecto: 10 sesiones globales, 3 por usuario y 1 por equipo.

## guacamole-common-js

Por política de supply-chain, GIDEON no descarga JavaScript de CDN de forma silenciosa. Descargue/compile el bundle
oficial de `guacamole-common-js` desde una fuente aprobada, calcule su SHA-256 y cárguelo en:

**WebAdmin → Claves y secretos → Cliente Web Apache Guacamole**

La Web valida que el bundle exponga `Guacamole.Client` y `Guacamole.WebSocketTunnel`, compara el SHA-256 si se
proporciona y lo guarda como activo administrado.
