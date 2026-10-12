# GIDEON Remote Control 6.3.4-rc30 · Agent 2.4.34 · Gateway 2.4.2 — OneClick por plataforma

Esta release separa la entrada de instalación del Control Plane/Agent para evitar usar un instalador ambiguo.

| Plataforma | Bundle | Entrada OneClick | Validación |
|---|---|---|---|
| Windows 10/11 | `*-WINDOWS-ONECLICK.zip` | `INSTALL-GIDEON-WINDOWS-DESKTOP.cmd` | Rechaza Windows Server |
| Windows Server 2016/2019/2022 | `*-WINDOWS-SERVER-ONECLICK.zip` | `INSTALL-GIDEON-WINDOWS-SERVER.cmd` | Rechaza Windows Desktop |
| Linux genérico systemd | `*-LINUX-ONECLICK.tar.gz` | `INSTALL-GIDEON-LINUX.sh` | Debian no-Ubuntu y familia RHEL/Rocky/Alma/CentOS/Fedora; rechaza Ubuntu |
| Ubuntu | `*-UBUNTU-ONECLICK.tar.gz` | `INSTALL-GIDEON-UBUNTU.sh` | Requiere Ubuntu/systemd |

## Principios de instalación

- No se usa MSI.
- No se modifica Defender.
- No se modifica OpenSSH/sshd/ssh-agent del sistema.
- No se usan los puertos 22 ni 443 para GIDEON.
- No se ejecuta upgrade global del sistema operativo.
- No se habilitan PPAs/repositorios externos automáticamente.
- Linux/Ubuntu requieren Python 3.11+; Ubuntu 24.04+ es la base recomendada.
- El OneClick Linux genérico solo declara compatibilidad con distribuciones systemd Debian/RHEL compatibles que puedan proporcionar Python 3.11+ desde sus repositorios ya configurados.

## Uso

### Windows 10/11
Extraer el ZIP y ejecutar como Administrador:

`INSTALL-GIDEON-WINDOWS-DESKTOP.cmd`

### Windows Server
Extraer el ZIP y ejecutar como Administrador:

`INSTALL-GIDEON-WINDOWS-SERVER.cmd`

### Linux genérico
Extraer el `.tar.gz` y ejecutar:

`./INSTALL-GIDEON-LINUX.sh`

El launcher eleva con `sudo` cuando está disponible; si ya se ejecuta como root no requiere sudo.

### Ubuntu
Extraer el `.tar.gz` y ejecutar:

`./INSTALL-GIDEON-UBUNTU.sh`

El instalador detecta el SO antes de modificar el host y aborta si el paquete no corresponde a la plataforma.

### Windows RC5 y backups legacy
El OneClick Windows/Windows Server puede instalar sobre un DataRoot que contenga el antiguo directorio `backup` recursivo. No lo borra ni lo recorre. Para evitar el límite MAX_PATH de Explorer se distribuye además una variante ShortPath (`GIDEON-WIN-RC6.zip` / `GIDEON-WS-RC6.zip`) cuya raíz interna es `GIDEON\`.

## RC22 · Agent Windows autocontenido
Los Agents Windows generados desde WebAdmin incluyen un CPython 3.11 privado y sus dependencias. La PC destino no requiere Python ni Internet. El primer build en el servidor puede descargar/cachear el runtime oficial; para entornos aislados puede preaprovisionarse `GIDEON_AGENT_RUNTIME_CACHE_DIR`.

## RC23 · runtime Agent completo
El generador valida el cierre de dependencias locales del Agent e incluye `gideon_agent_bootstrap.py` y `gideon_script_host.ps1` en el payload. Un instalador incompleto se rechaza durante la generación en lugar de fallar después en el endpoint.


## RC28 · Apache Guacamole / visor remoto Web

El instalador del Control Plane no instala Docker ni descarga imágenes/JavaScript de terceros silenciosamente. RC28 incluye `deploy/guacamole/docker-compose.yml` para levantar únicamente `guacd` en `127.0.0.1:4822`. El operador provisiona la imagen aprobada y carga `guacamole-common-js` desde WebAdmin con SHA-256 verificado. Esta separación evita que una actualización GIDEON modifique runtimes de contenedores o repositorios del sistema sin autorización.
