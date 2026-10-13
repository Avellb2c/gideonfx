# Gideon Rx

Gideon Rx es una plataforma AGPLv3 para gestión remota, transferencia segura,
agentes multiplataforma y campañas para pantallas publicitarias.

## Alcance

- Administración web y auditoría.
- Túneles inversos y sesiones remotas RDP/VNC.
- Agentes para Windows, Linux, Raspberry Pi y macOS.
- Biblioteca multimedia, campañas, pantallas y programación.
- Reproducción externa mediante VLC, conservando sus avisos GPL.

## Tecnologías y cómo se integran

Gideon Rx está organizado en capas para que una falla del reproductor o de una
sesión remota no detenga el panel administrativo ni los Agents.

| Capa | Tecnologías | Integración |
| --- | --- | --- |
| Panel y API | Python 3.11+, FastAPI, Starlette, Uvicorn, Jinja2, HTML/CSS/JavaScript | WebAdmin sirve la interfaz, las APIs, los trabajos, campañas, pantallas, transferencias y auditoría. WebSockets se usan para actualizaciones y sesiones interactivas. |
| Estado local | SQLite, `sqlite3`, migraciones y jobs controlados | Guarda usuarios, roles, auditoría, Agents, pantallas, campañas, revisiones, programación, biblioteca multimedia y estados de distribución. Cada instalación crea su propio estado. |
| Identidad y seguridad | TLS/mTLS, `cryptography`, Fernet, Argon2, firmas Ed25519, SHA-256 y redacción de secretos | Protege el canal WebAdmin-Gateway-Agent, cifra valores sensibles, firma manifiestos y valida integridad de archivos, instaladores y actualizaciones. |
| Gateway y remoto | Túnel inverso autenticado, WebSocket seguro y protocolo Guacamole | El Agent inicia la conexión saliente. WebAdmin entrega instrucciones al Gateway y `guacd`; este traduce RDP, VNC o SSH sin exponer esos puertos públicamente. |
| Guacamole | `guacd` en Docker/Compose o en una VM Hyper-V validada | En Linux se ejecuta como servicio de contenedor. En Windows puede usar Docker Desktop/WSL2 o Hyper-V según la edición y el perfil seleccionado. El puerto de `guacd` queda interno. |
| Agents | Python, servicios `systemd` en Linux/Raspberry Pi y servicios/tareas de Windows | Reportan conectividad, sesiones, salidas físicas, monitores, capacidad gráfica y estado del reproductor. Mantienen túnel, control remoto y reproducción como componentes separados. |
| Campañas y pantallas | MediaAsset, Campaign, Revision, Playlist, Assignment y Schedule | WebAdmin valida el video, calcula su hash, firma el manifiesto y lo distribuye por pantalla. El Agent descarga sólo lo asignado, guarda caché y continúa con la última revisión válida sin conexión. |
| Reproducción | VLC externo, ejecutado como proceso independiente | El Agent no incrusta VLC. Inicia/reintenta VLC en pantalla completa, adapta la salida física y reporta versión, campaña, video, errores y último éxito sin bloquear el túnel remoto. |
| Instalación y operación | Bash, PowerShell, Docker Compose, systemd, Hyper-V, WSL2 | Los instaladores detectan el sistema operativo, validan requisitos, generan PKI/secretos nuevos, configuran servicios y ejecutan verificaciones de salud. Los kits offline añaden cachés y artefactos firmados. |

### Flujo de integración

```text
Marketing/WebAdmin
        │ HTTPS + sesión/roles
        ▼
FastAPI + SQLite + Jobs + Auditoría
        │ manifiesto firmado / distribución
        ▼
Gateway ── túnel inverso mTLS ── Agent
   │                              ├─ remoto RDP/VNC/SSH → guacd
   │                              └─ campañas → caché → VLC → pantalla física
   └─ WebSocket Guacamole (sólo red interna)
```

El flujo de campañas no depende de una sesión interactiva del usuario: la
pantalla física queda asociada a una salida concreta del Agent y reproduce la
última campaña válida aunque temporalmente no haya Internet. Las sesiones
remotas son independientes y pueden abrirse sin interrumpir la reproducción.

### Dependencias y despliegue

- Linux/Ubuntu y Raspberry Pi: Python, `systemd`, Docker/Compose para
  `guacd`, y VLC instalado o autorizado mediante el catálogo de terceros.
- Windows Server/Pro: PowerShell, Python privado, Hyper-V o Docker Desktop/WSL2
  según el backend seleccionado, y VLC externo para pantallas físicas.
- AWS y Azure: proporcionan la VM, red, disco, DNS y TLS; Gideon configura la
  aplicación dentro del sistema operativo. La red debe restringir WebAdmin y
  mantener RDP, VNC, SSH y `guacd` fuera de Internet pública.

Las versiones y hashes de dependencias se controlan mediante los archivos de
instalación y manifiestos del repositorio. El clone público no contiene datos
de producción, claves privadas, campañas, bases de datos ni registros de una
nube concreta.

## Capacidad de referencia

La instalación actual selecciona perfiles `compact`, `standard` o
`performance` según los recursos del servidor. Como referencia operativa:

| Perfil | Host | Agents sostenidos | Sesiones remotas objetivo | Jobs objetivo |
| --- | --- | ---: | ---: | ---: |
| `compact` | 4 vCPU · 8–15 GiB RAM | 1–25 | 1–2 | 5 |
| `standard` | 4–8 vCPU · 16–31 GiB RAM | 25–100 | 2–4 | 10–20 |
| `performance` | 8+ vCPU · 32+ GiB RAM | 100–200 | 4–8 | 20 |

Son objetivos de dimensionamiento, no garantías de rendimiento. El detalle de
los límites de Gateway, sesiones, Jobs, transferencias, builds y almacenamiento
está en la [guía de capacidad e instalación](docs/INSTALLATION-GUIDE.md).

## Inicio rápido

Consulta [ONECLICK-INSTALL.md](ONECLICK-INSTALL.md) y la [guía de instalación
por plataforma y nube](docs/INSTALLATION-GUIDE.md) antes de instalar. Las credenciales, certificados, secretos y datos
de producción deben proporcionarse mediante variables o archivos locales; no
se guardan en este repositorio.

## Licencia

El código propio de Gideon Rx se distribuye bajo GNU AGPLv3. Las dependencias
de terceros mantienen sus propias licencias; revisa los avisos incluidos antes
de redistribuir un paquete.

## Contribuciones y seguridad

Consulta [SECURITY.md](SECURITY.md) para reportar vulnerabilidades. No envíes
claves privadas, tokens, contraseñas, bases de datos ni paquetes Executive en
issues o pull requests.
