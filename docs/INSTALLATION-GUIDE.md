# Gideon Rx: instalación y configuración

Esta guía cubre una instalación base del control plane en Windows Server o
Ubuntu y su despliegue en AWS o Azure. Los Agents usan túneles inversos mTLS;
no se deben publicar RDP, VNC, guacd ni puertos de Agent en Internet.

## Reglas comunes

1. Usa un DNS estable para WebAdmin y sincroniza la hora del sistema.
2. Conserva el bundle y sus manifiestos SHA-256; no modifiques archivos antes
   de verificar la integridad.
3. Instala con una cuenta administrativa, cambia la contraseña inicial y activa
   MFA antes de registrar sedes.
4. Proporciona certificados, claves y contraseñas mediante archivos locales o
   el almacén seguro del sistema. Nunca los pegues en issues, scripts o esta
   guía.
5. Configura backups cifrados del directorio de datos y prueba una restauración.

## Capacidad y dimensionamiento

La siguiente matriz describe el alcance operativo recomendado para una sola
instancia de WebAdmin/Gateway. Son objetivos de dimensionamiento, no un SLA:
la capacidad real depende del tamaño de los videos, latencia, tipo de RDP/VNC,
frecuencia de Jobs y almacenamiento disponible. Antes de producción, valida el
perfil con métricas de CPU, RAM, disco, latencia y errores.

| Nivel | Servidor de control | Agents conectados de forma sostenida | Sesiones remotas simultáneas objetivo | Jobs simultáneos objetivo | `guacd` |
| --- | --- | ---: | ---: | ---: | --- |
| Mínimo / `compact` | 4 vCPU, 8–15 GiB RAM, 20 GiB libres en Windows o 8 GiB libres en Linux | 1–25 | 1–2 | 5 | 768 MiB, 1 CPU |
| Intermedio / `standard` | 4–8 vCPU, 16–31 GiB RAM, 40 GiB libres más biblioteca multimedia | 25–100 | 2–4 | 10–20 | 1 GiB, 1 CPU |
| Recomendado / `performance` | 8+ vCPU, 32+ GiB RAM, 80 GiB o más más biblioteca y backups | 100–200 | 4–8 | 20 | 1,5 GiB, 2 CPU |

### Límites actuales del software

- El Gateway reserva hasta **256 conexiones** simultáneas por defecto. La guía
  considera 200 Agents sostenidos como límite operativo prudente; por encima de
  200 se debe validar `gateway_max_connections`, almacenamiento y una posible
  base de datos externa o arquitectura de alta disponibilidad.
- La política remota permite por defecto **10 sesiones activas globales**, **3
  por usuario** y **1 por destino**. Por eso la cifra de la tabla es un objetivo
  de operación y no un aumento automático de esos límites.
- Cada Agent puede reclamar hasta **20 Jobs activos** (`fleet_max_active_jobs`).
  El orquestador de fan-out parte de **6 envíos** y **8 consultas** simultáneas
  para no saturar la red; la cola conserva los trabajos pendientes.
- Transferencias y análisis usan por defecto **2 workers** y una cola persistida
  de **32 trabajos**. Se pueden elevar de forma controlada hasta 4 workers y
  500 pendientes, vigilando CPU, disco y antivirus.
- La generación pesada de instaladores se serializa por defecto (**1 build**),
  con un máximo acotado de 4; solicitudes idénticas se deduplican.
- El análisis antivirus paralelo parte de **2 exploraciones**, con máximo 4.
- La capacidad de campañas está limitada principalmente por almacenamiento:
  reserva espacio para el archivo original, cuarentena, temporales, Jobs y
  backups. La caché de cada Agent se calcula aparte y crece con sus videos.

### Lectura práctica

- Para una sede pequeña o laboratorio, usa `compact` y evita cargas masivas
  mientras se ejecutan sesiones remotas.
- Para varias sedes y campañas diarias, `standard` es el punto de partida
  equilibrado.
- Para 100–200 Agents, campañas, transferencias y varias sesiones, usa
  `performance`, almacenamiento separado para medios y monitorización continua.
- Si se necesita superar 200 Agents, 10 sesiones remotas o 20 Jobs de forma
  sostenida, no basta con aumentar RAM: hay que probar un Gateway escalado,
  persistencia externa y una política de sesiones/Jobs revisada.

### Consumo normal de referencia

Estas mediciones corresponden a una instalación validada en reposo; sirven para
estimar el consumo base, no para prometer el consumo durante una campaña o una
sesión de video. El consumo de Linux puede variar según el kernel, Docker y el
controlador gráfico.

| Componente | Reposo observado | Qué lo incrementa |
| --- | ---: | --- |
| Árbol de procesos Gideon | ≈222,8 MB de working set | WebAdmin, auditoría, Jobs, análisis y consultas activas |
| Contenedor `guacd` | ≈13,73 MiB y 0 % CPU en la muestra | Sesiones RDP/VNC, resolución, movimiento y redirecciones |
| Docker Desktop + `vmmem` en Windows Home | ≈1,41 GB de working set | WSL2, imágenes, sesiones y otros contenedores |
| Incremento total del host Windows Home | ≈1,65 GB en reposo | Todo lo anterior; no incluye VLC en los Agents |

En la red, el heartbeat y el polling de Agents generan tráfico bajo. Como
presupuesto orientativo por sesión RDP/VNC: reposo ≈0,3 Kbps, oficina
0,5–1 Mbps, web/gráficos 2–5 Mbps y video hasta 10 Mbps. Para diez sesiones
normales conviene reservar 20–50 Mbps, además de Agents, Jobs y transferencias.

La reproducción VLC ocurre en cada Agent y no en el servidor central: su CPU,
RAM, aceleración gráfica y disco dependen de la resolución y del video local.
Para sostener 5–10 sesiones remotas se recomienda asignar 2–4 vCPU y 2–4 GiB
específicos a `guacd` y ejecutar una prueba de carga antes de ampliar el
límite.

## Windows Server

Requisitos sugeridos: Windows Server 2019/2022 x64, 4 vCPU, 8 GB RAM, 20 GB
libres, IP/DNS estables y PowerShell con permisos de administrador.

```powershell
tzutil /s "SA Pacific Standard Time"
w32tm /resync
cd C:\Gideon\installers\WINDOWS
.\INSTALL_GIDEON_MASTER_WINDOWS.cmd -InstallMode fresh
```

Después de instalar:

- abre WebAdmin por HTTPS;
- en **Acceso externo y TLS**, registra el FQDN y un certificado válido;
- verifica los servicios Gideon y Guacamole desde **Diagnóstico y salud**;
- activa MFA, crea roles mínimos y valida una auditoría;
- genera un Agent de prueba desde **Crear instalador**.

El firewall debe permitir únicamente 443/TCP desde el proxy, balanceador o
rango administrativo. Guacamole queda interno; no abras 3389 ni 5900.

## Ubuntu Server

Usa Ubuntu 22.04 o 24.04 LTS, systemd, Python 3.11+, Docker para Guacamole,
una IP estable y un usuario con `sudo`.

```bash
sudo timedatectl set-timezone America/Lima
sudo timedatectl set-ntp true
sudo apt update
cd ~/gideonfx
bash installers/LINUX/INSTALL_GIDEON_MASTER_LINUX.sh
```

Para forzar una instalación sólo desde el caché firmado:

```bash
export GIDEON_ALLOW_ONLINE_INSTALL=0
bash installers/LINUX/INSTALL_GIDEON_MASTER_LINUX.sh
```

Comprueba los servicios sin reiniciar a ciegas:

```bash
sudo systemctl status gideon-web-admin
sudo systemctl status gideon-agent-gateway
sudo docker compose -f payload/linux/app/deploy/guacamole/docker-compose.yml ps
```

## AWS (EC2)

1. Crea una VPC y coloca la instancia Ubuntu en una subnet privada cuando sea
   posible.
2. Permite sólo 443/TCP desde un Application Load Balancer, VPN o rango
   administrativo. Usa SSM Session Manager en lugar de SSH público.
3. Asigna un rol IAM mínimo para SSM, métricas y backups; no guardes access
   keys en la VM.
4. Asocia un nombre Route 53, termina TLS en el balanceador o en WebAdmin y
   ejecuta el instalador Ubuntu.
5. Valida el Gateway mTLS y un Agent antes de registrar todas las sedes.
6. Activa snapshots EBS cifrados y documenta una restauración.

No abras 3389, 5900 ni el puerto de guacd a Internet. Referencia: [AWS
Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html).

## Azure (VM)

1. Crea una VNet/subnet dedicada y un NSG que permita sólo 443/TCP desde
   Application Gateway, VPN o rangos administrativos.
2. Activa Managed Identity y Azure Monitor; evita client secrets en `.env` o
   imágenes de VM.
3. Publica un DNS estable, instala el certificado y ejecuta el OneClick de
   Windows o Ubuntu según la VM.
4. Comprueba auditoría, Gateway, servicios y un Agent de prueba antes de
   incorporar más sedes.
5. Configura Azure Backup para datos, certificados y configuración y prueba la
   recuperación.

Prioriza Azure Bastion o Just-In-Time VM access. Referencia: [Azure Network
Security Groups](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview).

## Validación final

- HTTPS y certificado válidos.
- Hora documentada en `America/Lima` o UTC.
- MFA, roles mínimos y auditoría activos.
- Gateway mTLS operativo y guacd interno.
- Agent de prueba visible, actualizado y con túnel inverso.
- Backup y restauración probados.

Si algo falla, exporta el diagnóstico sin secretos desde WebAdmin y revisa el
servicio concreto. No borres la base de datos ni regeneres certificados como
primer intento.
