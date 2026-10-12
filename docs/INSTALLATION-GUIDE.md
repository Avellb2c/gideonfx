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
