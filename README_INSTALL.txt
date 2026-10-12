GIDEON RX DEPLOYMENT BUNDLE PRE-RC31 · Agent 2.4.56 · Gateway 2.4.3
Generated: 2026-09-11T16:08:01Z
Source: DESKTOP-NQK5ET7
Clean OneClick kit: protected data, secrets and state DB are excluded by default.
Clone state is included only in a separately generated, explicitly authorized clone kit.

Branding: Gideon Rx is the public product identity. Internal GIDEON paths, service
identifiers and migration contracts remain unchanged for compatibility with
existing installations; they are not a public trademark or visual identity.

WINDOWS:
  Run installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd as Administrator.
  This is fresh by default: it does not import payload/data, databases, PKI,
  secrets or machine environment values from this bundle.
  A controlled clone requires an explicit -InstallMode clone and a clone kit
  created with installers\tools\BUILD_GIDEON_PORTABLE_KITS.cmd --include-clone-state.

LINUX:
  Run sudo bash installers/LINUX/install-gideon-master-linux.sh

Guacamole:
  See metadata\guacamole\guacamole-production-report.json

Security:
  This installer never resets third-party firewall rules, never docker-prunes,
  never depends on a fixed LAN IP, and keeps guacd private.
  Windows installs the pinned YARA 4.5.5 CLI privately for GIDEON after verifying
  both the official release ZIP and yara64.exe by SHA-256. The offline ZIP is
  bundled; a locked HTTPS download is allowed only when that cache is missing.
INSTALACION DIRECTA
===================

Windows: installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd
Linux:   bash installers/LINUX/INSTALL_GIDEON_MASTER_LINUX.sh

TRANSPORTE RAPIDO A OTRO EQUIPO
===============================

Use uno de los kits modulares generados en la carpeta hermana cuyo nombre
termina en -PORTABLE. Copie solamente el kit del sistema destino y ejecute su
INSTALL_GIDEON_ONECLICK. No descomprima manualmente los archivos .tar.gz.

Consulte ONECLICK-INSTALL.md para perfiles Windows Home/Docker,
Windows Hyper-V, Linux y Universal, caché local y descarga por URL.

CREDENCIALES INICIALES Y AGENTES NUEVOS
=======================================
En un servidor nuevo, OneClick genera contraseñas temporales diferentes para
dchaskypp (SUPERADMIN) y damautapp (ADMIN). Ambas cuentas exigen cambio de
contraseña y alta de MFA. Las claves no se imprimen en logs: la pantalla final
indica el archivo protegido que debe abrir como Administrador/root.

Windows: C:\ProgramData\GIDEON Remote Control\secrets\bootstrap-credentials.txt (ruta interna de compatibilidad)
Linux:   /var/lib/gideon-remote-control/secrets/bootstrap-credentials.txt

En una nueva identidad de servidor se eliminan Agents/grants/jobs heredados del
clon. El catálogo para generar instaladores permanece disponible. Una
reinstalación en la misma máquina conserva sus Agents y usuarios.

SEGURIDAD DEL MODO DE INSTALACION
=================================
El modo predeterminado es fresh tanto para Windows como para Linux. En Windows
se genera PKI, tokens, Fernet y estado vacíos en el servidor destino; nunca se
copian desde payload/data. Clone es una excepción explícita para migraciones
autorizadas y falla si el kit no declara e incluye su estado confidencial.

RECURSOS ADAPTATIVOS
====================

OneClick selecciona automáticamente compact (8-15 GB), standard (16-31 GB)
o performance (32+ GB y 8+ CPU lógicos). Hyper-V usa memoria dinámica.
En Windows, Backup se ejecuta por horario y Updater por eventos de archivos,
sin procesos Python residentes para esas tareas mientras están inactivas.
Puede fijar un perfil con GIDEON_RESOURCE_PROFILE=compact|standard|performance.

UBUNTU: URL PUBLICA Y CERTIFICADOS
=================================
El asistente final ofrece CA privada de laboratorio, Let's Encrypt o importación
PEM/PFX. Permite reemplazar certificados después sin reinstalar el producto:
sudo bash /opt/gideon/web/app/deploy/ubuntu/CONFIGURE-GIDEON-EXTERNAL.sh

DNS, IP fija y firewall de Google se configuran por separado. Para CA privada,
confíe únicamente el certificado público de la CA; nunca comparta claves.
Guía: installers/LINUX/EXTERNAL-ACCESS-AND-CERTIFICATES.md
