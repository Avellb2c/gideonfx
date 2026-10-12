# Ubuntu: acceso externo y certificados

## Qué configura cada capa

| Capa | Responsabilidad |
|---|---|
| Google Cloud | VM, IP pública fija y reglas VPC de entrada/salida. |
| Proveedor DNS | Registros A de WebAdmin y agentes hacia la IP fija; no es obligatorio contratar Cloud DNS. |
| OneClick Ubuntu | Servicios GIDEON, HTTPS directo, URL anunciada a los agentes, permisos de certificados y restricción administrativa por IP/CIDR. |

Valores externos predeterminados: `https://admin.example.com:9443` y `https://agents.example.com` (443). También puede utilizar una sola IP para ambos con puertos distintos. Este modo no requiere un proxy ni un balanceador facturable. La IP de cliente y TLS/mTLS llegan directamente a GIDEON. WebSockets, túneles inversos y transferencias no atraviesan un proxy HTTP que pueda cortarlos.

La publicación no termina hasta probar desde una red externa. `FINAL_INSTALL=PASS` o `LOCAL_HTTPS=PASS` NO certifica el DNS ni el firewall de Google. No se crean reglas cloud con credenciales implícitas, no se habilita ni restablece UFW y no se sobrescribe Nginx/Apache. Este publicador utiliza IPv4; no configure registros AAAA para GIDEON sin preparar por separado un servicio IPv6 compatible.

## Sin dominio ni certificados todavía

1. Reserve una IP externa fija para la VM.
2. Ejecute `sudo bash INSTALL_GIDEON_ONECLICK.sh` en la carpeta Linux completa.
3. Introduzca la IP pública como dirección WebAdmin y agentes.
4. En el asistente final seleccione `private-ca`.
5. Indique su IP pública administrativa, por ejemplo `203.0.113.8/32`. No se acepta una lista vacía ni `0.0.0.0/0`.

El instalador genera certificados con identidad DNS/IP, verifica la cadena y activa HTTPS. La CA del laboratorio no es una autoridad pública: el navegador no confiará automáticamente. Importe SOLO `/etc/gideon/pki/root/gideon-root-ca.pem` en el almacén de confianza de los equipos de laboratorio, por un canal autenticado. Los instaladores de agentes deben generarse DESPUÉS de establecer la URL/CA definitivas. Nunca desactive `verify_tls` ni use `-k` como solución.

No distribuya `gideon-root-ca.key`, archivos `privkey.pem` ni las claves de `/etc/gideon/pki/agent-ca`. La CA privada no se debe importar indiscriminadamente en equipos ajenos. Sus certificados servidor duran como máximo un año; se reemplazan con la misma herramienta. No se instala renovación automática para CA privada o PFX/PEM manuales.

## Certificados públicos durante la instalación: Let's Encrypt

Elija `letsencrypt` cuando ya disponga de dos nombres DNS que apunten a la VM. El flujo integrado utiliza nombres DNS, no certificados públicos por IP ni wildcard.

Requisitos:

- Registros A públicos correctos; no publique AAAA mientras utilice este publicador IPv4.
- TCP/80 libre en Ubuntu y permitido desde Internet en Google y en el firewall local. Certbot utiliza HTTP-01/standalone.
- Email válido y aceptación explícita de los términos en el asistente.
- Acceso saliente HTTPS a ACME y repositorios Ubuntu para instalar Certbot si falta.

El asistente no detiene servidores ajenos que ocupen el puerto 80. Si está ocupado, se detiene con una explicación: obtenga el certificado mediante su proxy/DNS-01 y use `pem`. La solicitud no cambia automáticamente DNS ni firewall cloud.

Certbot conserva su identidad en `/etc/letsencrypt/live/gideon-public/`. GIDEON copia versiones verificadas en `/etc/gideon/public-tls/` con permisos restringidos y configura un deploy-hook para aplicar cada renovación. Se utiliza `certbot.timer` del paquete Ubuntu, sin reemplazar su configuración global. Mantenga la validación HTTP-01 disponible también para las renovaciones.

Para comprobar la renovación ACME:

```bash
sudo certbot renew --cert-name gideon-public --dry-run
sudo systemctl status certbot.timer
```

El dry-run prueba ACME; no sustituye una prueba real del deploy-hook. Cambios de CA que los agentes antiguos no confíen se bloquean hasta confirmar su actualización.

## Importar o reemplazar certificados PEM/PFX

### Desde WebAdmin después de instalar

Abra **Infraestructura → TLS y acceso externo** con un usuario **SuperAdmin**. La nueva pantalla no es la antigua carga de CA de confianza de «Claves y secretos»: aquí se administran los certificados HTTPS que presentan WebAdmin y Gateway.

1. Seleccione conservar certificados, generar certificados de laboratorio, Let’s Encrypt, PEM o PFX/P12.
2. Introduzca los nombres/IPs, puertos y redes administrativas. La lista debe incluir la IP desde la que está conectado.
3. Si importa, seleccione los archivos locales y sus contraseñas. Puede usar un certificado SAN para ambos servicios, si cubre ambos nombres.
4. Ingrese contraseña y MFA y pulse **Validar y preparar**. Se valida la identidad, cadena, vigencia y clave; no se publican cambios. La preparación caduca a los 30 minutos. Para ACME, esta fase solo valida requisitos: la emisión ocurre al aplicar.
5. Revise la URL propuesta y la posible actualización de agentes. Vuelva a ingresar contraseña/MFA y pulse **Aplicar configuración preparada**. Se reinician los dos servicios y pueden interrumpirse sesiones remotas.
6. Abra la nueva URL, inicie sesión y **confirme el acceso antes de 5 minutos**. Si HTTPS falla, no confirma a tiempo o reinicia el servidor antes de confirmar, se restaura la configuración anterior. Mantenga SSH disponible para recuperación. Una confirmación administrativa no reemplaza pruebas funcionales de agentes/RDP/SSH.

Las contraseñas de archivos solo se usan en memoria. Los archivos se normalizan en un área temporal root-only; las claves temporales se eliminan al completar/cancelar o durante la limpieza de preparaciones caducadas. No se devuelven claves por HTTP ni se incluyen en auditorías. Los certificados instalados y sus generaciones previas se conservan protegidos para recuperación.

Cada acción exige contraseña y MFA nuevos; la autorización general de 15 minutos no los sustituye. El gestor rechaza solicitudes reutilizadas, de otro administrador, preparadas sobre una configuración que ya cambió, o con rutas/comandos arbitrarios. El servicio WebAdmin continúa como `gideonweb`, sin sudo ni root.

El broker usa un socket Unix local autorizado mediante UID y permisos. systemd inicia procesos solo al solicitar operaciones; no hay un nuevo daemon Python permanente. Los timers de confirmación/limpieza son de una sola ejecución. Un servicio de arranque recupera cambios no confirmados tras un reinicio.

OneClick instala esta integración automáticamente. Para una instalación anterior es necesario actualizar primero el código de la aplicación con el paquete actualizado; después puede registrar los componentes con:

```bash
sudo bash /opt/gideon/web/app/deploy/ubuntu/INSTALL-GIDEON-TLS-MANAGER.sh
sudo systemctl restart gideon-web-admin.service
```

El registrador no copia ni actualiza por sí solo una versión antigua de WebAdmin. Let’s Encrypt desde la web requiere el paquete Ubuntu `certbot` (incluido en los requisitos del OneClick actualizado). El broker no instala paquetes ni acepta términos automáticamente. Si la emisión ACME tuvo éxito pero después se revierte GIDEON, el certificado emitido puede seguir en Certbot; no se revoca ni se elimina de forma automática.

Para diagnosticar en Ubuntu:

```bash
sudo systemctl status gideon-tls-manager.socket gideon-tls-recovery.service
sudo journalctl -u 'gideon-tls-*' --since '-30 minutes' --no-pager
```

No publique el socket ni entregue acceso al grupo `gideonweb` a otros usuarios. La descarga **CA pública de laboratorio** entrega únicamente el certificado público de la CA, nunca su clave.

### Desde consola

Puede utilizar un certificado por hostname o un único SAN/wildcard que cubra ambos. El instalador admite:

- `pem`: certificado servidor y cadena intermedia en `fullchain.pem`, más su clave privada PEM.
- `pfx`: archivo `.pfx`/`.p12` con certificado, cadena y clave privada. La contraseña se solicita oculta y no se guarda.
- Para una CA corporativa/privada: indique además el bundle PEM de CA raíz de confianza. Para certificados públicos se usa el almacén de CA de Ubuntu.

Suba los archivos por SFTP/SCP a una carpeta privada, por ejemplo `/root/gideon-certificates` con modo `0700`, archivos `0600`. No los incluya en el ZIP transportable, repositorio, chat ni carpeta web pública. Si una clave PEM está cifrada, también se solicita su contraseña de forma oculta.

Después de instalar, vuelva a abrir el asistente sin reinstalar GIDEON:

```bash
sudo bash /opt/gideon/web/app/deploy/ubuntu/CONFIGURE-GIDEON-EXTERNAL.sh
```

Ejemplo de validación PEM sin cambiar servicios:

```bash
sudo bash /opt/gideon/web/app/deploy/ubuntu/CONFIGURE-GIDEON-EXTERNAL.sh \
  --mode pem --web-host admin.example.com --agent-host agents.example.com \
  --admin-cidr 203.0.113.8/32 \
  --web-cert /root/gideon-certificates/admin-fullchain.pem \
  --web-key /root/gideon-certificates/admin.key \
  --agent-cert /root/gideon-certificates/agents-fullchain.pem \
  --agent-key /root/gideon-certificates/agents.key
```

Agregue `--apply` únicamente para aplicar esa configuración. El asistente interactivo aplica tras solicitar los datos. Antes de publicar se verifican SAN, vigencia, cadena, uso servidor y coincidencia clave/certificado. Se respaldan configuraciones y se prueban HTTPS WebAdmin/Gateway. Si falla, se restauran configuraciones previas y servicios. Las claves anteriores se conservan protegidas para recuperación; no se borran automáticamente.

Cambiar solo un certificado renovado bajo la misma CA/dominio normalmente no exige reconfigurar agentes. Cambiar URL, puerto o CA puede exigir actualizar agentes existentes; la herramienta pide confirmación. No modifica la CA cliente ni desactiva mTLS. Un certificado servidor NO reemplaza los certificados cliente de mTLS.

Si cargó antes una CA del Gateway desde la pantalla Seguridad de WebAdmin, ese override tiene prioridad sobre el archivo de configuración. Si no confía en el nuevo certificado, la herramienta bloquea el cambio: desactive ese override desde WebAdmin y repita el asistente. Elegir `later` al reemplazar certificados conserva la configuración y la renovación existentes.

## Certificados que ya existen en la nube

Se pueden importar solo si dispone del certificado/cadena Y su clave privada exportable. Un archivo `.cer` sin clave privada no basta. Los certificados Google-managed permanecen administrados por Google y se utilizan en servicios compatibles, como un balanceador; no se trasladan como un PFX a Ubuntu. Para ese diseño se debe preparar una integración distinta y verificar WebSockets y mTLS de agentes. No cambie a terminación TLS en un proxy sin revisar ese requisito.

## DNS y reglas Google Cloud

Ejemplo, sustituya nombres e IP por los reales:

| Registro | Destino |
|---|---|
| `admin.example.com` A | IP externa fija de la VM |
| `agents.example.com` A | La misma IP externa fija |

Permita TCP/443 desde los agentes y TCP/9443 exclusivamente desde IPs administrativas. Permita TCP/22 solo desde administración (o use IAP). TCP/80 se necesita si elige HTTP-01. No publique 4822 ni los puertos internos de staging 28443/29443. No es necesario publicar RDP/3389 ni SSH de los equipos agente para el túnel inverso soportado; GIDEON y el agente deben tener la conectividad propia de cada función.

El instalador mantiene un bloque identificado en `/etc/hosts` exclusivamente para resolver localmente los nombres GIDEON a loopback: así las conexiones internas validan certificados públicos por su nombre real sin exigir SAN de localhost. Rechaza entradas ajenas en conflicto y restaura el bloque al fallar. El DNS público se configura por separado.

Si UFW/firewalld ya está activo, un administrador debe añadir reglas equivalentes sin bloquear SSH. El control por CIDR de WebAdmin protege HTTP y WebSocket, ignora cabeceras `X-Forwarded-For` no confiables y mantiene MFA/RBAC.

## Verificación desde otra PC

Con Python en una PC externa, ejecute la herramienta incluida en el bundle:

```bash
python installers/tools/verify_gideon_public_endpoints.py \
  --admin-url https://admin.example.com:9443 \
  --agent-url https://agents.example.com \
  --expected-ip 203.0.113.20
```

Para CA privada agregue `--ca ruta/gideon-root-ca.pem`. Después pruebe login+MFA, enrolamiento de un agente, WebSocket/túnel inverso, RDP/SSH según modalidad, transferencia, backup y reinicio. Un health check no prueba todas esas funciones.

Referencias oficiales: [Google Certificate Manager](https://docs.cloud.google.com/certificate-manager/docs/core-components), [desafíos Let's Encrypt](https://letsencrypt.org/docs/challenge-types/), [Certbot y renovaciones](https://eff-certbot.readthedocs.io/en/stable/using.html).
