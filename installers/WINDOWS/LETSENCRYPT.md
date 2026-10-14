# Let’s Encrypt en Windows

Gideon Rx puede instalar y renovar un certificado público en Windows mediante
`win-acme` (cliente ACMEv2). Esta integración sólo aplica al OneClick de
Windows; Ubuntu conserva su flujo independiente con Certbot y `systemd`.

## Requisitos

- Un FQDN público para WebAdmin y, opcionalmente, otro para Gateway.
- Registros DNS `A`/`AAAA` apuntando a la máquina y NAT/firewall de la nube
  configurados por el operador.
- TCP/80 accesible desde Internet durante la validación HTTP-01. El OneClick
  crea únicamente la regla local de Windows `GIDEON Let's Encrypt HTTP-01`.
- Un correo válido para avisos de renovación y aceptación de los términos de
  Let’s Encrypt.

El instalador no modifica DNS, el firewall de la nube, el router ni los
agentes ya instalados. Si el puerto 80 está ocupado o el DNS aún no resuelve,
la emisión falla sin reemplazar la PKI local.

## Configuración durante la instalación

Ejecute PowerShell como Administrador:

```powershell
& .\installers\WINDOWS\Install-GIDEONMasterWindows.ps1 `
  -LetsEncryptWebHost admin.example.com `
  -LetsEncryptGatewayHost agents.example.com `
  -LetsEncryptEmail ops@example.com
```

Para validar con el entorno de pruebas de Let’s Encrypt use
`-LetsEncryptEnvironment staging`; esos certificados no son de confianza para
usuarios finales. `-SkipLetsEncryptIssue` guarda la configuración y el cliente
sin solicitar todavía el certificado.

El OneClick descarga el ZIP x64 de `win-acme`, comprueba su SHA-256, lo deja en
`C:\Program Files\GIDEON Remote Control\tools\win-acme` y crea el estado en
`C:\ProgramData\GIDEON Remote Control\config\windows-letsencrypt.json`.
Los PEM quedan en `acme\certs`. La tarea programada propia de win-acme ejecuta
el hook GIDEON después de cada renovación; el hook valida certificado y clave,
actualiza WebAdmin/Gateway de forma atómica, guarda backup y reinicia sólo esos
dos servicios.

## Verificación y reparación

Desde la carpeta instalada:

```powershell
$py = 'C:\Program Files\GIDEON Remote Control\venv\Scripts\python.exe'
$helper = 'C:\Program Files\GIDEON Remote Control\app\deploy\windows\gideon_windows_acme.py'
& $py $helper status --data-root 'C:\ProgramData\GIDEON Remote Control'
& $py $helper validate --data-root 'C:\ProgramData\GIDEON Remote Control'
```

La pantalla **Infraestructura → TLS y acceso externo** muestra si win-acme,
la tarea de renovación y el certificado están activos. La CA privada GIDEON
se mantiene para mTLS de Agents; Let’s Encrypt sólo reemplaza el certificado
de servidor presentado por WebAdmin y Gateway.

## Dependencia de terceros

`win-acme` conserva su propia licencia y avisos. El paquete no redistribuye
credenciales ni claves privadas; revise `THIRD-PARTY-NOTICES.md` antes de crear
un kit offline.
