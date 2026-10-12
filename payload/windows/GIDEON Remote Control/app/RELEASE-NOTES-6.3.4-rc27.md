# GIDEON Remote Control 6.3.4-rc27 — SSH Vault Folder Import

RC27 corrige la carga de identidades SSH privadas en WebAdmin. El selector anterior filtraba por extensiones `.pem/.key/.ppk`, lo que ocultaba claves OpenSSH habituales como `id_ed25519` o `id_rsa` que no tienen extensión.

## Cambios

- Selección individual sin filtro de extensión; validación criptográfica por contenido.
- Importación opcional de carpeta `.ssh` desde Chrome/Edge mediante `webkitdirectory`.
- Máximo 64 archivos y 2 MiB por selección; máximo 128 KiB por clave.
- Se omiten automáticamente claves públicas, `known_hosts`, `config` y archivos no relacionados.
- Las claves válidas se cifran inmediatamente en el vault GIDEON; no existe staging de clave privada en `uploads`.
- Password + MFA siguen siendo obligatorios para importar.
- PuTTY PPK se detecta de forma explícita y se rechaza con mensaje claro para conversión a OpenSSH/PEM; no se ejecutan conversores externos ni se instalan paquetes del sistema.
- No modifica `ssh-agent`, `sshd`, `authorized_keys`, Defender ni Firewall/UFW.

## Componentes

- Control Plane/WebAdmin: 6.3.4-rc27
- Agent: 2.3.9 (sin cambios)
- Gateway: 2.4.1 (sin cambios)
