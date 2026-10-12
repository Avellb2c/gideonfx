# GIDEON Remote Control 6.3.4-rc25

## Objetivo
Corregir el upgrade real del Agent Windows, el runtime CPython embebido y completar el ciclo de releases estable desde WebAdmin.

## Cambios
- Agent 2.3.8: `python311._pth` incorpora explícitamente la raíz GIDEON (`..\..`), por lo que `gideon_agent_http` y los demás módulos locales son importables en una PC limpia sin `PYTHONPATH` ni Python global.
- El smoke-test deja de insertar manualmente la raíz de aplicación; ahora reproduce el arranque real del Agent y falla antes de emitir un instalador roto.
- Los scripts PowerShell del instalador se empaquetan en UTF-8 con BOM para evitar mojibake en Windows PowerShell 5.1.
- Upgrade/migración in-place: el instalador busca identidad existente en Program Files, Program Files (x86), ProgramData, registro Uninstall y la tarea programada GIDEONAgent. Si encuentra token/identidad válidos los preserva y no vuelve a pedir sede.
- Navegación Web: botones Volver usan historial solo con referrer seguro del mismo origen y siempre tienen fallback explícito.
- Releases Web: construir bundle stable site-neutral, publicar DRAFT, aprobar/revocar y `Publicar + distribuir`; la aprobación usa fallback compatible de API cuando corresponde.
- Ninguno de estos cambios modifica Defender, OpenSSH, Firewall/UFW, puertos 22/443 ni servicios de terceros.

## Validación nativa pendiente
El código y los tests se validan en el entorno de build. La confirmación final del EXE requiere una Windows de prueba: 1) upgrade sobre Agent legado y 2) instalación limpia.
