# GIDEON Remote Control 6.3.4-rc24 · Agent 2.3.7

RC24 hace que el instalador Windows sea autocontenido de forma fail-closed. El builder no puede emitir un EXE si faltan `runtime\python\python.exe`, CPython 3.11.9 x64, VC runtime, wheels, `runtime-manifest.json` o componentes GIDEON obligatorios.

- El PC final no necesita Python, pip ni librerías Python globales.
- El Agent usa su runtime privado dentro de GIDEON y nunca depende del PATH del usuario.
- El manifest del runtime se valida archivo por archivo con SHA-256 antes de compilar el EXE.
- El packager EXE repite la validación como última barrera.
- Si un payload antiguo/recortado llega sin runtime, la contingencia descarga CPython oficial dentro de GIDEON, valida firma Authenticode de Python Software Foundation y no modifica PATH/asociaciones.
- `gideon_script_host.ps1`, worker, contrato de Jobs y `gideon_common` siguen siendo obligatorios.
