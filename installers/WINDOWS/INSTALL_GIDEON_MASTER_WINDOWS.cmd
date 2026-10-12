@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo GIDEON REMOTE CONTROL - MASTER WINDOWS INSTALLER PRE-RC31
echo OneClick adaptativo: Hyper-V o Docker Desktop segun Windows
echo ============================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
  echo [INFO] Solicitando permisos de Administrador...
  set "GIDEON_ELEVATE_FILE=%~f0"
  set "GIDEON_ELEVATE_ARGS=%*"
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { $p=@{FilePath=$env:GIDEON_ELEVATE_FILE;Verb='RunAs'}; if($env:GIDEON_ELEVATE_ARGS){$p.ArgumentList=$env:GIDEON_ELEVATE_ARGS}; Start-Process @p; exit 0 } catch { exit 10 }"
  if errorlevel 1 (
    echo [ERROR] La elevacion fue cancelada o fallo.
    pause
    exit /b 10
  )
  exit /b 0
)


echo [PRECHECK] Validando sintaxis PowerShell del instalador...
powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0..\tools\Test-GideonPowerShellSyntax.ps1"

if errorlevel 1 (
  echo POWERSHELL_SYNTAX_PRECHECK=FAILED
  echo No se iniciara la instalacion.
  pause
  exit /b 21
)


echo [PRECHECK] Validando compatibilidad Windows PowerShell 5.1...
powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0..\tools\Test-GideonPowerShellCompatibility.ps1"
if errorlevel 1 (
  echo POWERSHELL_COMPAT_PRECHECK=FAILED
  echo No se ejecutara ningun cambio hasta corregir la compatibilidad.
  pause
  exit /b 22
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-GIDEONMasterWindows.ps1" %*
set "RC=%ERRORLEVEL%"

if "%RC%"=="194" (
  echo.
  echo [ATTENTION] Se habilitaron componentes de virtualizacion y Windows requiere reinicio.
  echo El OneClick ya registro la continuacion automatica para el proximo arranque o inicio de sesion.
  choice /C SN /N /M "Reiniciar ahora? [S/N]: "
  if errorlevel 2 (
    echo Reinicie Windows cuando sea seguro. GIDEON continuara automaticamente.
    pause
    exit /b 194
  )
  shutdown.exe /r /t 15 /c "GIDEON OneClick continuara automaticamente despues del reinicio."
  exit /b 194
)

if not "%RC%"=="0" (
  echo.
  echo INSTALL=FAILED exit=%RC%
  echo Revise el ZIP GIDEON-INSTALL-DIAGNOSTICS generado por el instalador.
  pause
  exit /b %RC%
)

echo.
echo INSTALL=PASS
pause
exit /b 0
