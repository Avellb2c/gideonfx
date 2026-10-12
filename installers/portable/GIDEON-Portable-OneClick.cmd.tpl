@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo GIDEON RX - PORTABLE ONECLICK
echo Perfil: @@PROFILE@@
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

set "GIDEON_PORTABLE_INSTALLER_ARGS=%*"
powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0Invoke-GideonPortableOneClick.ps1" ^
  -PackageRoot "%~dp0." ^
  -Profile "@@PROFILE@@"
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo.
  echo PORTABLE_ONECLICK=FAILED exit=%RC%
  pause
  exit /b %RC%
)

echo.
echo PORTABLE_ONECLICK=PASS
pause
exit /b 0
