@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-GIDEON-Windows.ps1" %*
set rc=%errorlevel%
if not "%rc%"=="0" (
  echo.
  echo GIDEON Remote Control no pudo completar la instalacion. Codigo %rc%.
  pause
)
exit /b %rc%
