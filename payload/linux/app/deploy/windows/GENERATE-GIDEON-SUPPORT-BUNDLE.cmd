@echo off
setlocal
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File','%~dp0Generate-GideonWindowsSupportBundle.ps1')"
  exit /b %errorlevel%
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Generate-GideonWindowsSupportBundle.ps1"
exit /b %errorlevel%
