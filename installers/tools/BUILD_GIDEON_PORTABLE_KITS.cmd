@echo off
setlocal EnableExtensions
cd /d "%~dp0\..\.."

set "GIDEON_BUNDLED_PYTHON=%CD%\payload\windows\GIDEON Remote Control\venv\Scripts\python.exe"
if not exist "%GIDEON_BUNDLED_PYTHON%" set "GIDEON_BUNDLED_PYTHON=%CD%\payload\windows\GIDEON Remote Control\runtime\python-base\python.exe"

if exist "%GIDEON_BUNDLED_PYTHON%" (
  "%GIDEON_BUNDLED_PYTHON%" "%CD%\installers\tools\build_portable_oneclick_packages.py" %*
) else (
  python "%CD%\installers\tools\build_portable_oneclick_packages.py" %*
)
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo PORTABLE_PACKAGE_BUILD=PASS
) else (
  echo PORTABLE_PACKAGE_BUILD=FAILED exit=%RC%
)
pause
exit /b %RC%
