@echo off
call "%~dp0deploy\windows\INSTALL-GIDEON-WINDOWS.cmd" %*
exit /b %errorlevel%
