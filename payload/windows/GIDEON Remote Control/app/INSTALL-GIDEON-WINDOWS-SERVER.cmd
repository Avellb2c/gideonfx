@echo off
call "%~dp0deploy\windows\INSTALL-GIDEON-WINDOWS-SERVER.cmd" %*
exit /b %errorlevel%
