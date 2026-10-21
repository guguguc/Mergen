@echo off
rem Bypass local ExecutionPolicy so this can run from cmd when .ps1 is blocked.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0lift_four_ultra.ps1" %*
exit /b %ERRORLEVEL%
