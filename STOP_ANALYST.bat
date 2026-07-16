@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0STOP_ANALYST.ps1"
if errorlevel 1 pause
