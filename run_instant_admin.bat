@echo off
schtasks /run /tn "PingTesterAdmin" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Task 'PingTesterAdmin' not found.
    echo Running setup_instant_admin.bat first...
    call "%~dp0setup_instant_admin.bat"
)
