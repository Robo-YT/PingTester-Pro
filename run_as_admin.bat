@echo off
cd /d "%~dp0"

:: 1. If instant admin task is already configured, run it silently with zero prompts
schtasks /query /tn "PingTesterAdmin" >nul 2>&1
if %errorLevel% EQU 0 (
    schtasks /run /tn "PingTesterAdmin" >nul 2>&1
    exit /b
)

:: 2. Check if already elevated
net session >nul 2>&1
if %errorLevel% EQU 0 (
    if exist "%~dp0PingTester.exe" (
        start "" "%~dp0PingTester.exe"
    ) else (
        start "" pythonw "%~dp0main.py"
    )
    exit /b
)

:: 3. Request elevation without opening extra CMD windows
if exist "%~dp0PingTester.exe" (
    powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process '%~dp0PingTester.exe' -WorkingDirectory '%~dp0' -Verb RunAs"
) else (
    powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process pythonw -ArgumentList '\"%~dp0main.py\"' -WorkingDirectory '\"%~dp0\"' -Verb RunAs"
)
exit /b
