@echo off
cd /d "%~dp0"
if exist "%~dp0PingTester.exe" (
    start "" "%~dp0PingTester.exe"
    exit /b
)
start "" pythonw "%~dp0main.py"
