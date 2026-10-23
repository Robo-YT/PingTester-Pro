@echo off
cd /d "%~dp0"
title Setup Instant Admin Launcher (Ping Tester)

:: Check for Administrator elevation
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo =======================================================================
    echo Requesting One-Time Administrator Elevation to create Silent Shortcut...
    echo =======================================================================
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0setup_instant_admin.bat\"\"' -Verb RunAs"
    exit /b
)

echo [1/3] Detecting application launcher...
set "TARGET_CMD="
set "ICON_PATH="

if exist "%~dp0PingTester.exe" (
    set "TARGET_CMD=\"%~dp0PingTester.exe\""
    set "ICON_PATH=%~dp0PingTester.exe,0"
    echo Found standalone executable: PingTester.exe
) else (
    set "PYTHONW_PATH="
    if exist "C:\Python314\pythonw.exe" (
        set "PYTHONW_PATH=C:\Python314\pythonw.exe"
    ) else (
        for /f "delims=" %%I in ('where pythonw.exe 2^>nul') do set "PYTHONW_PATH=%%I"
    )
    if "%PYTHONW_PATH%"=="" (
        echo [ERROR] Neither PingTester.exe nor pythonw.exe was found!
        pause
        exit /b 1
    )
    set "TARGET_CMD=\"%PYTHONW_PATH%\" \"%~dp0main.py\""
    set "ICON_PATH=%PYTHONW_PATH%,0"
    echo Found Python environment: %PYTHONW_PATH%
)

echo [2/3] Registering elevated task in Windows Task Scheduler (PingTesterAdmin)...

schtasks /create /tn "PingTesterAdmin" /tr "%TARGET_CMD%" /sc ONCE /st 00:00 /rl HIGHEST /f >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [ERROR] Failed to register task with Task Scheduler.
    pause
    exit /b 1
)

echo [3/3] Creating Desktop Shortcut for Instant Zero-Prompt Launch...
set "DESKTOP_PATH=%USERPROFILE%\Desktop"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP_PATH%\Ping Tester (Admin).lnk'); $s.TargetPath = 'wscript.exe'; $s.Arguments = '\"%~dp0run_instant_admin.vbs\"'; $s.WorkingDirectory = '%~dp0'; $s.IconLocation = '%ICON_PATH%'; $s.Description = 'Launch Ping Tester Elevated with Zero UAC Prompts'; $s.Save()"

echo.
echo =======================================================================
echo SUCCESS! INSTANT ADMIN LAUNCHER CONFIGURED!
echo =======================================================================
echo A desktop shortcut 'Ping Tester (Admin)' has been created.
echo You can now launch Ping Tester elevated anytime:
echo  1. ZERO Windows UAC Yes/No prompts!
echo  2. ZERO black CMD console windows!
echo  3. Full Administrator privileges for live Apex match packet sniffing!
echo =======================================================================
echo.
pause
