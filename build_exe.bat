@echo off
echo ==========================================================
echo    Building Ping Tester & Network Diagnostics Standalone EXE
echo ==========================================================
echo.

:: Ensure dependencies are present
python -m pip install -r requirements.txt

:: Build standalone executable with CustomTkinter and PIL assets bundled
python -m PyInstaller --noconfirm --onedir --windowed ^
    --name "PingTester" ^
    --collect-all "customtkinter" ^
    --collect-all "PIL" ^
    --add-data "core;core" ^
    --add-data "ui;ui" ^
    main.py

echo.
echo ==========================================================
echo    Build Complete!
echo    Executable is located in: dist\PingTester\PingTester.exe
echo ==========================================================
pause
