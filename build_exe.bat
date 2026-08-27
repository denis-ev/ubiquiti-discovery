@echo off
REM ---------------------------------------------------------------------
REM build_exe.bat - build ubnt_scan.exe on a Windows machine.
REM
REM Needs Python 3.8+ installed and on PATH (python.org or the Store build).
REM Everything is done inside a throwaway virtual environment, so nothing is
REM installed into your system Python.
REM
REM Results: dist\ubnt_scan_gui.exe - windowed app, for field techs
REM          dist\ubnt_scan.exe     - command line version
REM Both are single files you can copy to any Windows machine, including
REM ones with no Python installed.
REM ---------------------------------------------------------------------
setlocal

cd /d "%~dp0"

echo.
echo === ubnt_scan.exe build ===
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found on PATH.
    echo Install Python 3.8 or newer and tick "Add python.exe to PATH".
    echo Download: https://www.python.org/downloads/windows/
    goto :fail
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo Using Python %PYVER%

if not exist "ubnt_scan.py" (
    echo ERROR: ubnt_scan.py not found next to this script.
    goto :fail
)

echo.
echo [1/4] Creating build environment...
if exist ".buildenv" rmdir /s /q ".buildenv"
python -m venv .buildenv
if errorlevel 1 (
    echo ERROR: could not create a virtual environment.
    goto :fail
)

echo [2/4] Installing PyInstaller...
call ".buildenv\Scripts\python.exe" -m pip install --upgrade pip --quiet
call ".buildenv\Scripts\python.exe" -m pip install pyinstaller --quiet
if errorlevel 1 (
    echo ERROR: could not install PyInstaller. Check your internet connection
    echo or proxy settings.
    goto :fail
)

echo [3/4] Building executables ^(this takes a couple of minutes^)...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

echo    ... command line version
call ".buildenv\Scripts\pyinstaller.exe" ^
    --onefile ^
    --console ^
    --name ubnt_scan ^
    --clean ^
    --noconfirm ^
    ubnt_scan.py
if errorlevel 1 (
    echo ERROR: command line build failed. See the output above.
    goto :fail
)

if exist "ubnt_gui.py" (
    echo    ... GUI version
    REM --windowed means no console window appears behind the GUI.
    call ".buildenv\Scripts\pyinstaller.exe" ^
        --onefile ^
        --windowed ^
        --name ubnt_scan_gui ^
        --clean ^
        --noconfirm ^
        ubnt_gui.py
    if errorlevel 1 (
        echo ERROR: GUI build failed. See the output above.
        goto :fail
    )
) else (
    echo    ... ubnt_gui.py not found, skipping GUI build
)

echo [4/4] Cleaning up...
rmdir /s /q ".buildenv"
if exist "build" rmdir /s /q "build"
if exist "ubnt_scan.spec" del /q "ubnt_scan.spec"
if exist "ubnt_scan_gui.spec" del /q "ubnt_scan_gui.spec"

echo.
if exist "dist\ubnt_scan.exe" (
    echo ============================================
    if exist "dist\ubnt_scan_gui.exe" echo  Built: dist\ubnt_scan_gui.exe  ^(GUI^)
    echo  Built: dist\ubnt_scan.exe      ^(command line^)
    echo ============================================
    echo.
    echo Copy those files anywhere. No Python needed on the target.
    echo Hand ubnt_scan_gui.exe to field techs - it is point and click.
    echo.
    echo First run notes:
    echo  - Windows Defender SmartScreen will warn about an unknown
    echo    publisher. Choose "More info" then "Run anyway". This happens
    echo    because the exe is not code-signed.
    echo  - Allow it through the Windows Firewall when prompted, or it
    echo    cannot receive discovery replies.
    echo.
) else (
    echo ERROR: build reported success but dist\ubnt_scan.exe is missing.
    goto :fail
)

pause
exit /b 0

:fail
echo.
echo Build did not complete.
pause
exit /b 1
