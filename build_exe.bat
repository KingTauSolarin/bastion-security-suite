@echo off
setlocal
cd /d "%~dp0"
set APPNAME=Bastion
set SCRIPT=bastion_v4.py
set ICON=icon.ico

echo.
echo ===============================================
echo   BASTION - WINDOWS BUILD
echo ===============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH.
    echo Install Python 3.10+ and enable "Add python.exe to PATH".
    pause
    exit /b 1
)

if not exist "%SCRIPT%" (
    echo [ERROR] %SCRIPT% is missing from this folder.
    pause
    exit /b 1
)

echo [1/4] Installing runtime and build dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Runtime dependency installation failed.
    pause
    exit /b 1
)
python -m pip install pyinstaller
if errorlevel 1 (
    echo [ERROR] PyInstaller installation failed.
    pause
    exit /b 1
)

set ICONFLAG=
if exist "%ICON%" set ICONFLAG=--icon="%ICON%"

echo [2/4] Cleaning old build output...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "%APPNAME%.spec" del /q "%APPNAME%.spec"

echo [3/4] Building %APPNAME%.exe...
python -m PyInstaller --name "%APPNAME%" --onefile --windowed %ICONFLAG% --clean "%SCRIPT%"
if errorlevel 1 (
    echo [ERROR] PyInstaller failed. Try build_exe_debug.bat for diagnostics.
    pause
    exit /b 1
)

echo.
echo [4/4] BUILD COMPLETE: dist\%APPNAME%.exe
echo Note: database location depends on the working directory at launch.
start "" "dist"
pause
endlocal
