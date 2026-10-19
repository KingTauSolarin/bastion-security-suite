@echo off
setlocal
cd /d "%~dp0"
set APPNAME=Bastion-Debug
set SCRIPT=bastion_v4.py
set ICON=icon.ico

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on PATH.
    pause
    exit /b 1
)
if not exist "%SCRIPT%" (
    echo [ERROR] %SCRIPT% is missing from this folder.
    pause
    exit /b 1
)

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

if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "%APPNAME%.spec" del /q "%APPNAME%.spec"

python -m PyInstaller --name "%APPNAME%" --onefile --console %ICONFLAG% --clean "%SCRIPT%"
if errorlevel 1 (
    echo [ERROR] Debug build failed.
    pause
    exit /b 1
)

echo.
echo Debug executable: dist\%APPNAME%.exe
echo Launch it from PowerShell or Command Prompt to inspect errors.
pause
endlocal
