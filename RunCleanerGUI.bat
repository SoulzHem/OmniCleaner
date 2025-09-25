@echo off
:: OmniCleaner - GUI Launcher
:: Version: 1.0
:: Author: SoulzHem
:: Description: Launches the OmniCleaner GUI application

setlocal EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%scripts\OmniCleaner.GUI.ps1"

:: Check if GUI script exists
if not exist "%PS1%" (
    echo [ERROR] GUI script not found: %PS1%
    echo Please ensure all files are in the correct directory.
    pause
    exit /b 1
)

:: Display startup message
echo Starting OmniCleaner...
echo This tool helps remove shortcut viruses and malware.
echo.

:: Launch PowerShell with security parameters
start "OmniCleaner GUI" /wait powershell.exe -NoProfile -ExecutionPolicy Bypass -Sta -File "%PS1%"

:: Check exit code
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Application exited with code: %ERRORLEVEL%
)

endlocal
exit /b 0
