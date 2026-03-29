@echo off
setlocal enableextensions

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%VSH_Project_MVP"
set "PS_SCRIPT=%SCRIPT_DIR%setup_and_run.ps1"

if not exist "%PROJECT_DIR%\requirements.txt" (
  echo [VSH] ERROR: Could not find VSH_Project_MVP\requirements.txt
  echo [VSH] Extract the zip fully and run this file from the extracted root folder.
  pause
  exit /b 1
)

if not exist "%PS_SCRIPT%" (
  echo [VSH] ERROR: setup_and_run.ps1 not found: %PS_SCRIPT%
  pause
  exit /b 1
)

echo [VSH] Starting setup and run workflow...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -ProjectDir "%PROJECT_DIR%"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo [VSH] Failed with exit code %EXIT_CODE%.
  echo [VSH] Press any key to close.
  pause >nul
  exit /b %EXIT_CODE%
)

echo [VSH] Completed.
exit /b 0
