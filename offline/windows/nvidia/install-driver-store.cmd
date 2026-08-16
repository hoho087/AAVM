@echo off
setlocal EnableExtensions

net session >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)

set "DRIVER_INF=%~dp0Display.Driver\nvmdi.inf"
set "LOG_DIR=%ProgramData%\KVM-AAVM"
set "LOG_FILE=%LOG_DIR%\nvidia-610.88-pnputil.log"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%DRIVER_INF%" (
  echo ERROR: Missing %DRIVER_INF%
  echo ERROR: Missing %DRIVER_INF% > "%LOG_FILE%"
  pause
  exit /b 2
)

echo Staging NVIDIA 610.88 WHQL for MSI RTX 5080...
echo INF: %DRIVER_INF%
pnputil.exe /add-driver "%DRIVER_INF%" /install > "%LOG_FILE%" 2>&1
set "RESULT=%ERRORLEVEL%"
type "%LOG_FILE%"

if not "%RESULT%"=="0" (
  echo.
  echo Driver staging failed with exit code %RESULT%.
  echo Log: %LOG_FILE%
  pause
  exit /b %RESULT%
)

echo.
echo Driver package was added to the Windows Driver Store.
echo Shut Windows down completely, then return the VM to GPU passthrough mode.
echo Log: %LOG_FILE%
pause
exit /b 0
