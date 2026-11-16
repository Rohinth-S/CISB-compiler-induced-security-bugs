@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   CISB-Guard: Compiler-Induced Security Bug Lab Launcher
echo ============================================================

where docker >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Docker detected. Building and starting container...
    docker compose up --build -d
) else (
    echo [*] Docker not found on host. Launching native Python backend...
    start "CISB-Guard Server" /b python backend/app.py
)

echo [*] Waiting for CISB-Guard dashboard service to become healthy at http://localhost:8080...
:wait_loop
powershell -Command "try { $r = Invoke-WebRequest -Uri 'http://localhost:8080/api/health' -UseBasicParsing -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    timeout /t 1 /nobreak >nul
    goto wait_loop
)

echo [+] CISB-Guard dashboard is online and healthy!
echo [*] Opening dashboard in browser: http://localhost:8080
start http://localhost:8080

echo.
echo Press Ctrl+C in this window or close it to stop the demo.
pause
