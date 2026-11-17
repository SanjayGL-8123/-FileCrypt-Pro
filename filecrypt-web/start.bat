@echo off
title FileCrypt Server Launcher
cd /d "%~dp0"

echo =======================================================
echo          Starting FileCrypt Local Server...
echo =======================================================

:: Try Node.js first
where node >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] Node.js detected. Launching server.js...
    start http://127.0.0.1:8080
    node server.js
    goto end
)

:: Try Python
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] Python detected. Launching server.py...
    start http://127.0.0.1:8080
    python server.py
    goto end
)

:: Try compiled binary
if exist "filecrypt-server.exe" (
    echo [OK] Compiled binary found. Launching filecrypt-server.exe...
    start http://127.0.0.1:8080
    filecrypt-server.exe
    goto end
)

echo.
echo [!] Neither Node.js, Python, nor a compiled C server was found.
echo Opening browser with client-side WebCrypto engine...
start public\index.html

:end
pause
