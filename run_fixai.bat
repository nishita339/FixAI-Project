@echo off
title FixAI - System Launcher
color 0A
echo ===================================================
echo             Starting FixAI Project
echo ===================================================
echo.

cd /d "%~dp0"

:: Auto-detect Python executable (py -3.11, python, or direct path)
set "PYTHON_CMD=python"
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=py -3.11"
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
            set "PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python311\python.exe""
        )
    )
)

echo [1/4] Starting Backend Server (FastAPI on Port 8000)...
start "FixAI - Backend API" cmd /k "cd backend && %PYTHON_CMD% -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo [2/4] Starting Frontend Dashboard (Vite on Port 5173)...
start "FixAI - Web Dashboard" cmd /k "cd fixai-guardian && npm run dev"

timeout /t 3 /nobreak >nul

echo [3/4] Starting Edge AI Agent Daemon (Hardware Telemetry & EDR)...
start "FixAI - Edge Agent" cmd /k "cd fixai-guardian\local_agent && %PYTHON_CMD% main.py"

timeout /t 2 /nobreak >nul

echo [4/4] Opening Web Dashboard in browser...
start http://localhost:5173/dashboard

echo.
echo ===================================================
echo  All services started successfully!
echo  - Backend API:       http://localhost:8000/docs
echo  - Web Dashboard:     http://localhost:5173/dashboard
echo ===================================================
timeout /t 5 >nul
exit
