@echo off
title FixAI Real-Time Endpoint Security Agent
echo =====================================================================
echo   FixAI Real-Time Endpoint Security Agent
echo   Streaming live hardware & security telemetry to Cloud Backend:
echo   https://fixai-backend.onrender.com
echo =====================================================================
echo.
cd /d "%~dp0fixai-guardian\local_agent"
"C:\Users\Nishita Singh\AppData\Local\Programs\Python\Python311\python.exe" main.py
pause
