@echo off
title PENTIGENT Launcher
echo ============================================
echo   PENTIGENT AI Pentest System - One-click
echo ============================================
echo.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1"
echo.
echo Press any key to close...
pause >nul