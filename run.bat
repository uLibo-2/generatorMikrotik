@echo off
title MikroTik Network Tool

echo.
echo  MikroTik Network Tool v1.0
echo  Network Engineer Suite
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.10+
    echo  https://www.python.org/downloads/
    pause
    exit /b 1
)

echo  Checking dependencies...
pip install fastapi uvicorn python-multipart --quiet --disable-pip-version-check

echo  Starting server...
echo  Browser will open at http://localhost:8899
echo  Press Ctrl+C to stop
echo.

python app.py
pause
