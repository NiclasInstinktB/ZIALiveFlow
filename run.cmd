@echo off
REM Thin wrapper around serve.py for Windows.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo No virtual environment found. Run: python install.py
  exit /b 1
)
".venv\Scripts\python.exe" serve.py %*
