@echo off
REM Thin wrapper around manage.py for Windows.
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" manage.py %*
) else (
  python manage.py %*
)
