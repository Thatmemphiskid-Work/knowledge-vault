@echo off
setlocal
if not exist "%~dp0assessment\data\catalog.json" (
  echo Catalog missing. See assessment\README.md for rebuild instructions.
  pause
  exit /b 1
)
start "" "http://127.0.0.1:8765"
"%~dp0.tools\python\python.exe" "%~dp0assessment\serve.py"
pause
