@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist .venv\installed-2.txt goto run
echo Installing libraries (1-2 minutes)...
if not exist .venv\Scripts\python.exe python -m venv .venv || goto fail
.venv\Scripts\python -m pip install --upgrade pip -q
.venv\Scripts\python -m pip install -r requirements.txt || goto fail
echo ok> .venv\installed-2.txt
:run
start "" .venv\Scripts\pythonw.exe remote_desktop.py
exit /b
:fail
echo Install failed - please install Python 3 from python.org (tick "Add to PATH")
pause
