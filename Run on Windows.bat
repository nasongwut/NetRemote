@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist .venv\installed.txt goto run
echo Installing for the first time (1-2 minutes)...
python -m venv .venv || goto fail
.venv\Scripts\python -m pip install --upgrade pip -q
.venv\Scripts\python -m pip install -r requirements.txt || goto fail
echo ok> .venv\installed.txt
:run
start "" .venv\Scripts\pythonw.exe remote_desktop.py
exit /b
:fail
echo Install failed - please install Python 3 from python.org (tick "Add to PATH")
pause
