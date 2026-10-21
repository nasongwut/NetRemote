@echo off
setlocal
REM =====================================================================
REM  Build "NetRemote.exe" for Windows - double-click this file on Windows
REM  Output: Network tools\Apps\Windows\NetRemote.exe
REM =====================================================================
cd /d "%~dp0"
set "PKG=%~dp0"
for %%I in ("%~dp0..") do set "APPDIR=%%~fI"
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "OUT=%ROOT%\Apps\Windows"
set "WORK=%PKG%.work"
set "NAME=NetRemote"

echo ==============================================
echo   Build %NAME%.exe  (Windows)
echo ==============================================
if not exist "%APPDIR%\remote_desktop.py" (echo remote_desktop.py not found & goto fail)

where python >nul 2>nul
if errorlevel 1 (
  echo Python not found. Install Python 3 from https://www.python.org/downloads/windows/
  echo and tick "Add python.exe to PATH", then run this again.
  goto fail
)
if not exist "%WORK%\venv\Scripts\python.exe" (
  echo Preparing build tools - first time 1-3 minutes, internet required ...
  python -m venv "%WORK%\venv" || goto fail
)
set "V=%WORK%\venv\Scripts\python.exe"
"%V%" -m pip install -q --upgrade pip
"%V%" -m pip install -q --upgrade pyinstaller mss Pillow pynput cryptography || goto fail

set "ADDENV="
if exist "%APPDIR%\.env" (
  set ADDENV=--add-data "%APPDIR%\.env;."
  echo Embedding .env [Relay settings] into the program
)
echo.
echo Building %NAME%.exe ...
"%V%" -m PyInstaller --noconfirm --clean --onefile --windowed --log-level WARN --distpath "%WORK%\dist" --workpath "%WORK%\build" --specpath "%WORK%" --name "%NAME%" --icon "%APPDIR%\assets\netremote.ico" --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 %ADDENV% "%APPDIR%\remote_desktop.py" || goto fail

if not exist "%OUT%" mkdir "%OUT%"
copy /y "%WORK%\dist\%NAME%.exe" "%OUT%\" >nul || goto fail
echo.
echo DONE:  %OUT%\%NAME%.exe
explorer "%OUT%"
pause
exit /b 0

:fail
echo.
echo BUILD FAILED - see the messages above.
pause
exit /b 1
