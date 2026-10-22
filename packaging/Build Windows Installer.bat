@echo off
setlocal
REM =====================================================================
REM  Build the NetRemote Windows installer - double-click this file on Windows
REM  Output: Network tools\Apps\Windows\NetRemote-Setup-<version>.exe
REM  Needs: Python 3 (python.org, "Add to PATH") + Inno Setup 6 (jrsoftware.org)
REM =====================================================================
cd /d "%~dp0"
set "PKG=%~dp0"
for %%I in ("%~dp0..") do set "APPDIR=%%~fI"
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
set "OUT=%ROOT%\Apps\Windows"
set "WORK=%PKG%.work"
set "NAME=NetRemote"

echo ==============================================
echo   Build %NAME% installer  (Windows)
echo ==============================================
if not exist "%APPDIR%\remote_desktop.py" (echo remote_desktop.py not found & goto fail)

where python >nul 2>nul
if errorlevel 1 (
  echo Python not found. Install Python 3 from https://www.python.org/downloads/windows/
  echo and tick "Add python.exe to PATH", then run this again.
  goto fail
)

set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo Inno Setup 6 not found - trying to install it with winget ...
  winget install -e --id JRSoftware.InnoSetup --accept-package-agreements --accept-source-agreements
  set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
  if not exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
)
if not exist "%ISCC%" (
  echo Please install Inno Setup 6 from https://jrsoftware.org/isdl.php then run this again.
  goto fail
)

if not exist "%WORK%\venv\Scripts\python.exe" (
  echo Preparing build tools - first time 1-3 minutes, internet required ...
  python -m venv "%WORK%\venv" || goto fail
)
set "V=%WORK%\venv\Scripts\python.exe"
"%V%" -m pip install -q --upgrade pip
"%V%" -m pip install -q --upgrade pyinstaller mss Pillow pynput cryptography sounddevice numpy opencv-python-headless || goto fail

"%V%" -c "import re;print(re.search(r'^VERSION = .([^\x22]+).', open(r'%APPDIR%\remote_desktop.py', encoding='utf-8').read(), re.M).group(1))" > "%WORK%\ver.txt" || goto fail
set /p VER=<"%WORK%\ver.txt"
if "%VER%"=="" (echo Could not read VERSION & goto fail)

set "ADDENV="
if exist "%APPDIR%\.env" (
  set ADDENV=--add-data "%APPDIR%\.env;."
  echo Embedding .env [Relay settings] into the program
)
echo.
echo Building %NAME% %VER% ...
"%V%" -m PyInstaller --noconfirm --clean --windowed --log-level WARN --distpath "%WORK%\dist" --workpath "%WORK%\build" --specpath "%WORK%" --name "%NAME%" --icon "%APPDIR%\assets\netremote.ico" --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 %ADDENV% "%APPDIR%\remote_desktop.py" || goto fail

echo.
echo Building installer ...
if not exist "%OUT%" mkdir "%OUT%"
"%ISCC%" /Q "/DAppVersion=%VER%" "/DSourceDir=%WORK%\dist\%NAME%" "/DOutputDir=%OUT%" "%PKG%netremote.iss" || goto fail

echo.
echo DONE:  %OUT%\NetRemote-Setup-%VER%.exe
explorer "%OUT%"
pause
exit /b 0

:fail
echo.
echo BUILD FAILED - see the messages above.
pause
exit /b 1
