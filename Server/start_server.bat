@echo off
setlocal EnableExtensions
REM =====================================================================
REM  NetRemote Relay Server (Windows) - start / reload / stop
REM
REM    start_server.bat            start the Server (if already running -> reload)
REM    start_server.bat reload     stop and start again (after editing .env / updating relay_server.py)
REM    start_server.bat stop       stop the Server
REM    start_server.bat status     is it running?
REM    start_server.bat log        watch the log live (Ctrl+C to leave - the Server keeps running)
REM    start_server.bat fg         run in this window (Ctrl+C = stop)
REM
REM  First run: creates .venv in this folder and installs requirements.txt
REM  Every run: uses .venv (re-installs only when requirements.txt changes)
REM  Runs hidden in the background - you can close this window. Log: server.log
REM =====================================================================
chcp 65001 >nul
cd /d "%~dp0"
set "HERE=%~dp0"
set "VPY=%HERE%.venv\Scripts\python.exe"
set "CMD=%~1"
if "%CMD%"=="" set "CMD=start"

if /i "%CMD%"=="start"   goto start
if /i "%CMD%"=="reload"  goto reload
if /i "%CMD%"=="restart" goto reload
if /i "%CMD%"=="stop"    goto stop
if /i "%CMD%"=="status"  goto status
if /i "%CMD%"=="log"     goto log
if /i "%CMD%"=="fg"      goto fg
echo Usage: start_server.bat [start^|reload^|stop^|status^|log^|fg]
exit /b 1

REM ---------------------------------------------------------------------
:start
call :find_pids
if defined PIDS (
  echo Server is already running - reloading ...
  call :kill
)
call :venv || exit /b 1
call :launch
exit /b %errorlevel%

:reload
call :find_pids
if defined PIDS (call :kill) else (echo [Server was not running])
call :venv || exit /b 1
call :launch
exit /b %errorlevel%

:stop
call :find_pids
if not defined PIDS (
  echo Server is not running
  exit /b 0
)
call :kill
exit /b 0

:status
call :find_pids
if defined PIDS (echo [ON]  Server is running - PID %PIDS%) else (echo [OFF] Server is not running)
exit /b 0

:log
if not exist server.log type nul > server.log
powershell -NoProfile -Command "Get-Content -Path 'server.log' -Tail 50 -Wait -Encoding UTF8"
exit /b 0

:fg
call :find_pids
if defined PIDS (
  echo Stopping the background Server first ...
  call :kill
)
call :venv || exit /b 1
echo Starting NetRemote Relay Server - press Ctrl+C to stop
set "RELAY_PIDFILE=%HERE%.server.pid"
"%VPY%" relay_server.py
exit /b %errorlevel%

REM ---------------------------------------------------------------------
REM  helpers
REM ---------------------------------------------------------------------
:venv
if exist "%VPY%" (
  "%VPY%" -c "" >nul 2>&1 || (
    echo Existing .venv is broken - recreating ...
    rmdir /s /q .venv
  )
)
if not exist "%VPY%" (
  echo Creating .venv ...
  where py >nul 2>nul
  if errorlevel 1 (python -m venv .venv) else (py -3 -m venv .venv)
)
if not exist "%VPY%" (
  echo Could not create .venv - install Python 3 from https://www.python.org/downloads/windows/
  echo and tick "Add python.exe to PATH", then run this again.
  pause
  exit /b 1
)
set "NEED="
if not exist ".venv\installed.txt" set "NEED=1"
if not defined NEED (
  "%VPY%" -c "import os,sys; sys.exit(0 if os.path.getmtime('requirements.txt') > os.path.getmtime(r'.venv\installed.txt') else 1)" && set "NEED=1"
)
if defined NEED (
  echo Installing libraries from requirements.txt ...
  "%VPY%" -m pip install -q --upgrade pip
  "%VPY%" -m pip install -q -r requirements.txt && (echo ok> ".venv\installed.txt") || echo [warn] Library install failed - the Server still runs ^(Server Monitor shows less detail^)
)
exit /b 0

:launch
echo Starting NetRemote Relay Server in the background ...
del /q .server.pid >nul 2>&1
set "PYTHONUNBUFFERED=1"
set "RELAY_PIDFILE=%HERE%.server.pid"
powershell -NoProfile -Command "Start-Process -FilePath '%VPY%' -ArgumentList 'relay_server.py' -WorkingDirectory '%HERE:~0,-1%' -WindowStyle Hidden -RedirectStandardOutput 'server.log' -RedirectStandardError 'server.err.log'"
timeout /t 3 /nobreak >nul
call :find_pids
if defined PIDS (
  echo [OK] Running - PID %PIDS%   ^(live log: start_server.bat log^)
  powershell -NoProfile -Command "if (Test-Path server.log) { Get-Content server.log -Tail 5 -Encoding UTF8 }"
  exit /b 0
)
echo [FAILED] Server did not start - details:
if exist server.err.log type server.err.log
if exist server.log type server.log
exit /b 1

:find_pids
REM  relay_server.py writes its own PID to .server.pid (also after "Restart" on the web page)
set "PIDS="
if not exist .server.pid exit /b 0
set "SPID="
set /p SPID=<.server.pid
if not defined SPID exit /b 0
tasklist /FI "PID eq %SPID%" /NH 2>nul | find /i "python" >nul && set "PIDS=%SPID%"
exit /b 0

:kill
echo Stopping Server (PID %PIDS%) ...
taskkill /PID %PIDS% /T /F >nul 2>&1
timeout /t 1 /nobreak >nul
del /q .server.pid >nul 2>&1
exit /b 0
