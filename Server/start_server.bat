@echo off
setlocal EnableExtensions
REM =====================================================================
REM  NetRemote Relay Server (Windows)
REM
REM    start_server.bat              start the Server in the background (if already running -> reload)
REM    start_server.bat reload       stop and start again (after editing .env / updating relay_server.py)
REM    start_server.bat stop         stop the Server
REM    start_server.bat status       is it running?
REM    start_server.bat log          watch the log live (Ctrl+C to leave - the Server keeps running)
REM    start_server.bat fg           run in this window (Ctrl+C = stop)
REM
REM    start_server.bat install      start automatically when Windows starts - no window, no login needed
REM                                  (Task Scheduler as SYSTEM + Windows Firewall rule; asks for Administrator)
REM    start_server.bat uninstall    remove the automatic start
REM
REM  First run: creates .venv in this folder and installs requirements.txt
REM  Log: server.log  (errors: server.err.log)
REM =====================================================================
chcp 65001 >nul
cd /d "%~dp0"
set "HERE=%~dp0"
set "SRVDIR=%HERE:~0,-1%"
set "VPY=%HERE%.venv\Scripts\python.exe"
set "VPYW=%HERE%.venv\Scripts\pythonw.exe"
set "TASKNAME=NetRemote Relay Server"
set "CMD=%~1"
if "%CMD%"=="" set "CMD=start"

set "TASK="
schtasks /Query /TN "%TASKNAME%" >nul 2>&1 && set "TASK=1"

if /i "%CMD%"=="start"     goto start
if /i "%CMD%"=="reload"    goto reload
if /i "%CMD%"=="restart"   goto reload
if /i "%CMD%"=="stop"      goto stop
if /i "%CMD%"=="status"    goto status
if /i "%CMD%"=="log"       goto log
if /i "%CMD%"=="fg"        goto fg
if /i "%CMD%"=="install"   goto install
if /i "%CMD%"=="uninstall" goto uninstall
echo Usage: start_server.bat [start^|reload^|stop^|status^|log^|fg^|install^|uninstall]
exit /b 1

REM ---------------------------------------------------------------------
:start
call :need_admin_if_task || exit /b 0
call :find_pids
if defined PIDS (
  echo Server is already running - reloading ...
  call :kill
)
call :venv || exit /b 1
call :launch
goto done

:reload
call :need_admin_if_task || exit /b 0
call :find_pids
if defined PIDS (call :kill) else (echo [Server was not running])
call :venv || exit /b 1
call :launch
goto done

:stop
call :need_admin_if_task || exit /b 0
call :find_pids
if not defined PIDS (
  echo Server is not running
  goto done
)
call :kill
goto done

:status
call :find_pids
if defined PIDS (echo [ON]  Server is running - PID %PIDS%) else (echo [OFF] Server is not running)
if defined TASK (echo       Starts automatically with Windows: YES) else (echo       Starts automatically with Windows: no  ^(start_server.bat install^))
exit /b 0

:log
if not exist server.log type nul > server.log
powershell -NoProfile -Command "Get-Content -Path 'server.log' -Tail 50 -Wait -Encoding UTF8"
exit /b 0

:fg
if defined TASK (
  echo The Server is installed to start with Windows. Use "start_server.bat uninstall" first to run it in a window.
  exit /b 1
)
call :find_pids
if defined PIDS (
  echo Stopping the background Server first ...
  call :kill
)
call :venv || exit /b 1
echo Starting NetRemote Relay Server - press Ctrl+C to stop
"%VPY%" relay_server.py --pidfile .server.pid
exit /b %errorlevel%

:install
call :is_admin || (call :elevate install & exit /b 0)
call :venv || goto done
call :find_pids
if defined PIDS call :kill
echo Installing "%TASKNAME%" - starts with Windows, hidden, restarts itself if it stops ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $d=$env:SRVDIR; $a=New-ScheduledTaskAction -Execute $env:VPYW -Argument 'relay_server.py --log server.log --pidfile .server.pid' -WorkingDirectory $d; $t=New-ScheduledTaskTrigger -AtStartup; $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew; Register-ScheduledTask -TaskName $env:TASKNAME -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null; $p1='5910'; $p2='5911'; $f=Join-Path $d '.env'; if (Test-Path $f) { foreach ($l in Get-Content $f) { if ($l -match '^\s*RELAY_PORT\s*=\s*(\d+)') { $p1=$matches[1] }; if ($l -match '^\s*RELAY_WEB_PORT\s*=\s*(\d+)') { $p2=$matches[1] } } }; Remove-NetFirewallRule -DisplayName $env:TASKNAME -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName $env:TASKNAME -Direction Inbound -Protocol TCP -LocalPort @($p1,$p2) -Action Allow | Out-Null; Write-Host ('Firewall: allowed TCP ' + $p1 + ', ' + $p2); Start-ScheduledTask -TaskName $env:TASKNAME"
if errorlevel 1 (
  echo [FAILED] Could not install the startup task - see the message above.
  goto done
)
set "TASK=1"
timeout /t 3 /nobreak >nul
call :find_pids
if defined PIDS (echo [OK] Installed and running - PID %PIDS%) else (echo [OK] Installed - check "start_server.bat log" if it does not come up)
echo The Server now starts by itself every time Windows starts, without any window.
goto done

:uninstall
call :is_admin || (call :elevate uninstall & exit /b 0)
call :find_pids
if defined PIDS call :kill
powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName $env:TASKNAME -Confirm:$false -ErrorAction SilentlyContinue; Remove-NetFirewallRule -DisplayName $env:TASKNAME -ErrorAction SilentlyContinue"
echo [OK] Automatic start removed. Start manually with: start_server.bat
goto done

REM ---------------------------------------------------------------------
REM  helpers
REM ---------------------------------------------------------------------
:done
REM  keep the window open when this was double-clicked / opened as Administrator
echo %CMDCMDLINE% | find /i "%~nx0" >nul && pause
exit /b 0

:is_admin
net session >nul 2>&1
exit /b %errorlevel%

:elevate
echo Asking for Administrator permission ...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%1' -Verb RunAs"
exit /b 0

:need_admin_if_task
REM  when installed as a startup task the Server runs as SYSTEM -> controlling it needs Administrator
if not defined TASK exit /b 0
call :is_admin && exit /b 0
call :elevate %CMD%
exit /b 1

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
  echo ^(tick "Add python.exe to PATH" - and for "install", choose "Install for all users"^), then run this again.
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
del /q .server.pid >nul 2>&1
if defined TASK (
  echo Starting the "%TASKNAME%" task ...
  schtasks /Run /TN "%TASKNAME%" >nul
) else (
  echo Starting NetRemote Relay Server in the background ...
  powershell -NoProfile -Command "Start-Process -FilePath $env:VPYW -ArgumentList 'relay_server.py','--log','server.log','--pidfile','.server.pid' -WorkingDirectory $env:SRVDIR -WindowStyle Hidden"
)
timeout /t 3 /nobreak >nul
call :find_pids
if defined PIDS (
  echo [OK] Running - PID %PIDS%   ^(live log: start_server.bat log^)
  powershell -NoProfile -Command "if (Test-Path server.log) { Get-Content server.log -Tail 5 -Encoding UTF8 }"
  exit /b 0
)
echo [FAILED] Server did not start - last lines of the log:
powershell -NoProfile -Command "if (Test-Path server.log) { Get-Content server.log -Tail 20 -Encoding UTF8 }"
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
if defined TASK schtasks /End /TN "%TASKNAME%" >nul 2>&1
taskkill /PID %PIDS% /T /F >nul 2>&1
timeout /t 1 /nobreak >nul
del /q .server.pid >nul 2>&1
exit /b 0
