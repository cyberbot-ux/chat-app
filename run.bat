@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "PROJECT=cs350"
set "PORT=54678"

REM ---- compose file detection ----
set "ROOT_COMPOSE=%~dp0docker-compose.yml"
set "SERVER_COMPOSE=%~dp0server\docker-compose.yml"

if exist "%ROOT_COMPOSE%" (
  set "COMPOSE_FILE=%ROOT_COMPOSE%"
) else if exist "%SERVER_COMPOSE%" (
  set "COMPOSE_FILE=%SERVER_COMPOSE%"
) else (
  echo [X] docker-compose.yml not found.
  echo     Looked for:
  echo     %ROOT_COMPOSE%
  echo     %SERVER_COMPOSE%
  pause
  exit /b 1
)

echo ==================================================
echo  CS350 Launcher (Docker + Client)
echo  Compose: %COMPOSE_FILE%
echo  Port:    %PORT%
echo ==================================================

REM ---- docker running? ----
docker info >nul 2>&1
if errorlevel 1 (
  echo [X] Docker is not running. Start Docker Desktop.
  pause
  exit /b 1
)
echo [OK] Docker is running.

REM ---- clean start to avoid duplicates ----
echo [..] Cleaning old containers (prevents duplicates)...
docker compose -p %PROJECT% -f "%COMPOSE_FILE%" down --remove-orphans >nul 2>&1

REM ---- start stack ----
echo [..] Starting Mongo + Server...
docker compose -p %PROJECT% -f "%COMPOSE_FILE%" up -d --build
if errorlevel 1 (
  echo [X] docker compose failed.
  echo ----- compose logs -----
  docker compose -p %PROJECT% -f "%COMPOSE_FILE%" logs --no-color --tail=120
  echo -----------------------
  pause
  exit /b 1
)

echo [OK] Containers started.
echo.
docker compose -p %PROJECT% -f "%COMPOSE_FILE%" ps
echo.

REM ---- check if server port is listening ----
echo [..] Checking if port %PORT% is listening...
powershell -NoProfile -Command ^
  "try { $c = Test-NetConnection -ComputerName 127.0.0.1 -Port %PORT% -WarningAction SilentlyContinue; if($c.TcpTestSucceeded){ exit 0 } else { exit 1 } } catch { exit 1 }"
if errorlevel 1 (
  echo [X] Server is NOT reachable on 127.0.0.1:%PORT%
  echo ----- server logs (latest) -----
  docker logs --tail 120 chat-server
  echo -------------------------------
  echo Tip: if client still points to 64898, change it to %PORT%.
  pause
  exit /b 1
)
echo [OK] Server is reachable on 127.0.0.1:%PORT%
echo.

REM ---- launch client ----
echo [..] Launching client...
cd /d "%~dp0client"
set CHAT_HOST=127.0.0.1
set CHAT_PORT=%PORT%

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" new_client.py
) else (
  py new_client.py
)

endlocal
