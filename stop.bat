@echo off
setlocal
cd /d "%~dp0"

echo Stopping containers...
docker compose down

endlocal
