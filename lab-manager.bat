@echo off
REM Docker Lab Management Script for ARP DoS Storm (Windows)
REM Educational/Research Purpose Only

setlocal EnableDelayedExpansion

set LAB_NAME=arp-dos-storm-lab
set COMPOSE_FILE=docker-compose.yml

:main
if "%1"=="" goto show_help
if "%1"=="check" goto check_prerequisites
if "%1"=="build" goto build_lab
if "%1"=="start" goto start_lab
if "%1"=="stop" goto stop_lab
if "%1"=="restart" goto restart_lab
if "%1"=="status" goto show_status
if "%1"=="logs" goto view_logs
if "%1"=="shell" goto access_container
if "%1"=="attack" goto run_attack
if "%1"=="export" goto export_results
if "%1"=="cleanup" goto cleanup_lab
if "%1"=="help" goto show_help
echo Unknown command: %1
goto show_help

:print_header
echo ================================================================
echo %~1
echo ================================================================
goto :eof

:print_status
echo [INFO] %~1
goto :eof

:print_warning
echo [WARNING] %~1
goto :eof

:print_error
echo [ERROR] %~1
goto :eof

:check_prerequisites
call :print_header "Checking Prerequisites"

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    call :print_error "Docker is not installed or not in PATH"
    exit /b 1
)
call :print_status "Docker found"

REM Check Docker Compose
docker-compose --version >nul 2>&1
if errorlevel 1 (
    call :print_error "Docker Compose is not installed or not in PATH"
    exit /b 1
)
call :print_status "Docker Compose found"

REM Check if Docker daemon is running
docker info >nul 2>&1
if errorlevel 1 (
    call :print_error "Docker daemon is not running"
    exit /b 1
)
call :print_status "Docker daemon is running"

REM Check compose file exists
if not exist "%COMPOSE_FILE%" (
    call :print_error "docker-compose.yml not found in current directory"
    exit /b 1
)
call :print_status "Docker Compose file found"
goto :eof

:build_lab
call :print_header "Building ARP DoS Storm Lab Containers"
call :check_prerequisites
if errorlevel 1 exit /b 1

call :print_status "Building containers..."
docker-compose build
call :print_status "Containers built successfully!"
goto :eof

:start_lab
call :print_header "Starting ARP DoS Storm Lab"
call :check_prerequisites
if errorlevel 1 exit /b 1

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "results" mkdir results
if not exist "captures" mkdir captures

call :print_status "Starting containers..."
docker-compose up -d

call :print_status "Waiting for containers to initialize..."
timeout /t 10 /nobreak >nul

call :print_status "Container status:"
docker-compose ps

call :print_status "Lab started successfully!"
call :print_status "Web dashboard: http://localhost:8080"
call :print_status "Victim services: http://localhost:80"
goto :eof

:stop_lab
call :print_header "Stopping ARP DoS Storm Lab"

call :print_status "Stopping containers..."
docker-compose down
call :print_status "Lab stopped successfully!"
goto :eof

:restart_lab
call :print_header "Restarting ARP DoS Storm Lab"
call :stop_lab
timeout /t 5 /nobreak >nul
call :start_lab
goto :eof

:show_status
call :print_header "ARP DoS Storm Lab Status"

call :print_status "Container status:"
docker-compose ps

echo.
call :print_status "Container logs (last 10 lines each):"

echo.
echo === Attacker Logs ===
docker-compose logs --tail=10 attacker 2>nul || echo Attacker container not running

echo.
echo === Victim Logs ===
docker-compose logs --tail=10 victim 2>nul || echo Victim container not running

echo.
echo === Observer Logs ===
docker-compose logs --tail=10 observer 2>nul || echo Observer container not running
goto :eof

:view_logs
if "%2"=="" (
    call :print_status "Showing logs for all containers..."
    docker-compose logs -f
) else (
    call :print_status "Showing logs for %2..."
    docker-compose logs -f %2
)
goto :eof

:access_container
if "%2"=="" (
    call :print_error "Please specify container name: attacker, victim, or observer"
    exit /b 1
)

call :print_status "Accessing %2 container..."
docker-compose exec %2 /bin/bash
goto :eof

:run_attack
if "%2"=="basic" (
    call :print_status "Running basic ARP storm attack..."
    docker-compose exec attacker python attacker_main.py
) else if "%2"=="intense" (
    call :print_status "Running high-intensity attack..."
    docker-compose exec attacker ./arp_storm --subnet 10.0.1 --duration 30 --threads 8 --rate 500
) else if "%2"=="poison" (
    call :print_status "Running targeted poisoning attack..."
    docker-compose exec attacker python attacker_main.py --poison
) else (
    call :print_status "Available attack types: basic, intense, poison"
    call :print_status "Usage: %0 attack <type>"
)
goto :eof

:export_results
call :print_header "Exporting Lab Results"

set "export_dir=lab_export_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "export_dir=!export_dir: =0!"

mkdir "!export_dir!"

call :print_status "Exporting logs..."
if exist "logs" xcopy /E /I "logs" "!export_dir!\logs" >nul 2>&1

call :print_status "Exporting results..."
if exist "results" xcopy /E /I "results" "!export_dir!\results" >nul 2>&1

call :print_status "Exporting captures..."
if exist "captures" xcopy /E /I "captures" "!export_dir!\captures" >nul 2>&1

call :print_status "Exporting container logs..."
docker-compose logs > "!export_dir!\container_logs.txt" 2>nul

call :print_status "Results exported to !export_dir!"
goto :eof

:cleanup_lab
call :print_header "Cleaning Up ARP DoS Storm Lab"

call :print_warning "This will remove all containers, networks, and volumes!"
set /p "confirm=Are you sure? (y/N): "

if /i "!confirm!"=="y" (
    call :print_status "Stopping and removing containers..."
    docker-compose down -v --remove-orphans
    
    call :print_status "Removing images..."
    docker-compose down --rmi all
    
    call :print_status "Cleaning up Docker system..."
    docker system prune -f
    
    call :print_status "Cleanup completed!"
) else (
    call :print_status "Cleanup cancelled"
)
goto :eof

:show_help
echo ARP DoS Storm Lab Management Script
echo Educational/Research Purpose Only
echo.
echo Usage: %0 ^<command^> [options]
echo.
echo Commands:
echo   check          Check prerequisites
echo   build          Build lab containers
echo   start          Start the lab
echo   stop           Stop the lab
echo   restart        Restart the lab
echo   status         Show lab status
echo   logs [name]    View logs (all or specific container)
echo   shell ^<name^>   Access container shell (attacker/victim/observer)
echo   attack ^<type^>  Run attack scenario (basic/intense/poison)
echo   export         Export lab results
echo   cleanup        Clean up everything
echo   help           Show this help
echo.
echo Examples:
echo   %0 start                    # Start the lab
echo   %0 shell attacker          # Access attacker container
echo   %0 logs observer           # View observer logs
echo   %0 attack basic            # Run basic attack
echo.
echo Web Interfaces:
echo   http://localhost:8080      # Monitoring dashboard
echo   http://localhost:80        # Victim services
goto :eof
