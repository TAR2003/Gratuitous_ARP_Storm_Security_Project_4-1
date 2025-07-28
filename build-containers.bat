@echo off
REM build-containers.bat - Windows version of container build script

echo ====================
echo Container Build Script
echo ====================

REM Function to test network connectivity
echo Testing network connectivity...
curl -s --max-time 10 https://index.docker.io/v1/ >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Docker Hub is reachable
) else (
    echo ⚠️ Docker Hub connectivity issues detected
    echo Building may be slow or fail. Consider using a VPN or different network.
)

curl -s --max-time 10 https://pypi.org/simple/ >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ PyPI is reachable
) else (
    echo ⚠️ PyPI connectivity issues detected
    echo Python package installation may fail.
)

echo.
echo Building containers with retry logic...
echo.

REM Build attacker container
echo Building attacker...
docker-compose build --no-cache attacker
if %errorlevel% neq 0 (
    echo Retrying attacker build...
    docker-compose build attacker
    if %errorlevel% neq 0 (
        echo ❌ Failed to build attacker container
        goto :error
    )
)
echo ✅ Attacker container built successfully

REM Build victim container
echo Building victim...
docker-compose build --no-cache victim
if %errorlevel% neq 0 (
    echo Retrying victim build...
    docker-compose build victim
    if %errorlevel% neq 0 (
        echo ❌ Failed to build victim container
        goto :error
    )
)
echo ✅ Victim container built successfully

REM Build observer container
echo Building observer...
docker-compose build --no-cache observer
if %errorlevel% neq 0 (
    echo Retrying observer build...
    docker-compose build observer
    if %errorlevel% neq 0 (
        echo ❌ Failed to build observer container
        goto :error
    )
)
echo ✅ Observer container built successfully

REM Build web_monitor container
echo Building web_monitor...
docker-compose build --no-cache web_monitor
if %errorlevel% neq 0 (
    echo Retrying web_monitor build...
    docker-compose build web_monitor
    if %errorlevel% neq 0 (
        echo ❌ Failed to build web_monitor container
        goto :error
    )
)
echo ✅ Web monitor container built successfully

REM Build defender container
echo Building defender...
docker-compose build --no-cache defender
if %errorlevel% neq 0 (
    echo Retrying defender build...
    docker-compose build defender
    if %errorlevel% neq 0 (
        echo ❌ Failed to build defender container
        echo Trying simplified build...
        
        REM Create simplified Dockerfile for defender
        echo FROM python:3.9-slim-bullseye > defender\Dockerfile.simple
        echo ENV PYTHONUNBUFFERED=1 >> defender\Dockerfile.simple
        echo WORKDIR /app >> defender\Dockerfile.simple
        echo RUN apt-get update ^&^& apt-get install -y iptables net-tools curl ^&^& rm -rf /var/lib/apt/lists/* >> defender\Dockerfile.simple
        echo RUN pip install --no-cache-dir flask psutil scapy netifaces requests >> defender\Dockerfile.simple
        echo COPY *.py ./ >> defender\Dockerfile.simple
        echo COPY *.json ./ >> defender\Dockerfile.simple
        echo RUN mkdir -p logs results captures >> defender\Dockerfile.simple
        echo EXPOSE 8082 8083 >> defender\Dockerfile.simple
        echo CMD ["python", "defense_main.py"] >> defender\Dockerfile.simple
        
        docker build -f defender\Dockerfile.simple -t gratuitous_arp_storm_security_project_4-1_defender defender\
        if %errorlevel% neq 0 (
            goto :error
        )
    )
)
echo ✅ Defender container built successfully

echo.
echo 🎉 All containers built successfully!
echo.
echo Next steps:
echo 1. Start the environment: docker-compose up -d
echo 2. Check container status: docker-compose ps
echo 3. View logs: docker-compose logs -f
echo 4. Access defense dashboard: http://localhost:8082
echo.
goto :end

:error
echo.
echo ❌ Build failed. You may need to:
echo 1. Check your internet connection
echo 2. Try building again later
echo 3. Use a VPN if behind a firewall
echo 4. Build containers individually: docker-compose build [container_name]
echo.
pause
exit /b 1

:end
pause
