#!/bin/bash
# build-containers.sh - Robust container building script with network retry logic

set -e

echo "===================="
echo "Container Build Script"
echo "===================="

# Function to build with retries
build_with_retry() {
    local container_name=$1
    local max_attempts=3
    local attempt=1
    
    echo "Building $container_name..."
    
    while [ $attempt -le $max_attempts ]; do
        echo "Attempt $attempt/$max_attempts for $container_name"
        
        if docker-compose build --no-cache --pull $container_name; then
            echo "✅ $container_name built successfully"
            return 0
        else
            echo "❌ Attempt $attempt failed for $container_name"
            if [ $attempt -lt $max_attempts ]; then
                echo "Waiting 10 seconds before retry..."
                sleep 10
            fi
            attempt=$((attempt + 1))
        fi
    done
    
    echo "❌ Failed to build $container_name after $max_attempts attempts"
    return 1
}

# Function to build with simplified requirements
build_simplified() {
    local container_name=$1
    
    echo "Attempting simplified build for $container_name..."
    
    # Create temporary simplified Dockerfile
    if [ "$container_name" = "defender" ]; then
        cat > defender/Dockerfile.simple << 'EOF'
FROM python:3.9-slim-bullseye

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install system tools
RUN apt-get update && apt-get install -y iptables net-tools curl && rm -rf /var/lib/apt/lists/*

# Install only essential Python packages
RUN pip install --no-cache-dir flask psutil scapy netifaces requests

# Copy application files
COPY *.py ./
COPY *.json ./
RUN mkdir -p logs results captures

EXPOSE 8082 8083
CMD ["python", "defense_main.py"]
EOF
        
        docker build -f defender/Dockerfile.simple -t "${PWD##*/}_defender" defender/
    fi
}

# Check Docker and docker-compose
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed or not in PATH"
    exit 1
fi

# Check network connectivity
echo "Testing network connectivity..."
if curl -s --max-time 10 https://index.docker.io/v1/ > /dev/null; then
    echo "✅ Docker Hub is reachable"
else
    echo "⚠️ Docker Hub connectivity issues detected"
    echo "Building may be slow or fail. Consider using a VPN or different network."
fi

if curl -s --max-time 10 https://pypi.org/simple/ > /dev/null; then
    echo "✅ PyPI is reachable"
else
    echo "⚠️ PyPI connectivity issues detected"
    echo "Python package installation may fail."
fi

# Build containers in order of dependencies
containers=("attacker" "victim" "observer" "web_monitor" "defender")

for container in "${containers[@]}"; do
    echo ""
    echo "Building $container..."
    
    if build_with_retry "$container"; then
        continue
    else
        echo "Standard build failed for $container"
        
        if [ "$container" = "defender" ]; then
            echo "Attempting simplified build..."
            if build_simplified "$container"; then
                echo "✅ Simplified build succeeded for $container"
                continue
            fi
        fi
        
        echo "❌ All build attempts failed for $container"
        echo "You may need to:"
        echo "1. Check your internet connection"
        echo "2. Try building again later"
        echo "3. Use a VPN if behind a firewall"
        echo "4. Build containers individually: docker-compose build $container"
        exit 1
    fi
done

echo ""
echo "🎉 All containers built successfully!"
echo ""
echo "Next steps:"
echo "1. Start the environment: docker-compose up -d"
echo "2. Check container status: docker-compose ps"
echo "3. View logs: docker-compose logs -f"
echo "4. Access defense dashboard: http://localhost:8082"
echo ""
