# Docker Build Troubleshooting Guide

## Network Connectivity Issues

The error you're experiencing is due to network connectivity problems when Docker tries to:
1. Download base images from Docker Hub
2. Install Python packages from PyPI

## Quick Solutions

### Option 1: Use the Build Scripts (Recommended)

**Windows:**
```cmd
build-containers.bat
```

**Linux/Mac:**
```bash
chmod +x build-containers.sh
./build-containers.sh
```

### Option 2: Manual Building with Retries

Try building containers one at a time with retries:

```bash
# Build each container individually
docker-compose build --no-cache attacker
docker-compose build --no-cache victim  
docker-compose build --no-cache observer
docker-compose build --no-cache web_monitor
docker-compose build --no-cache defender
```

### Option 3: Offline/Simplified Build

If network issues persist, use minimal dependencies:

```bash
# Create simplified defender container
docker build -f defender/Dockerfile.simple -t defender-simple defender/
```

## Network Troubleshooting

### Check Connectivity
```bash
# Test Docker Hub access
curl -I https://index.docker.io/v1/

# Test PyPI access  
curl -I https://pypi.org/simple/

# Test DNS resolution
nslookup registry-1.docker.io
nslookup files.pythonhosted.org
```

### Common Network Issues

1. **Corporate Firewall/Proxy**
   - Configure Docker to use proxy
   - Use VPN to bypass restrictions
   - Contact IT to whitelist Docker/PyPI domains

2. **DNS Issues**
   - Change DNS servers (8.8.8.8, 1.1.1.1)
   - Restart Docker daemon
   - Check hosts file

3. **ISP Blocking**
   - Use VPN
   - Try different network
   - Use mobile hotspot temporarily

### Docker Configuration

Create/edit `~/.docker/config.json` for proxy settings:
```json
{
  "proxies": {
    "default": {
      "httpProxy": "http://proxy.company.com:8080",
      "httpsProxy": "http://proxy.company.com:8080"
    }
  }
}
```

### Alternative Package Sources

If PyPI is blocked, configure pip to use mirrors:
```bash
# Create pip.conf with alternative index
pip config set global.index-url https://pypi.douban.com/simple/
pip config set global.trusted-host pypi.douban.com
```

## Specific Error Solutions

### "failed to resolve source metadata for docker.io/library/python"
- **Cause**: Cannot connect to Docker Hub
- **Solution**: 
  1. Check internet connection
  2. Restart Docker daemon
  3. Use VPN if behind firewall
  4. Try building later

### "ReadTimeoutError: HTTPSConnectionPool host='files.pythonhosted.org'"
- **Cause**: PyPI download timeout
- **Solution**:
  1. Increase pip timeout in Dockerfile
  2. Use simplified requirements.txt
  3. Install packages individually
  4. Use package mirrors

### "dial tcp: lookup registry-1.docker.io: no such host"
- **Cause**: DNS resolution failure
- **Solution**:
  1. Change DNS servers
  2. Check /etc/resolv.conf
  3. Restart network services
  4. Use alternative Docker registry

## Minimal Working Setup

If all else fails, here's a minimal setup that should work:

### Simplified defender/Dockerfile:
```dockerfile
FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y iptables net-tools
RUN pip install flask psutil requests
COPY *.py ./
EXPOSE 8082
CMD ["python", "defense_main.py"]
```

### Essential commands only:
```bash
# Build only essential containers
docker-compose build attacker victim observer

# Use host network for testing
docker run --network host --privileged -v $(pwd)/defender:/app python:3.9-slim python /app/defense_main.py
```

## Verification Steps

After successful build:
```bash
# Check all images are created
docker images | grep arp

# Verify containers can start
docker-compose up -d

# Check container status
docker-compose ps

# Test network connectivity inside containers
docker-compose exec defender ping google.com
```

## Getting Help

If issues persist:
1. Run with verbose output: `docker-compose build --no-cache --progress=plain`
2. Check Docker daemon logs: `docker system events`
3. Verify Docker installation: `docker version`
4. Try building on different network/machine

## Success Indicators

Build completed successfully when you see:
- ✅ All containers show "Successfully built"
- `docker-compose ps` shows all services
- No error messages in `docker-compose logs`
- Web interfaces accessible on localhost ports
