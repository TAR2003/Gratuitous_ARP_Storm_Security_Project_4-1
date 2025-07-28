# Use a more stable base image
FROM python:3.9-slim-bullseye

# Set environment variables for better pip behavior
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies for defense capabilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    net-tools \
    tcpdump \
    arp-scan \
    nmap \
    iputils-ping \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app directory
WORKDIR /app

# Upgrade pip first with retry mechanism
RUN pip install --upgrade pip --timeout 100 --retries 3

# Copy requirements and install Python dependencies with robust settings
COPY requirements.txt .
RUN pip install --timeout 100 --retries 3 --no-cache-dir -r requirements.txt \
    || pip install --timeout 200 --retries 5 --no-cache-dir -r requirements.txt \
    || (echo "Installing packages individually..." && \
    pip install --timeout 200 --retries 5 --no-cache-dir scapy psutil flask flask-socketio netifaces && \
    pip install --timeout 200 --retries 5 --no-cache-dir requests pyyaml colorama rich)

# Copy defender-specific files
COPY arp_defense_engine.py .
COPY defense_main.py .
COPY defense_config.json .
COPY utils.py .

# Create directories
RUN mkdir -p logs results captures

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Expose monitoring ports
EXPOSE 8082 8083

# Set default command
CMD ["python", "defense_main.py"]
