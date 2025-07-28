FROM python:3.9-slim-bullseye

# Set environment variables for better network handling
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools \
    iputils-ping \
    iproute2 \
    arp-scan \
    curl \
    wget \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app directory
WORKDIR /app

# Upgrade pip first
RUN pip install --upgrade pip --timeout 100 --retries 3

# Copy requirements and install Python dependencies with fallback
COPY requirements.txt .
RUN pip install --timeout 100 --retries 3 --no-cache-dir -r requirements.txt \
    || pip install --timeout 200 --retries 5 --no-cache-dir -r requirements.txt \
    || (echo "Installing core packages only..." && \
    pip install --timeout 200 --retries 5 --no-cache-dir flask psutil requests)

# Copy victim-specific files
COPY victim_main.py .
COPY utils.py .

# Create directories
RUN mkdir -p logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Expose service ports
EXPOSE 80 443 22 21 53

# Set default command
CMD ["python", "victim_main.py"]
