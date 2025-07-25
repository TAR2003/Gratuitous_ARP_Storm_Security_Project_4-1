FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    net-tools \
    iputils-ping \
    tcpdump \
    tshark \
    iproute2 \
    arp-scan \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy observer-specific files
COPY arp_analyzer.py .
COPY observer_main.py .
COPY web_monitor.py .
COPY utils.py .

# Create directories
RUN mkdir -p logs results captures

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Expose monitoring ports
EXPOSE 8080 8081

# Set default command
CMD ["python", "observer_main.py"]
