FROM python:3.9-slim-bullseye

# Set environment variables for better network handling
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    linux-libc-dev \
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
    pip install --timeout 200 --retries 5 --no-cache-dir flask flask-socketio requests)

# Copy web monitor files
COPY monitor_main.py .
COPY static/ static/
COPY templates/ templates/
COPY utils.py .

# Create directories
RUN mkdir -p logs results captures

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=monitor_main.py
ENV FLASK_ENV=production

# Expose web interface port
EXPOSE 8080

# Set default command
CMD ["python", "monitor_main.py"]
