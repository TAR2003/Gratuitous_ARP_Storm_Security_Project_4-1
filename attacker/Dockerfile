FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    net-tools \
    iputils-ping \
    tcpdump \
    iproute2 \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy attacker-specific files
COPY arp_dos_storm.py .
COPY arp_storm.cpp .
COPY Makefile .
COPY attacker_main.py .
COPY utils.py .

# Create directories
RUN mkdir -p logs results captures

# Compile C++ tool
RUN make clean && make

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Expose any needed ports (none for attacker)
# EXPOSE 

# Set default command
CMD ["python", "attacker_main.py"]
