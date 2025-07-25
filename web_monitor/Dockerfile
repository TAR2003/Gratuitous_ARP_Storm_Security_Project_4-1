FROM python:3.9-alpine

# Install system dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    linux-headers

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
