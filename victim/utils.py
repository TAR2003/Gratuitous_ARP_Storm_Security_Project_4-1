#!/usr/bin/env python3
"""
Common utilities for Docker containers
"""

import os
import json
import time
import socket
import subprocess
from datetime import datetime

def get_container_ip():
    """Get container's IP address by running 'hostname -I'"""
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        return result.stdout.strip().split()[0]
    except:
        return '127.0.0.1'

def log_to_file(container_name, event_type, message, data=None):
    """Log event to a shared /app/logs directory"""
    """All containers should use this function to log events"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'container': container_name,
        'event_type': event_type,
        'message': message,
        'data': data or {}
    }
    
    log_dir = '/app/logs'
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"{container_name}_{datetime.now().strftime('%Y%m%d')}.log")
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def check_port_open(host, port, timeout=5):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def wait_for_service(host, port, timeout=60):
    """Wait for a service to become available"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if check_port_open(host, port):
            return True
        time.sleep(2)
    return False

def ping_host(host, count=1, timeout=5):
    """Ping a host"""
    """This is how we can check if host is reachable"""
    try:
        result = subprocess.run(['ping', '-c', str(count), '-W', str(timeout), host],
                              capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def get_network_interfaces():
    """Get network interface information"""
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        return result.stdout
    except:
        return "Unable to get network interfaces"

def get_arp_table():
    """Get current ARP table"""
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        return result.stdout
    except:
        return "Unable to get ARP table"

def save_results(data, filename_prefix='result'):
    """Save results to JSON file"""
    results_dir = '/app/results'
    os.makedirs(results_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.json"
    filepath = os.path.join(results_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    return filepath
