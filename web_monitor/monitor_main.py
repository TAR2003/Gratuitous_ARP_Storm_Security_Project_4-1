#!/usr/bin/env python3
"""
Web Monitoring Interface for ARP DoS Storm Lab
Real-time dashboard for attack monitoring and analysis
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request
import threading
import subprocess

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "matplotlib", "numpy", "pandas"])
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd

app = Flask(__name__)

class WebMonitor:
    """Web-based monitoring dashboard"""
    
    def __init__(self):
        self.data = {
            'logs': [],
            'attack_status': 'Normal',
            'real_time_stats': {},
            'containers': {
                'attacker': {'status': 'Unknown', 'last_seen': None},
                'victim': {'status': 'Unknown', 'last_seen': None},
                'observer': {'status': 'Unknown', 'last_seen': None}
            }
        }
        
        self.update_thread = None
        self.running = False
    
    def load_logs(self):
        """Load logs from all containers"""
        logs = []
        log_dir = '/app/logs'
        
        if os.path.exists(log_dir):
            for filename in os.listdir(log_dir):
                if filename.endswith('.log'):
                    filepath = os.path.join(log_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            for line in f:
                                try:
                                    entry = json.loads(line.strip())
                                    logs.append(entry)
                                except:
                                    pass
                    except:
                        pass
        
        # Sort by timestamp
        logs.sort(key=lambda x: x.get('timestamp', ''))
        return logs[-100:]  # Last 100 entries
    
    def load_results(self):
        """Load analysis results"""
        results = []
        results_dir = '/app/results'
        
        if os.path.exists(results_dir):
            for filename in os.listdir(results_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(results_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            result = json.load(f)
                            result['filename'] = filename
                            results.append(result)
                    except:
                        pass
        
        return results
    
    def update_data(self):
        """Update dashboard data"""
        while self.running:
            try:
                # Load logs
                self.data['logs'] = self.load_logs()
                
                # Determine attack status
                recent_logs = [log for log in self.data['logs'] 
                              if (datetime.now() - datetime.fromisoformat(log.get('timestamp', '2000-01-01'))).seconds < 300]
                
                attack_detected = any(log.get('event_type') == 'attack_detected' for log in recent_logs)
                self.data['attack_status'] = 'ATTACK DETECTED' if attack_detected else 'Normal'
                
                # Update container status
                for log in recent_logs:
                    container = log.get('container')
                    if container in self.data['containers']:
                        self.data['containers'][container]['status'] = 'Active'
                        self.data['containers'][container]['last_seen'] = log.get('timestamp')
                
                # Load results
                self.data['results'] = self.load_results()
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                print(f"Data update error: {e}")
                time.sleep(10)
    
    def start_monitoring(self):
        """Start monitoring data updates"""
        self.running = True
        self.update_thread = threading.Thread(target=self.update_data, daemon=True)
        self.update_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False

# Global monitor instance
monitor = WebMonitor()

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>ARP DoS Storm Lab - Monitoring Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        .header { 
            text-align: center; 
            margin-bottom: 30px;
            border-bottom: 2px solid rgba(255,255,255,0.3);
            padding-bottom: 20px;
        }
        .status-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .status-card { 
            background: rgba(255,255,255,0.1); 
            padding: 20px; 
            border-radius: 10px; 
            border-left: 5px solid;
        }
        .status-card.normal { border-left-color: #28a745; }
        .status-card.attack { border-left-color: #dc3545; animation: pulse 2s infinite; }
        .status-card.warning { border-left-color: #ffc107; }
        .status-card.info { border-left-color: #17a2b8; }
        
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); }
            100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); }
        }
        
        .logs-section { 
            background: rgba(0,0,0,0.3); 
            padding: 20px; 
            border-radius: 10px; 
            margin-top: 20px;
        }
        .log-entry { 
            padding: 8px; 
            margin: 5px 0; 
            border-radius: 5px; 
            background: rgba(255,255,255,0.1);
            font-family: monospace;
            font-size: 12px;
        }
        .log-attack { background: rgba(220, 53, 69, 0.3); }
        .log-normal { background: rgba(40, 167, 69, 0.2); }
        .log-warning { background: rgba(255, 193, 7, 0.2); }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 10px 0; 
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
        }
        th, td { 
            border: 1px solid rgba(255,255,255,0.2); 
            padding: 12px; 
            text-align: left; 
        }
        th { 
            background: rgba(255,255,255,0.2); 
            font-weight: bold;
        }
        
        .metric-value { 
            font-size: 2em; 
            font-weight: bold; 
            color: #fff;
        }
        .metric-label { 
            font-size: 0.9em; 
            opacity: 0.8; 
        }
        
        .attack-indicator {
            background: #dc3545;
            color: white;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-weight: bold;
            text-align: center;
            animation: blink 1s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 ARP DoS Storm Lab - Monitoring Dashboard</h1>
            <p>Real-time monitoring of ARP attack simulation</p>
            <p><strong>Current Time:</strong> {{ current_time }}</p>
        </div>
        
        {% if attack_status == 'ATTACK DETECTED' %}
        <div class="attack-indicator">
            🚨 ARP ATTACK IN PROGRESS 🚨
        </div>
        {% endif %}
        
        <div class="status-grid">
            <div class="status-card {{ 'attack' if attack_status == 'ATTACK DETECTED' else 'normal' }}">
                <h3>🛡️ Attack Status</h3>
                <div class="metric-value">{{ attack_status }}</div>
                <div class="metric-label">Network Security Status</div>
            </div>
            
            <div class="status-card info">
                <h3>🔥 Attacker</h3>
                <div class="metric-value">{{ containers.attacker.status }}</div>
                <div class="metric-label">10.0.1.10</div>
            </div>
            
            <div class="status-card info">
                <h3>🎯 Victim</h3>
                <div class="metric-value">{{ containers.victim.status }}</div>
                <div class="metric-label">10.0.1.20</div>
            </div>
            
            <div class="status-card info">
                <h3>👁️ Observer</h3>
                <div class="metric-value">{{ containers.observer.status }}</div>
                <div class="metric-label">10.0.1.30</div>
            </div>
        </div>
        
        <div class="status-grid">
            <div class="status-card info">
                <h3>📊 Log Entries</h3>
                <div class="metric-value">{{ logs|length }}</div>
                <div class="metric-label">Total Events Logged</div>
            </div>
            
            <div class="status-card info">
                <h3>📈 Attack Events</h3>
                <div class="metric-value">{{ attack_events }}</div>
                <div class="metric-label">Attack-related Events</div>
            </div>
            
            <div class="status-card info">
                <h3>📋 Analysis Reports</h3>
                <div class="metric-value">{{ results|length if results else 0 }}</div>
                <div class="metric-label">Generated Reports</div>
            </div>
            
            <div class="status-card info">
                <h3>⏱️ Uptime</h3>
                <div class="metric-value">{{ uptime }}</div>
                <div class="metric-label">Lab Running Time</div>
            </div>
        </div>
        
        <h2>📋 Recent Activity</h2>
        <div class="logs-section">
            {% for log in logs[-10:] %}
            <div class="log-entry {{ 'log-attack' if 'attack' in log.event_type else 'log-normal' }}">
                <strong>{{ log.timestamp[:19] }}</strong> 
                [{{ log.container.upper() }}] 
                <em>{{ log.event_type }}</em>: {{ log.message }}
            </div>
            {% endfor %}
        </div>
        
        <h2>🏗️ Container Status</h2>
        <table>
            <tr>
                <th>Container</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th>Role</th>
            </tr>
            <tr>
                <td>🔥 Attacker</td>
                <td>10.0.1.10</td>
                <td>{{ containers.attacker.status }}</td>
                <td>{{ containers.attacker.last_seen[:19] if containers.attacker.last_seen else 'Never' }}</td>
                <td>Performs ARP DoS attacks</td>
            </tr>
            <tr>
                <td>🎯 Victim</td>
                <td>10.0.1.20</td>
                <td>{{ containers.victim.status }}</td>
                <td>{{ containers.victim.last_seen[:19] if containers.victim.last_seen else 'Never' }}</td>
                <td>Simulates target services</td>
            </tr>
            <tr>
                <td>👁️ Observer</td>
                <td>10.0.1.30</td>
                <td>{{ containers.observer.status }}</td>
                <td>{{ containers.observer.last_seen[:19] if containers.observer.last_seen else 'Never' }}</td>
                <td>Monitors and analyzes traffic</td>
            </tr>
        </table>
        
        {% if results %}
        <h2>📊 Analysis Reports</h2>
        <table>
            <tr>
                <th>Report</th>
                <th>Generated</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Actions</th>
            </tr>
            {% for result in results[-5:] %}
            <tr>
                <td>{{ result.filename }}</td>
                <td>{{ result.detection_timestamp[:19] if result.detection_timestamp else 'N/A' }}</td>
                <td>{{ result.attack_type if result.attack_type else 'Unknown' }}</td>
                <td>{{ result.severity if result.severity else 'N/A' }}</td>
                <td><a href="/api/report/{{ result.filename }}" style="color: #17a2b8;">View Details</a></td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        
        <div style="text-align: center; margin-top: 30px; padding: 20px; border-top: 1px solid rgba(255,255,255,0.3);">
            <p><strong>ARP DoS Storm Lab</strong> - Educational/Research Purpose Only</p>
            <p>Dashboard auto-refreshes every 10 seconds</p>
            <p>
                <a href="/api/stats" style="color: #17a2b8; margin: 0 10px;">API Stats</a> |
                <a href="/api/logs" style="color: #17a2b8; margin: 0 10px;">Raw Logs</a> |
                <a href="/api/export" style="color: #17a2b8; margin: 0 10px;">Export Data</a>
            </p>
        </div>
    </div>
</body>
</html>
    ''',
    current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    attack_status=monitor.data.get('attack_status', 'Normal'),
    logs=monitor.data.get('logs', []),
    containers=monitor.data.get('containers', {}),
    results=monitor.data.get('results', []),
    attack_events=len([log for log in monitor.data.get('logs', []) if 'attack' in log.get('event_type', '')]),
    uptime='N/A'  # Could calculate from first log entry
    )

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'attack_status': monitor.data.get('attack_status'),
        'containers': monitor.data.get('containers'),
        'log_count': len(monitor.data.get('logs', [])),
        'attack_events': len([log for log in monitor.data.get('logs', []) if 'attack' in log.get('event_type', '')]),
        'results_count': len(monitor.data.get('results', []))
    })

@app.route('/api/logs')
def api_logs():
    """API endpoint for logs"""
    return jsonify({
        'logs': monitor.data.get('logs', []),
        'total_count': len(monitor.data.get('logs', []))
    })

@app.route('/api/export')
def api_export():
    """Export all data"""
    return jsonify({
        'export_timestamp': datetime.now().isoformat(),
        'lab_data': monitor.data
    })

@app.route('/api/report/<filename>')
def api_report(filename):
    """View specific report"""
    results = monitor.data.get('results', [])
    for result in results:
        if result.get('filename') == filename:
            return jsonify(result)
    
    return jsonify({'error': 'Report not found'}), 404

def main():
    """Main entry point"""
    print("Starting ARP DoS Storm Lab Web Monitor...")
    
    # Start monitoring
    monitor.start_monitoring()
    
    # Get port from environment
    port = int(os.getenv('WEB_PORT', 8080))
    
    print(f"Web dashboard starting on port {port}")
    print(f"Access dashboard at: http://localhost:{port}")
    
    try:
        app.run(host='0.0.0.0', port=port, debug=False)
    except KeyboardInterrupt:
        print("Web monitor stopping...")
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()
