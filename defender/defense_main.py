#!/usr/bin/env python3
"""
Defense Container Main Script
Orchestrates comprehensive ARP attack defense

This is the main entry point for the ARP Defense Container that provides
real-time protection against ARP DoS attacks. It integrates multiple
defense mechanisms:

1. Real-time ARP traffic monitoring and analysis
2. Dynamic threat detection and classification
3. Automated mitigation and response
4. Machine learning-based anomaly detection
5. Web dashboard for defense monitoring
6. Integration with network infrastructure

The defense system operates in multiple modes:
- Learning Mode: Builds baseline traffic patterns
- Protection Mode: Active defense against detected threats
- Recovery Mode: Post-attack network healing

Key Components:
- ARPDefenseEngine: Core defense logic
- DefenseWebInterface: Real-time monitoring dashboard
- ThreatIntelligence: Attack pattern recognition
- AutoMitigation: Automated response system
"""

import os
import sys
import signal
import threading
import time
import json
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request
from flask_socketio import SocketIO

# Add current directory to path
sys.path.insert(0, '/app')

try:
    from arp_defense_engine import ARPDefenseEngine
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

console = Console()


class DefenseOrchestrator:
    """
    Main orchestrator for the ARP defense system

    Coordinates between different defense components:
    - Traffic monitoring
    - Threat detection
    - Automated response
    - Web interface
    - Logging and reporting
    """

    def __init__(self):
        self.defense_engine = None
        self.web_app = Flask(__name__)
        self.socketio = SocketIO(self.web_app, cors_allowed_origins="*")
        self.running = False
        self.stats_update_thread = None

        # Configuration
        self.config = self.load_config()

        # Network configuration from environment
        self.defender_ip = os.getenv('DEFENDER_IP', '10.0.1.50')
        self.attacker_ip = os.getenv('ATTACKER_IP', '10.0.1.10')
        self.victim_ip = os.getenv('VICTIM_IP', '10.0.1.20')
        self.observer_ip = os.getenv('OBSERVER_IP', '10.0.1.30')
        self.monitor_ip = os.getenv('MONITOR_IP', '10.0.1.40')

        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Setup web routes
        self.setup_web_routes()

        self.log_event("container_start", "Defense container started", {
            "defender_ip": self.defender_ip,
            "protected_targets": [self.victim_ip, self.observer_ip, self.monitor_ip]
        })

    def load_config(self):
        """Load defense configuration"""
        try:
            with open('/app/defense_config.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[red]Failed to load config: {e}[/red]")
            return {}

    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        console.print(
            "\n[yellow]Received shutdown signal, cleaning up...[/yellow]")
        self.stop_defense()
        sys.exit(0)

    def log_event(self, event_type, message, data=None):
        """Log events to JSON format for consistency"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "container": "defender",
            "event_type": event_type,
            "message": message,
            "data": data or {}
        }

        # Write to log file
        log_dir = "/app/logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(
            log_dir, f"defender_{datetime.now().strftime('%Y%m%d')}.log")

        try:
            with open(log_file, 'a') as f:
                json.dump(log_entry, f)
                f.write('\n')
        except Exception as e:
            console.print(f"[red]Failed to write log: {e}[/red]")

        # Also print to console
        console.print(
            f"[blue]{datetime.now().strftime('%H:%M:%S')}[/blue] {message}")

    def display_banner(self):
        """Display startup banner"""
        banner = Panel.fit(
            "[bold green]ARP Defense System[/bold green]\n"
            "[cyan]Real-time Protection Against ARP DoS Attacks[/cyan]\n\n"
            f"[white]Defender IP:[/white] [yellow]{self.defender_ip}[/yellow]\n"
            f"[white]Protected Network:[/white] [yellow]10.0.1.0/24[/yellow]\n"
            f"[white]Auto-Mitigation:[/white] [{'[green]Enabled[/green]' if self.config.get('auto_mitigation') else '[red]Disabled[/red]'}]\n"
            f"[white]Learning Mode:[/white] [{'[green]Active[/green]' if self.config.get('learning_mode') else '[red]Inactive[/red]'}]",
            title="🛡️  Defense Container",
            border_style="green"
        )
        console.print(banner)

    def check_capabilities(self):
        """Check defense system capabilities"""
        capabilities = {
            "Raw Socket Access": False,
            "Iptables Access": False,
            "ARP Table Access": False,
            "Privileged Mode": False
        }

        try:
            # Test raw socket creation
            import socket
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.close()
            capabilities["Raw Socket Access"] = True
        except:
            pass

        try:
            # Test iptables access
            import subprocess
            result = subprocess.run(
                ['iptables', '-L'], capture_output=True, timeout=5)
            capabilities["Iptables Access"] = (result.returncode == 0)
        except:
            pass

        try:
            # Test ARP table access
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, timeout=5)
            capabilities["ARP Table Access"] = (result.returncode == 0)
        except:
            pass

        try:
            # Check if running with sufficient privileges
            capabilities["Privileged Mode"] = (os.geteuid() == 0)
        except:
            pass

        self.log_event("capabilities_check",
                       "Defense capabilities assessed", capabilities)

        # Display capabilities
        table = Table(title="Defense System Capabilities")
        table.add_column("Capability", style="cyan")
        table.add_column("Status", style="white")

        for capability, status in capabilities.items():
            status_str = "[green]✓ Available[/green]" if status else "[red]✗ Missing[/red]"
            table.add_row(capability, status_str)

        console.print(table)

        # Warn about missing critical capabilities
        critical_missing = [cap for cap,
                            status in capabilities.items() if not status]
        if critical_missing:
            console.print(
                f"[yellow]Warning: Missing critical capabilities: {', '.join(critical_missing)}[/yellow]")
            console.print(
                "[yellow]Some defense features may not work properly.[/yellow]")

    def start_defense_engine(self):
        """Start the core defense engine"""
        try:
            self.defense_engine = ARPDefenseEngine(
                interface='eth0',
                config_file='/app/defense_config.json'
            )

            # Start monitoring in a separate thread
            defense_thread = threading.Thread(
                target=self.defense_engine.monitor_arp_traffic,
                args=(86400,),  # Run for 24 hours
                daemon=True
            )
            defense_thread.start()

            self.log_event("defense_started", "ARP defense engine started")
            return True

        except Exception as e:
            self.log_event("defense_failed",
                           f"Failed to start defense engine: {e}")
            console.print(f"[red]Failed to start defense engine: {e}[/red]")
            return False

    def setup_web_routes(self):
        """Setup web interface routes"""

        @self.web_app.route('/')
        def dashboard():
            return render_template_string(DEFENSE_DASHBOARD_TEMPLATE,
                                          defender_ip=self.defender_ip)

        @self.web_app.route('/api/status')
        def api_status():
            if self.defense_engine:
                return jsonify(self.defense_engine.get_defense_status())
            return jsonify({"status": "inactive"})

        @self.web_app.route('/api/stats')
        def api_stats():
            if self.defense_engine:
                stats = self.defense_engine.get_defense_status()
                return jsonify({
                    "packets_analyzed": stats['stats']['packets_analyzed'],
                    "attacks_detected": stats['stats']['attacks_detected'],
                    "packets_blocked": stats['stats']['packets_blocked'],
                    "mitigations_active": stats['active_mitigations'],
                    "uptime": stats['uptime_seconds']
                })
            return jsonify({})

        @self.web_app.route('/api/threats')
        def api_threats():
            if self.defense_engine:
                recent_threats = [
                    event for event in self.defense_engine.mitigation_history
                    if time.time() - event['timestamp'] <= 3600
                ]
                return jsonify(recent_threats)
            return jsonify([])

        @self.web_app.route('/api/config')
        def api_config():
            return jsonify(self.config)

    def start_web_interface(self):
        """Start web interface in background"""
        try:
            web_thread = threading.Thread(
                target=lambda: self.socketio.run(
                    self.web_app,
                    host='0.0.0.0',
                    port=8082,
                    debug=False
                ),
                daemon=True
            )
            web_thread.start()

            self.log_event("web_interface_started",
                           "Defense web interface started on port 8082")
            console.print(
                "[green]Defense dashboard available at http://localhost:8082[/green]")

        except Exception as e:
            self.log_event("web_interface_failed",
                           f"Failed to start web interface: {e}")

    def start_stats_updater(self):
        """Start background stats updater for web interface"""
        def update_stats():
            while self.running:
                try:
                    if self.defense_engine:
                        stats = self.defense_engine.get_defense_status()
                        self.socketio.emit('stats_update', stats)
                    time.sleep(5)  # Update every 5 seconds
                except Exception as e:
                    console.print(f"[red]Stats update error: {e}[/red]")
                    time.sleep(10)

        self.stats_update_thread = threading.Thread(
            target=update_stats, daemon=True)
        self.stats_update_thread.start()

    def monitor_defense_health(self):
        """Monitor defense system health and performance"""
        last_check = time.time()

        while self.running:
            try:
                current_time = time.time()

                # Check defense engine health every 30 seconds
                if current_time - last_check >= 30:
                    if self.defense_engine:
                        status = self.defense_engine.get_defense_status()

                        # Log periodic status
                        self.log_event("health_check", "Defense system health check", {
                            "status": status['status'],
                            "packets_analyzed": status['stats']['packets_analyzed'],
                            "threats_detected": status['stats']['attacks_detected'],
                            "uptime": status['uptime_seconds']
                        })

                        # Check for performance issues
                        if status['stats']['packets_analyzed'] > 0:
                            block_rate = status['stats']['packets_blocked'] / \
                                status['stats']['packets_analyzed']
                            if block_rate > 0.5:  # Blocking more than 50% of traffic
                                self.log_event("high_block_rate",
                                               f"High packet block rate: {block_rate:.2%}")

                    last_check = current_time

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                console.print(f"[red]Health monitor error: {e}[/red]")
                time.sleep(30)

    def stop_defense(self):
        """Stop all defense components"""
        self.running = False

        if self.defense_engine:
            self.defense_engine.running = False
            self.defense_engine.cleanup_mitigations()

        self.log_event("defense_stopped", "Defense system stopped")

    def run(self):
        """Main execution loop"""
        self.running = True

        # Display startup information
        self.display_banner()

        # Check system capabilities
        self.check_capabilities()

        # Start defense components
        console.print("[cyan]Starting defense components...[/cyan]")

        if self.start_defense_engine():
            console.print("[green]✓ Defense engine started[/green]")
        else:
            console.print("[red]✗ Defense engine failed to start[/red]")
            return

        # Start web interface
        self.start_web_interface()
        console.print("[green]✓ Web interface started[/green]")

        # Start background services
        self.start_stats_updater()
        console.print("[green]✓ Stats updater started[/green]")

        # Log successful startup
        self.log_event("defense_system_ready",
                       "All defense components started")

        console.print("\n[bold green]Defense System Active[/bold green]")
        console.print("[cyan]Press Ctrl+C to stop[/cyan]")

        # Start health monitoring
        try:
            self.monitor_defense_health()
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutdown requested[/yellow]")
        finally:
            self.stop_defense()


# HTML template for defense dashboard
DEFENSE_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ARP Defense System - Real-time Protection</title>
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: #1e1e1e; 
            color: #fff; 
            margin: 0; 
            padding: 20px; 
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            text-align: center; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 20px; 
        }
        .metrics-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .metric-card { 
            background: #2d2d2d; 
            padding: 20px; 
            border-radius: 10px; 
            border-left: 4px solid #4CAF50; 
        }
        .metric-label { 
            font-size: 14px; 
            color: #bbb; 
            margin-bottom: 5px; 
        }
        .metric-value { 
            font-size: 24px; 
            font-weight: bold; 
            color: #4CAF50; 
        }
        .status-critical { color: #f44336; }
        .status-warning { color: #ff9800; }
        .status-good { color: #4CAF50; }
        .chart-container { 
            background: #2d2d2d; 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 20px; 
        }
        .threats-section { 
            background: #2d2d2d; 
            padding: 20px; 
            border-radius: 10px; 
        }
        .threat-item { 
            background: #3d3d3d; 
            padding: 10px; 
            margin: 10px 0; 
            border-radius: 5px; 
            border-left: 3px solid #f44336; 
        }
        .footer { 
            text-align: center; 
            margin-top: 30px; 
            color: #888; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ARP Defense System</h1>
            <p>Real-time Protection Against ARP DoS Attacks</p>
            <p>Defender IP: {{ defender_ip }}</p>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">System Status</div>
                <div class="metric-value status-good" id="system-status">Active</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-label">Packets Analyzed</div>
                <div class="metric-value" id="packets-analyzed">0</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-label">Threats Detected</div>
                <div class="metric-value status-warning" id="threats-detected">0</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-label">Packets Blocked</div>
                <div class="metric-value status-critical" id="packets-blocked">0</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-label">Active Mitigations</div>
                <div class="metric-value" id="active-mitigations">0</div>
            </div>
            
            <div class="metric-card">
                <div class="metric-label">System Uptime</div>
                <div class="metric-value" id="uptime">0s</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>📊 Traffic Analysis</h3>
            <canvas id="trafficChart" width="400" height="100"></canvas>
        </div>
        
        <div class="threats-section">
            <h3>🚨 Recent Threats</h3>
            <div id="threats-list">
                <p>No recent threats detected</p>
            </div>
        </div>
        
        <div class="footer">
            <small>Last updated: <span id="last-update">Never</span> | Auto-refresh every 5 seconds</small>
        </div>
    </div>

    <script>
        const socket = io();
        
        // Chart setup
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/sec',
                    data: [],
                    borderColor: '#4CAF50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    tension: 0.1
                }, {
                    label: 'Threats/sec',
                    data: [],
                    borderColor: '#f44336',
                    backgroundColor: 'rgba(244, 67, 54, 0.1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                },
                scales: {
                    x: { 
                        ticks: { color: '#fff' },
                        grid: { color: '#555' }
                    },
                    y: { 
                        ticks: { color: '#fff' },
                        grid: { color: '#555' }
                    }
                }
            }
        });
        
        // Update functions
        function updateMetrics(stats) {
            document.getElementById('packets-analyzed').textContent = stats.packets_analyzed || 0;
            document.getElementById('threats-detected').textContent = stats.attacks_detected || 0;
            document.getElementById('packets-blocked').textContent = stats.packets_blocked || 0;
            document.getElementById('active-mitigations').textContent = stats.mitigations_active || 0;
            
            const uptime = stats.uptime || 0;
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = Math.floor(uptime % 60);
            document.getElementById('uptime').textContent = `${hours}h ${minutes}m ${seconds}s`;
            
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }
        
        function updateChart(stats) {
            const now = new Date().toLocaleTimeString();
            
            if (trafficChart.data.labels.length > 20) {
                trafficChart.data.labels.shift();
                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[1].data.shift();
            }
            
            trafficChart.data.labels.push(now);
            trafficChart.data.datasets[0].data.push(stats.packets_analyzed || 0);
            trafficChart.data.datasets[1].data.push(stats.attacks_detected || 0);
            trafficChart.update();
        }
        
        // Socket events
        socket.on('stats_update', function(data) {
            updateMetrics(data.stats);
            updateChart(data.stats);
        });
        
        // Periodic updates
        setInterval(function() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    updateMetrics(data);
                    updateChart(data);
                })
                .catch(console.error);
        }, 5000);
        
        // Load threats
        setInterval(function() {
            fetch('/api/threats')
                .then(response => response.json())
                .then(threats => {
                    const threatsList = document.getElementById('threats-list');
                    if (threats.length === 0) {
                        threatsList.innerHTML = '<p>No recent threats detected</p>';
                    } else {
                        threatsList.innerHTML = threats.slice(0, 10).map(threat => 
                            `<div class="threat-item">
                                <strong>${threat.type}</strong> at ${new Date(threat.timestamp * 1000).toLocaleTimeString()}
                                <br><small>${JSON.stringify(threat.details)}</small>
                            </div>`
                        ).join('');
                    }
                })
                .catch(console.error);
        }, 10000);
    </script>
</body>
</html>
"""


def main():
    """Main entry point"""
    try:
        orchestrator = DefenseOrchestrator()
        orchestrator.run()
    except Exception as e:
        console.print(f"[red]Defense system failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
