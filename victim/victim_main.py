#!/usr/bin/env python3
"""
Victim Container Main Script
Simulates network services that are targets of ARP attacks

Now this is run as a victim pc, inside dockerized virtual networks

its main engine is the VictimService class, which is the core
First it loads the network initialization by loading the environment variables IPs
Then it tracks the running services HTTP, echo, ARP monitor
Then the network stats

Now its core methods are start web services which runs the flask web server
start echo services which is the TCP echo service at port 7
monitor arp traffic which checks the ARP table for rapid changes
check connectivity which pings gateway or observer
simulate network activity which generates normal traffic


Now it workflow
First it displays a banner with configuration
then it starts the services web dahsboard, echo service, ARP monitor, and network activity simulator

live monitoring checks the UI upadaets after 30 seconds
now the attack dtection
flags if more than 10 entries change in 5 seconds
connectivity loss detects ping fdailures to fateway observer
no detection it sets the attack detecte true
and logs event to app.logs/vicitm .log



"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
from datetime import datetime
from flask import Flask, jsonify, render_template_string

try:
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
except ImportError as e:
    print(f"Import error: {e}")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "psutil", "flask"])
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live

console = Console()

class VictimServices:
    """Victim container that simulates network services"""
    """loads environment variables for configuration"""
    """ sets up empty dictionaries for services and network stats"""
    """CReates necessary directories"""
    """Configures signal handlers for graceful shutdown"""
    def __init__(self):
        self.victim_ip = os.getenv('VICTIM_IP', '10.0.1.20')
        self.attacker_ip = os.getenv('ATTACKER_IP', '10.0.1.10')
        self.observer_ip = os.getenv('OBSERVER_IP', '10.0.1.30')
        self.gateway_ip = os.getenv('GATEWAY_IP', '10.0.1.1')
        
        self.running = False
        self.services = {}
        self.attack_detected = False
        self.network_stats = {
            'arp_requests_received': 0,
            'arp_replies_sent': 0,
            'connectivity_checks': 0,
            'service_requests': 0,
            'attack_indicators': []
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Ensure directories exist
        os.makedirs('/app/logs', exist_ok=True)
        
        # Initialize Flask app
        self.app = Flask(__name__)
        self.setup_web_routes()
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals, it user preses Control + C"""
        console.print(f"\n[yellow]Received signal {signum}, shutting down services...[/yellow]")
        self.stop_services()
        sys.exit(0)
    
    def log_event(self, event_type, message, data=None):
        """Log events to a shared /app/logs directory, in /app/logs/victim_YYYYMMDD.log format"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'container': 'victim',
            'event_type': event_type,
            'message': message,
            'data': data or {}
        }
        
        log_file = f"/app/logs/victim_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def display_banner(self):
        """Display startup banner"""
        banner_text = """
    ARP Attack Victim Container
    Simulating Network Services
    
    🎯 This container simulates services under attack
    """
        
        console.print(Panel(banner_text, style="bold blue", title="🎯 VICTIM"))
        
        # Display configuration
        table = Table(title="Victim Configuration")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Victim IP", self.victim_ip)
        table.add_row("Attacker IP", self.attacker_ip)
        table.add_row("Observer IP", self.observer_ip)
        table.add_row("Gateway IP", self.gateway_ip)
        
        console.print(table)
    
    def setup_web_routes(self):
        """Setup Flask web routes"""
        
        @self.app.route('/')
        def index():
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Victim Services - ARP Lab</title>
                <meta http-equiv="refresh" content="5">
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                    .container { background: white; padding: 20px; border-radius: 10px; }
                    .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
                    .normal { background: #d4edda; color: #155724; }
                    .warning { background: #fff3cd; color: #856404; }
                    .danger { background: #f8d7da; color: #721c24; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background: #f2f2f2; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🎯 Victim Services Dashboard</h1>
                    <div class="status {{ status_class }}">
                        <strong>Status:</strong> {{ status_message }}
                    </div>
                    
                    <h2>Network Statistics</h2>
                    <table>
                        <tr><th>Metric</th><th>Value</th></tr>
                        <tr><td>ARP Requests Received</td><td>{{ stats.arp_requests_received }}</td></tr>
                        <tr><td>ARP Replies Sent</td><td>{{ stats.arp_replies_sent }}</td></tr>
                        <tr><td>Service Requests</td><td>{{ stats.service_requests }}</td></tr>
                        <tr><td>Connectivity Checks</td><td>{{ stats.connectivity_checks }}</td></tr>
                    </table>
                    
                    <h2>Running Services</h2>
                    <ul>
                        {% for service, status in services.items() %}
                        <li>{{ service }}: {{ status }}</li>
                        {% endfor %}
                    </ul>
                    
                    {% if stats.attack_indicators %}
                    <h2>⚠️ Attack Indicators</h2>
                    <ul>
                        {% for indicator in stats.attack_indicators[-10:] %}
                        <li>{{ indicator }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    <p><small>Auto-refresh every 5 seconds | Container IP: {{ victim_ip }}</small></p>
                </div>
            </body>
            </html>
            ''', 
            victim_ip=self.victim_ip,
            stats=self.network_stats,
            services=self.services,
            status_class="danger" if self.attack_detected else "normal",
            status_message="UNDER ATTACK!" if self.attack_detected else "Normal Operation"
            )
        
        @self.app.route('/api/stats')
        def api_stats():
            return jsonify({
                'victim_ip': self.victim_ip,
                'network_stats': self.network_stats,
                'services': self.services,
                'attack_detected': self.attack_detected,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/api/test')
        def api_test():
            self.network_stats['service_requests'] += 1
            return jsonify({'message': 'Service responding normally', 'timestamp': datetime.now().isoformat()})
    
    def start_web_service(self):
        """Start web service, start the flask server"""
        def run_flask():
            self.app.run(host='0.0.0.0', port=80, debug=False, threaded=True)
        
        web_thread = threading.Thread(target=run_flask, daemon=True)
        web_thread.start()
        self.services['HTTP Web Server'] = 'Running on port 80'
        console.print("[green]Web service started on port 80[/green]")
    
    def start_echo_service(self):
        """Start echo service for connectivity testing"""
        """Counts requests in network stats"""
        """Returns any received data"""
        import socket
        
        def echo_server():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', 7))  # Echo port
                sock.listen(5)
                
                console.print("[green]Echo service started on port 7[/green]")
                self.services['Echo Service'] = 'Running on port 7'
                
                while self.running:
                    try:
                        sock.settimeout(1.0)
                        conn, addr = sock.accept()
                        
                        # Handle echo request
                        data = conn.recv(1024)
                        if data:
                            conn.send(data)  # Echo back
                            self.network_stats['service_requests'] += 1
                        
                        conn.close()
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            console.print(f"[yellow]Echo service error: {e}[/yellow]")
                
                sock.close()
                
            except Exception as e:
                console.print(f"[red]Echo service failed: {e}[/red]")
        
        echo_thread = threading.Thread(target=echo_server, daemon=True)
        echo_thread.start()
    
    def monitor_arp_traffic(self):
        """Monitor ARP traffic for attack detection"""
        """ Runs the arp -a every 5 mintues """
        """Flags rapid ARP table changes (>10 entries difference)"""
        def arp_monitor():
            console.print("[green]ARP traffic monitoring started[/green]")
            
            last_arp_count = 0
            high_traffic_threshold = 50  # ARP packets per monitoring interval
            
            while self.running:
                try:
                    # Get ARP table
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                    current_arp_entries = len(result.stdout.splitlines())
                    
                    # Simple heuristic: detect rapid ARP table changes
                    if abs(current_arp_entries - last_arp_count) > 10:
                        self.network_stats['attack_indicators'].append(
                            f"{datetime.now().strftime('%H:%M:%S')} - Rapid ARP table changes detected"
                        )
                        self.attack_detected = True
                        
                        self.log_event("attack_detected", "Rapid ARP table changes", {
                            'arp_entries': current_arp_entries,
                            'previous_count': last_arp_count
                        })
                    
                    last_arp_count = current_arp_entries
                    
                    # Monitor network connectivity
                    self.check_connectivity()
                    
                    time.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    console.print(f"[red]ARP monitoring error: {e}[/red]")
                    time.sleep(10)
        
        arp_thread = threading.Thread(target=arp_monitor, daemon=True)
        arp_thread.start()
        self.services['ARP Monitor'] = 'Active'
    
    def check_connectivity(self):
        """Check connectivity to other containers"""
        """test test network reachability"""
        """Pings gateway and observer IPs"""
        targets = [self.gateway_ip, self.observer_ip]
        
        for target in targets:
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', target],
                                      capture_output=True, text=True)
                
                self.network_stats['connectivity_checks'] += 1
                
                if result.returncode != 0:
                    # Connectivity issue detected
                    self.network_stats['attack_indicators'].append(
                        f"{datetime.now().strftime('%H:%M:%S')} - Connectivity lost to {target}"
                    )
                    self.attack_detected = True
                    
                    self.log_event("connectivity_lost", f"Lost connectivity to {target}")
                
            except Exception as e:
                console.print(f"[yellow]Connectivity check error: {e}[/yellow]")
    
    def simulate_network_activity(self):
        """Simulate normal network activity"""
        """generates normal traffic in a network"""
        """ periodically pings gateway and logs results"""

        def activity_simulator():
            console.print("[green]Network activity simulation started[/green]")
            
            while self.running:
                try:
                    # Simulate periodic network requests
                    time.sleep(30)
                    
                    # Test connectivity to gateway
                    result = subprocess.run(['ping', '-c', '1', self.gateway_ip],
                                          capture_output=True)
                    
                    if result.returncode == 0:
                        self.log_event("network_activity", "Periodic gateway ping successful")
                    else:
                        self.log_event("network_activity", "Periodic gateway ping failed")
                        self.network_stats['attack_indicators'].append(
                            f"{datetime.now().strftime('%H:%M:%S')} - Gateway unreachable"
                        )
                        self.attack_detected = True
                    
                except Exception as e:
                    console.print(f"[yellow]Activity simulation error: {e}[/yellow]")
        
        activity_thread = threading.Thread(target=activity_simulator, daemon=True)
        activity_thread.start()
        self.services['Activity Simulator'] = 'Running'
    
    def display_live_status(self):
        """Display live status information"""
        """Shows real time console UI"""
        def generate_status_table():
            table = Table(title="🎯 Victim Container Live Status")
            table.add_column("Service", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="white")
            
            for service, status in self.services.items():
                table.add_row(service, status, "")
            
            # Add network statistics
            table.add_row("", "", "")  # Separator
            table.add_row("Network Stats", "", "")
            table.add_row("ARP Requests", str(self.network_stats['arp_requests_received']), "")
            table.add_row("Service Requests", str(self.network_stats['service_requests']), "")
            table.add_row("Connectivity Checks", str(self.network_stats['connectivity_checks']), "")
            
            if self.attack_detected:
                table.add_row("", "", "")
                table.add_row("⚠️ ATTACK STATUS", "DETECTED", "[red]Under Attack![/red]")
            
            return table
        
        # Show initial status
        console.print(generate_status_table())
        
        # In a real deployment, you might want to use Rich's Live display
        # For simplicity, we'll just update periodically
        def status_updater():
            while self.running:
                time.sleep(30)  # Update every 30 seconds
                console.clear()
                console.print(generate_status_table())
        
        status_thread = threading.Thread(target=status_updater, daemon=True)
        status_thread.start()
    
    def start_services(self):
        """Start all victim services"""
        self.running = True
        
        console.print(f"\n[bold green]🚀 Starting victim services...[/bold green]")
        
        # Start services
        self.start_web_service()
        self.start_echo_service()
        self.monitor_arp_traffic()
        self.simulate_network_activity()
        
        self.log_event("services_started", "All victim services started", {
            'services': list(self.services.keys())
        })
        
        console.print(f"[green]✅ All services started successfully![/green]")
    
    def stop_services(self):
        """Stop all services"""
        console.print(f"\n[yellow]🛑 Stopping victim services...[/yellow]")
        
        self.running = False
        self.services.clear()
        
        self.log_event("services_stopped", "All victim services stopped")
        console.print(f"[green]✅ All services stopped[/green]")
    
    def run(self):
        """Main container runtime"""
        self.display_banner()
        
        # Log startup
        self.log_event("container_start", "Victim container started", {
            'victim_ip': self.victim_ip,
            'attacker_ip': self.attacker_ip,
            'observer_ip': self.observer_ip
        })
        
        # Start services
        self.start_services()
        
        # Display live status
        self.display_live_status()
        
        console.print(f"\n[green]🎯 Victim container ready![/green]")
        console.print(f"[cyan]Web interface available at: http://{self.victim_ip}[/cyan]")
        console.print(f"[cyan]API endpoint: http://{self.victim_ip}/api/stats[/cyan]")
        
        try:
            # Keep container running
            while self.running:
                time.sleep(1)
                
                # Reset attack detection after some time
                if self.attack_detected:
                    time.sleep(60)  # Wait 60 seconds before clearing attack flag
                    self.attack_detected = False
                    
        except KeyboardInterrupt:
            console.print(f"\n[yellow]Victim container interrupted[/yellow]")
        
        self.stop_services()
        self.log_event("container_stop", "Victim container stopped")

def main():
    """Main entry point"""
    try:
        victim = VictimServices()
        victim.run()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
