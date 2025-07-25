#!/usr/bin/env python3
"""
Observer Container Main Script
Monitors and analyzes ARP traffic for attack detection
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
from datetime import datetime, timedelta

# Add current directory to path
sys.path.insert(0, '/app')

try:
    from arp_analyzer import ARPAnalyzer
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError as e:
    print(f"Import error: {e}")
    print("Installing missing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "psutil", "matplotlib", "numpy"])
    from arp_analyzer import ARPAnalyzer
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    import matplotlib.pyplot as plt
    import numpy as np

console = Console()

class NetworkObserver:
    """Network traffic observer and analyzer"""
    
    def __init__(self):
        self.observer_ip = os.getenv('OBSERVER_IP', '10.0.1.30')
        self.attacker_ip = os.getenv('ATTACKER_IP', '10.0.1.10')
        self.victim_ip = os.getenv('VICTIM_IP', '10.0.1.20')
        self.gateway_ip = os.getenv('GATEWAY_IP', '10.0.1.1')
        self.subnet = os.getenv('SUBNET', '10.0.1')
        
        self.analyzer = ARPAnalyzer()
        self.running = False
        self.monitoring_thread = None
        
        # Analysis data
        self.analysis_data = {
            'attack_detected': False,
            'detection_timestamp': None,
            'packet_timeline': [],
            'attack_summary': {},
            'real_time_stats': {
                'packets_per_second': [],
                'unique_senders': [],
                'gratuitous_ratio': [],
                'timestamps': []
            }
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Ensure directories exist
        os.makedirs('/app/logs', exist_ok=True)
        os.makedirs('/app/results', exist_ok=True)
        os.makedirs('/app/captures', exist_ok=True)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        console.print(f"\n[yellow]Received signal {signum}, stopping monitoring...[/yellow]")
        self.stop_monitoring()
        sys.exit(0)
    
    def log_event(self, event_type, message, data=None):
        """Log events to file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'container': 'observer',
            'event_type': event_type,
            'message': message,
            'data': data or {}
        }
        
        log_file = f"/app/logs/observer_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def display_banner(self):
        """Display startup banner"""
        banner_text = """
    ARP Attack Observer Container
    Network Traffic Analysis & Detection
    
    👁️ Monitoring network for ARP-based attacks
    """
        
        console.print(Panel(banner_text, style="bold green", title="👁️ OBSERVER"))
        
        # Display configuration
        table = Table(title="Observer Configuration")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Observer IP", self.observer_ip)
        table.add_row("Attacker IP", self.attacker_ip)
        table.add_row("Victim IP", self.victim_ip)
        table.add_row("Gateway IP", self.gateway_ip)
        table.add_row("Subnet", f"{self.subnet}.0/24")
        
        console.print(table)
    
    def check_monitoring_capabilities(self):
        """Check if we can monitor network traffic"""
        console.print(f"\n[yellow]Checking monitoring capabilities...[/yellow]")
        
        capabilities = {
            'Raw Socket Access': False,
            'Packet Capture': False,
            'Network Interface': False,
            'Privileged Mode': False
        }
        
        # Check raw socket access
        try:
            import socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.close()
            capabilities['Raw Socket Access'] = True
        except:
            pass
        
        # Check packet capture tools
        try:
            result = subprocess.run(['tcpdump', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                capabilities['Packet Capture'] = True
        except:
            pass
        
        # Check network interfaces
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
            if 'eth0' in result.stdout or 'docker' in result.stdout:
                capabilities['Network Interface'] = True
        except:
            pass
        
        # Check if running in privileged mode
        try:
            if os.path.exists('/proc/1/cgroup'):
                capabilities['Privileged Mode'] = True
        except:
            pass
        
        # Display capabilities
        cap_table = Table(title="Monitoring Capabilities")
        cap_table.add_column("Capability", style="cyan")
        cap_table.add_column("Status", style="green")
        
        for cap, status in capabilities.items():
            status_text = "✅ Available" if status else "❌ Not Available"
            style = "green" if status else "red"
            cap_table.add_row(cap, f"[{style}]{status_text}[/{style}]")
        
        console.print(cap_table)
        
        # Log capabilities
        self.log_event("capabilities_check", "Monitoring capabilities assessed", capabilities)
        
        return any(capabilities.values())
    
    def start_packet_capture(self):
        """Start packet capture using tcpdump"""
        def capture_worker():
            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                capture_file = f"/app/captures/arp_capture_{timestamp}.pcap"
                
                # Start tcpdump for ARP packets
                cmd = [
                    'tcpdump', 
                    '-i', 'any',           # Capture on all interfaces
                    '-w', capture_file,    # Write to file
                    'arp',                 # Filter for ARP packets only
                    '-v'                   # Verbose output
                ]
                
                console.print(f"[green]Starting packet capture: {capture_file}[/green]")
                
                process = subprocess.Popen(cmd, 
                                         stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE,
                                         text=True)
                
                # Monitor capture
                while self.running:
                    if process.poll() is not None:
                        break
                    time.sleep(1)
                
                # Stop capture
                process.terminate()
                process.wait()
                
                console.print(f"[yellow]Packet capture stopped[/yellow]")
                self.log_event("packet_capture_stopped", f"Capture saved to {capture_file}")
                
            except Exception as e:
                console.print(f"[red]Packet capture error: {e}[/red]")
                self.log_event("packet_capture_error", f"Capture failed: {e}")
        
        capture_thread = threading.Thread(target=capture_worker, daemon=True)
        capture_thread.start()
    
    def analyze_traffic_patterns(self):
        """Analyze traffic patterns and detect attacks"""
        def analysis_worker():
            console.print(f"[green]Traffic pattern analysis started[/green]")
            
            while self.running:
                try:
                    # Get current ARP statistics
                    current_time = time.time()
                    
                    # Simulate traffic analysis (in real deployment, parse actual packets)
                    # This would analyze the data collected by ARPAnalyzer
                    
                    # For demo purposes, detect high packet rates
                    recent_packets = len([t for t in self.analyzer.time_windows['packets_1sec'] 
                                        if current_time - t <= 1.0])
                    
                    # Store real-time stats
                    self.analysis_data['real_time_stats']['timestamps'].append(current_time)
                    self.analysis_data['real_time_stats']['packets_per_second'].append(recent_packets)
                    
                    # Keep only last 100 data points
                    for key in self.analysis_data['real_time_stats']:
                        if len(self.analysis_data['real_time_stats'][key]) > 100:
                            self.analysis_data['real_time_stats'][key] = self.analysis_data['real_time_stats'][key][-100:]
                    
                    # Attack detection logic
                    if recent_packets > 50:  # Threshold for attack detection
                        if not self.analysis_data['attack_detected']:
                            self.analysis_data['attack_detected'] = True
                            self.analysis_data['detection_timestamp'] = datetime.now()
                            
                            console.print(f"[bold red]🚨 ARP ATTACK DETECTED! 🚨[/bold red]")
                            console.print(f"[red]High packet rate: {recent_packets} packets/second[/red]")
                            
                            self.log_event("attack_detected", "ARP storm attack detected", {
                                'packet_rate': recent_packets,
                                'detection_time': self.analysis_data['detection_timestamp'].isoformat()
                            })
                            
                            # Generate attack report
                            self.generate_attack_report()
                    
                    time.sleep(5)  # Analysis interval
                    
                except Exception as e:
                    console.print(f"[red]Analysis error: {e}[/red]")
                    time.sleep(10)
        
        analysis_thread = threading.Thread(target=analysis_worker, daemon=True)
        analysis_thread.start()
    
    def generate_attack_report(self):
        """Generate detailed attack analysis report"""
        try:
            report_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f"/app/results/attack_report_{report_timestamp}.json"
            
            # Compile attack data
            attack_report = {
                'detection_timestamp': self.analysis_data['detection_timestamp'].isoformat(),
                'observer_ip': self.observer_ip,
                'suspected_attacker': self.attacker_ip,
                'victim_ip': self.victim_ip,
                'attack_type': 'ARP Storm',
                'severity': 'HIGH',
                'analyzer_stats': {
                    'total_packets': self.analyzer.arp_stats['total_packets'],
                    'gratuitous_arp': self.analyzer.arp_stats['gratuitous_arp'],
                    'unique_senders': len(self.analyzer.arp_stats['unique_senders']),
                    'suspicious_activities': self.analyzer.arp_stats['suspicious_activity']
                },
                'real_time_stats': self.analysis_data['real_time_stats'],
                'recommendations': [
                    "Implement ARP rate limiting",
                    "Configure static ARP entries for critical devices",
                    "Deploy network segmentation",
                    "Monitor ARP table changes",
                    "Consider ARP inspection mechanisms"
                ],
                'generated_by': 'ARP DoS Storm Observer Container'
            }
            
            # Save report
            with open(report_file, 'w') as f:
                json.dump(attack_report, f, indent=2, default=str)
            
            console.print(f"[green]Attack report generated: {report_file}[/green]")
            self.log_event("attack_report_generated", f"Report saved to {report_file}")
            
            # Generate visualization
            self.generate_attack_visualization(report_timestamp)
            
        except Exception as e:
            console.print(f"[red]Report generation error: {e}[/red]")
    
    def generate_attack_visualization(self, timestamp):
        """Generate attack visualization charts"""
        try:
            if not self.analysis_data['real_time_stats']['timestamps']:
                return
            
            plt.style.use('dark_background')
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('ARP Attack Analysis', fontsize=16, color='white')
            
            # Convert timestamps to relative time
            start_time = min(self.analysis_data['real_time_stats']['timestamps'])
            relative_times = [(t - start_time) / 60 for t in self.analysis_data['real_time_stats']['timestamps']]
            
            # Packet rate over time
            axes[0, 0].plot(relative_times, self.analysis_data['real_time_stats']['packets_per_second'], 
                           'r-', linewidth=2, label='Packets/Second')
            axes[0, 0].axhline(y=50, color='orange', linestyle='--', label='Attack Threshold')
            axes[0, 0].set_title('ARP Packet Rate')
            axes[0, 0].set_xlabel('Time (minutes)')
            axes[0, 0].set_ylabel('Packets/Second')
            axes[0, 0].legend()
            axes[0, 0].grid(True, alpha=0.3)
            
            # Attack timeline
            if self.analysis_data['attack_detected']:
                detection_time = (self.analysis_data['detection_timestamp'].timestamp() - start_time) / 60
                axes[0, 1].axvline(x=detection_time, color='red', linewidth=3, label='Attack Detected')
                axes[0, 1].set_title('Attack Timeline')
                axes[0, 1].set_xlabel('Time (minutes)')
                axes[0, 1].legend()
                axes[0, 1].grid(True, alpha=0.3)
            
            # Statistics summary
            axes[1, 0].text(0.1, 0.8, f"Total ARP Packets: {self.analyzer.arp_stats['total_packets']}", 
                           transform=axes[1, 0].transAxes, fontsize=12, color='white')
            axes[1, 0].text(0.1, 0.6, f"Gratuitous ARP: {self.analyzer.arp_stats['gratuitous_arp']}", 
                           transform=axes[1, 0].transAxes, fontsize=12, color='white')
            axes[1, 0].text(0.1, 0.4, f"Unique Senders: {len(self.analyzer.arp_stats['unique_senders'])}", 
                           transform=axes[1, 0].transAxes, fontsize=12, color='white')
            axes[1, 0].text(0.1, 0.2, f"Attack Detected: {'YES' if self.analysis_data['attack_detected'] else 'NO'}", 
                           transform=axes[1, 0].transAxes, fontsize=12, 
                           color='red' if self.analysis_data['attack_detected'] else 'green')
            axes[1, 0].set_title('Attack Statistics')
            axes[1, 0].set_xlim(0, 1)
            axes[1, 0].set_ylim(0, 1)
            axes[1, 0].axis('off')
            
            # Network topology
            axes[1, 1].text(0.5, 0.8, 'Network Topology', transform=axes[1, 1].transAxes, 
                           fontsize=14, ha='center', color='white')
            axes[1, 1].text(0.2, 0.6, f'Attacker\n{self.attacker_ip}', transform=axes[1, 1].transAxes, 
                           fontsize=10, ha='center', color='red')
            axes[1, 1].text(0.5, 0.6, f'Victim\n{self.victim_ip}', transform=axes[1, 1].transAxes, 
                           fontsize=10, ha='center', color='blue')
            axes[1, 1].text(0.8, 0.6, f'Observer\n{self.observer_ip}', transform=axes[1, 1].transAxes, 
                           fontsize=10, ha='center', color='green')
            axes[1, 1].text(0.5, 0.3, f'Gateway\n{self.gateway_ip}', transform=axes[1, 1].transAxes, 
                           fontsize=10, ha='center', color='yellow')
            axes[1, 1].set_xlim(0, 1)
            axes[1, 1].set_ylim(0, 1)
            axes[1, 1].axis('off')
            
            # Save visualization
            viz_file = f"/app/results/attack_visualization_{timestamp}.png"
            plt.tight_layout()
            plt.savefig(viz_file, dpi=150, bbox_inches='tight', facecolor='black')
            plt.close()
            
            console.print(f"[green]Attack visualization saved: {viz_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Visualization error: {e}[/red]")
    
    def display_live_monitoring(self):
        """Display live monitoring information"""
        def generate_monitoring_table():
            table = Table(title="👁️ Network Observer - Live Monitoring")
            table.add_column("Metric", style="cyan")
            table.add_column("Current Value", style="green")
            table.add_column("Status", style="white")
            
            # Current stats
            current_time = time.time()
            recent_packets = len([t for t in self.analyzer.time_windows['packets_1sec'] 
                                if current_time - t <= 5.0])  # Last 5 seconds
            
            table.add_row("ARP Packets (5s)", str(recent_packets), 
                         "[red]HIGH[/red]" if recent_packets > 25 else "[green]Normal[/green]")
            table.add_row("Total ARP Packets", str(self.analyzer.arp_stats['total_packets']), "")
            table.add_row("Gratuitous ARP", str(self.analyzer.arp_stats['gratuitous_arp']), "")
            table.add_row("Unique Senders", str(len(self.analyzer.arp_stats['unique_senders'])), "")
            table.add_row("Suspicious Activities", str(len(self.analyzer.arp_stats['suspicious_activity'])), "")
            
            if self.analysis_data['attack_detected']:
                table.add_row("", "", "")
                table.add_row("🚨 ATTACK STATUS", "DETECTED", "[bold red]UNDER ATTACK![/bold red]")
                table.add_row("Detection Time", 
                             self.analysis_data['detection_timestamp'].strftime('%H:%M:%S') if self.analysis_data['detection_timestamp'] else "N/A", 
                             "")
            
            return table
        
        # Show initial monitoring info
        console.print(generate_monitoring_table())
        
        # Update display periodically
        def display_updater():
            while self.running:
                time.sleep(10)  # Update every 10 seconds
                console.clear()
                console.print(generate_monitoring_table())
        
        display_thread = threading.Thread(target=display_updater, daemon=True)
        display_thread.start()
    
    def start_monitoring(self):
        """Start all monitoring components"""
        self.running = True
        
        console.print(f"\n[bold green]🚀 Starting network monitoring...[/bold green]")
        
        # Start components
        self.start_packet_capture()
        self.analyze_traffic_patterns()
        
        # Use ARPAnalyzer for actual packet analysis
        def analyzer_worker():
            try:
                # Monitor traffic for extended period
                self.analyzer.monitor_traffic(duration=3600)  # 1 hour
            except Exception as e:
                console.print(f"[red]Analyzer error: {e}[/red]")
        
        analyzer_thread = threading.Thread(target=analyzer_worker, daemon=True)
        analyzer_thread.start()
        
        self.log_event("monitoring_started", "Network monitoring started")
        console.print(f"[green]✅ Network monitoring active![/green]")
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        console.print(f"\n[yellow]🛑 Stopping network monitoring...[/yellow]")
        
        self.running = False
        
        # Generate final report if attack was detected
        if self.analysis_data['attack_detected']:
            console.print(f"[yellow]Generating final attack report...[/yellow]")
            self.generate_attack_report()
        
        self.log_event("monitoring_stopped", "Network monitoring stopped")
        console.print(f"[green]✅ Monitoring stopped[/green]")
    
    def run(self):
        """Main container runtime"""
        self.display_banner()
        
        # Log startup
        self.log_event("container_start", "Observer container started", {
            'observer_ip': self.observer_ip,
            'monitoring_targets': [self.attacker_ip, self.victim_ip]
        })
        
        # Check capabilities
        if not self.check_monitoring_capabilities():
            console.print(f"[yellow]Limited monitoring capabilities detected[/yellow]")
            console.print(f"[yellow]Some features may not work correctly[/yellow]")
        
        # Start monitoring
        self.start_monitoring()
        
        # Display live monitoring
        self.display_live_monitoring()
        
        console.print(f"\n[green]👁️ Observer container ready![/green]")
        console.print(f"[cyan]Monitoring network: {self.subnet}.0/24[/cyan]")
        console.print(f"[cyan]Results will be saved to: /app/results/[/cyan]")
        
        try:
            # Keep container running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print(f"\n[yellow]Observer container interrupted[/yellow]")
        
        self.stop_monitoring()
        self.log_event("container_stop", "Observer container stopped")

def main():
    """Main entry point"""
    try:
        observer = NetworkObserver()
        observer.run()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
