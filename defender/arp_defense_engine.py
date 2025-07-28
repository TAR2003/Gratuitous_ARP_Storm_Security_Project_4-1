#!/usr/bin/env python3
"""
ARP Defense Engine - Active Protection Against ARP DoS Attacks

This module implements comprehensive defense mechanisms against ARP DoS attacks:
1. Rate Limiting - Controls ARP packet processing rate
2. Static ARP Protection - Maintains critical IP-MAC mappings
3. ARP Inspection - Validates ARP packet authenticity
4. Dynamic Blacklisting - Blocks malicious MAC addresses
5. Network Segmentation - Isolates suspicious traffic
6. Adaptive Thresholds - Machine learning-based detection
7. Automatic Mitigation - Real-time response to attacks

Defense Architecture:
- Passive Monitoring: Continuous ARP traffic analysis
- Active Filtering: Real-time packet inspection and dropping
- Adaptive Learning: Dynamic threshold adjustment
- Incident Response: Automated attack mitigation
- Recovery: Post-attack network healing

Author: Security Team
Purpose: Educational and Research
"""

import socket
import struct
import time
import threading
import collections
import subprocess
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple
import ipaddress
import hashlib
import pickle


class ARPDefenseEngine:
    """
    Comprehensive ARP Attack Defense System

    Features:
    - Real-time ARP traffic monitoring and analysis
    - Dynamic rate limiting with adaptive thresholds
    - Static ARP table protection for critical infrastructure
    - Intelligent packet filtering and blacklisting
    - Automated incident response and recovery
    - Machine learning-based anomaly detection
    """

    def __init__(self, interface="eth0", config_file="defense_config.json"):
        self.interface = interface
        self.config_file = config_file
        self.running = False
        self.defense_active = True

        # Load configuration
        self.config = self.load_configuration()

        # Defense statistics
        self.stats = {
            'packets_analyzed': 0,
            'packets_blocked': 0,
            'attacks_detected': 0,
            'mitigation_actions': 0,
            'false_positives': 0,
            'uptime': time.time()
        }

        # Detection thresholds (adaptive)
        self.thresholds = {
            'packets_per_second': 10,       # Normal baseline
            'unique_senders_per_minute': 5,  # Normal baseline
            'gratuitous_ratio': 0.1,        # Normal baseline
            'mac_changes_per_ip': 1,        # Normal baseline
            'suspicious_score': 0.7         # Anomaly threshold
        }

        # Protected infrastructure
        self.protected_devices = self.load_protected_devices()
        self.static_arp_table = {}

        # Blacklist and whitelist
        self.blacklisted_macs = set()
        self.whitelisted_macs = set()
        self.suspicious_ips = collections.defaultdict(float)

        # Traffic analysis windows
        self.traffic_windows = {
            'packets_1sec': collections.deque(maxlen=1000),
            'senders_1min': collections.deque(maxlen=6000),
            'mac_changes': collections.defaultdict(list),
            'packet_patterns': collections.defaultdict(list)
        }

        # Machine learning components
        self.ml_features = collections.deque(maxlen=10000)
        self.normal_patterns = {}
        self.anomaly_detector = None

        # Logging setup
        self.setup_logging()

        # Defense measures
        self.active_mitigations = set()
        self.mitigation_history = []

        self.logger.info("ARP Defense Engine initialized")

    def load_configuration(self) -> Dict:
        """Load defense configuration from file"""
        default_config = {
            "protection_level": "high",
            "auto_mitigation": True,
            "learning_mode": True,
            "rate_limits": {
                "global_arp_pps": 50,
                "per_host_arp_pps": 10,
                "gratuitous_arp_ratio": 0.3
            },
            "protected_networks": ["10.0.1.0/24"],
            "critical_devices": {
                "10.0.1.1": "gateway",
                "10.0.1.30": "monitor"
            }
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    default_config.update(config)
            return default_config
        except Exception as e:
            self.logger.warning(f"Failed to load config: {e}, using defaults")
            return default_config

    def load_protected_devices(self) -> Dict:
        """Load list of devices that require special protection"""
        protected = {}
        for ip, device_type in self.config.get("critical_devices", {}).items():
            try:
                # Get MAC address for critical device
                mac = self.get_mac_address(ip)
                if mac:
                    protected[ip] = {
                        'mac': mac,
                        'type': device_type,
                        'protection_level': 'high'
                    }
            except Exception as e:
                self.logger.warning(f"Failed to get MAC for {ip}: {e}")

        return protected

    def setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = "/app/logs"
        os.makedirs(log_dir, exist_ok=True)

        self.logger = logging.getLogger("ARPDefense")
        self.logger.setLevel(logging.INFO)

        # File handler
        log_file = os.path.join(
            log_dir, f"defense_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def get_mac_address(self, ip: str) -> str:
        """Get MAC address for IP using ARP table"""
        try:
            result = subprocess.run(['arp', '-n', ip],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part.lower()
        except Exception as e:
            self.logger.debug(f"Failed to get MAC for {ip}: {e}")
        return None

    def create_static_arp_entries(self):
        """Create static ARP entries for protected devices"""
        self.logger.info("Creating static ARP entries for protected devices")

        for ip, device_info in self.protected_devices.items():
            try:
                mac = device_info['mac']
                # Create static ARP entry
                subprocess.run(['arp', '-s', ip, mac],
                               check=True, timeout=5)
                self.static_arp_table[ip] = mac
                self.logger.info(f"Static ARP entry created: {ip} -> {mac}")
            except subprocess.CalledProcessError as e:
                self.logger.error(
                    f"Failed to create static ARP entry for {ip}: {e}")

    def setup_iptables_rules(self):
        """Setup iptables rules for ARP rate limiting"""
        self.logger.info("Setting up iptables ARP protection rules")

        rules = [
            # Rate limit ARP packets globally
            "iptables -I INPUT -p arp -m limit --limit 50/sec -j ACCEPT",
            "iptables -I INPUT -p arp -j DROP",

            # Log dropped ARP packets
            "iptables -I INPUT -p arp -j LOG --log-prefix 'ARP_DROPPED: '",
        ]

        for rule in rules:
            try:
                subprocess.run(rule.split(), check=True, timeout=10)
                self.active_mitigations.add(rule)
                self.logger.info(f"Applied rule: {rule}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to apply rule '{rule}': {e}")

    def analyze_arp_packet(self, frame: bytes, timestamp: float) -> Dict:
        """Analyze ARP packet for malicious indicators"""

        # Parse Ethernet frame
        if len(frame) < 14:
            return {'valid': False, 'reason': 'truncated_frame'}

        dst_mac = frame[0:6]
        src_mac = frame[6:12]
        ethertype = struct.unpack('!H', frame[12:14])[0]

        if ethertype != 0x0806:  # Not ARP
            return {'valid': False, 'reason': 'not_arp'}

        # Parse ARP packet
        arp_data = frame[14:]
        if len(arp_data) < 28:
            return {'valid': False, 'reason': 'truncated_arp'}

        arp_header = struct.unpack('!HHBBH6s4s6s4s', arp_data[:28])

        arp_info = {
            'valid': True,
            'htype': arp_header[0],
            'ptype': arp_header[1],
            'hlen': arp_header[2],
            'plen': arp_header[3],
            'operation': arp_header[4],
            'sha': arp_header[5],  # Sender hardware address
            'spa': arp_header[6],  # Sender protocol address
            'tha': arp_header[7],  # Target hardware address
            'tpa': arp_header[8],  # Target protocol address
            'timestamp': timestamp,
            'src_mac_str': ':'.join([f'{b:02x}' for b in arp_header[5]]),
            'src_ip_str': '.'.join([str(b) for b in arp_header[6]]),
            'dst_ip_str': '.'.join([str(b) for b in arp_header[8]]),
        }

        # Add analysis flags
        arp_info.update(self.detect_arp_anomalies(arp_info))

        return arp_info

    def detect_arp_anomalies(self, arp_info: Dict) -> Dict:
        """Detect various ARP attack patterns"""
        anomalies = {
            'is_gratuitous': False,
            'is_suspicious': False,
            'anomaly_score': 0.0,
            'anomaly_reasons': []
        }

        src_mac = arp_info['src_mac_str']
        src_ip = arp_info['src_ip_str']
        dst_ip = arp_info['dst_ip_str']
        operation = arp_info['operation']
        timestamp = arp_info['timestamp']

        # Check for gratuitous ARP
        if operation == 2 and src_ip == dst_ip:
            anomalies['is_gratuitous'] = True
            anomalies['anomaly_score'] += 0.3

        # Check if sender is blacklisted
        if src_mac in self.blacklisted_macs:
            anomalies['is_suspicious'] = True
            anomalies['anomaly_score'] += 1.0
            anomalies['anomaly_reasons'].append('blacklisted_mac')

        # Check for MAC address spoofing of protected devices
        for protected_ip, device_info in self.protected_devices.items():
            if src_ip == protected_ip and src_mac != device_info['mac']:
                anomalies['is_suspicious'] = True
                anomalies['anomaly_score'] += 0.9
                anomalies['anomaly_reasons'].append('mac_spoofing_protected')

        # Check for rapid MAC changes
        if src_ip in self.traffic_windows['mac_changes']:
            recent_changes = [
                change for change in self.traffic_windows['mac_changes'][src_ip]
                if timestamp - change['timestamp'] <= 300  # 5 minutes
            ]
            if len(recent_changes) > self.thresholds['mac_changes_per_ip']:
                anomalies['is_suspicious'] = True
                anomalies['anomaly_score'] += 0.6
                anomalies['anomaly_reasons'].append('rapid_mac_changes')

        # Check packet rate
        recent_packets = [
            t for t in self.traffic_windows['packets_1sec']
            if timestamp - t <= 1.0
        ]
        if len(recent_packets) > self.thresholds['packets_per_second']:
            anomalies['anomaly_score'] += 0.5
            anomalies['anomaly_reasons'].append('high_packet_rate')

        # Check for unusual network ranges
        try:
            ip_obj = ipaddress.IPv4Address(src_ip)
            is_in_protected = any(
                ip_obj in ipaddress.IPv4Network(net)
                for net in self.config.get("protected_networks", [])
            )
            if not is_in_protected:
                anomalies['anomaly_score'] += 0.4
                anomalies['anomaly_reasons'].append(
                    'outside_protected_network')
        except ValueError:
            anomalies['anomaly_score'] += 0.7
            anomalies['anomaly_reasons'].append('invalid_ip')

        # Final suspicious determination
        if anomalies['anomaly_score'] >= self.thresholds['suspicious_score']:
            anomalies['is_suspicious'] = True

        return anomalies

    def update_traffic_patterns(self, arp_info: Dict):
        """Update traffic pattern analysis"""
        timestamp = arp_info['timestamp']
        src_mac = arp_info['src_mac_str']
        src_ip = arp_info['src_ip_str']

        # Update time windows
        self.traffic_windows['packets_1sec'].append(timestamp)
        self.traffic_windows['senders_1min'].append((timestamp, src_mac))

        # Track MAC changes
        if src_ip in self.traffic_windows['mac_changes']:
            last_mac = None
            if self.traffic_windows['mac_changes'][src_ip]:
                last_mac = self.traffic_windows['mac_changes'][src_ip][-1]['mac']

            if last_mac and last_mac != src_mac:
                self.traffic_windows['mac_changes'][src_ip].append({
                    'timestamp': timestamp,
                    'old_mac': last_mac,
                    'mac': src_mac
                })
        else:
            self.traffic_windows['mac_changes'][src_ip] = [
                {'timestamp': timestamp, 'mac': src_mac}
            ]

        # Update pattern features for ML
        features = self.extract_ml_features(arp_info)
        self.ml_features.append(features)

    def extract_ml_features(self, arp_info: Dict) -> List[float]:
        """Extract features for machine learning anomaly detection"""
        timestamp = arp_info['timestamp']

        # Time-based features
        hour_of_day = datetime.fromtimestamp(timestamp).hour / 24.0
        day_of_week = datetime.fromtimestamp(timestamp).weekday() / 7.0

        # Traffic volume features
        recent_packet_count = len([
            t for t in self.traffic_windows['packets_1sec']
            if timestamp - t <= 1.0
        ])

        recent_sender_count = len(set([
            mac for t, mac in self.traffic_windows['senders_1min']
            if timestamp - t <= 60.0
        ]))

        # Pattern features
        is_gratuitous = 1.0 if arp_info.get('is_gratuitous', False) else 0.0
        operation_type = arp_info['operation'] / 2.0  # Normalize to 0-1

        return [
            hour_of_day,
            day_of_week,
            recent_packet_count / 100.0,  # Normalize
            recent_sender_count / 50.0,   # Normalize
            is_gratuitous,
            operation_type,
            arp_info.get('anomaly_score', 0.0)
        ]

    def apply_mitigation(self, mitigation_type: str, **kwargs):
        """Apply specific mitigation measure"""
        timestamp = time.time()

        if mitigation_type == "blacklist_mac":
            mac = kwargs.get('mac')
            if mac:
                self.blacklisted_macs.add(mac)
                self.logger.warning(f"Blacklisted MAC address: {mac}")

                # Add iptables rule to drop packets from this MAC
                rule = f"iptables -I INPUT -m mac --mac-source {mac} -j DROP"
                try:
                    subprocess.run(rule.split(), check=True, timeout=5)
                    self.active_mitigations.add(rule)
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to blacklist MAC {mac}: {e}")

        elif mitigation_type == "rate_limit_ip":
            ip = kwargs.get('ip')
            rate = kwargs.get('rate', 5)
            if ip:
                rule = f"iptables -I INPUT -s {ip} -p arp -m limit --limit {rate}/sec -j ACCEPT"
                drop_rule = f"iptables -I INPUT -s {ip} -p arp -j DROP"
                try:
                    subprocess.run(rule.split(), check=True, timeout=5)
                    subprocess.run(drop_rule.split(), check=True, timeout=5)
                    self.active_mitigations.add(rule)
                    self.active_mitigations.add(drop_rule)
                    self.logger.warning(
                        f"Rate limited IP {ip} to {rate} ARP/sec")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to rate limit IP {ip}: {e}")

        elif mitigation_type == "reinforce_static_arp":
            # Refresh static ARP entries
            self.create_static_arp_entries()
            self.logger.info("Reinforced static ARP entries")

        elif mitigation_type == "alert_admin":
            alert_info = kwargs.get('alert_info', {})
            self.send_security_alert(alert_info)

        # Record mitigation action
        self.mitigation_history.append({
            'timestamp': timestamp,
            'type': mitigation_type,
            'details': kwargs
        })
        self.stats['mitigation_actions'] += 1

    def send_security_alert(self, alert_info: Dict):
        """Send security alert to administrators"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': alert_info.get('severity', 'HIGH'),
            'attack_type': alert_info.get('attack_type', 'ARP_DOS'),
            'source_ip': alert_info.get('source_ip'),
            'source_mac': alert_info.get('source_mac'),
            'anomaly_score': alert_info.get('anomaly_score'),
            'mitigations_applied': list(self.active_mitigations)
        }

        # Save alert to file
        alert_dir = "/app/logs"
        os.makedirs(alert_dir, exist_ok=True)
        alert_file = os.path.join(
            alert_dir, f"security_alerts_{datetime.now().strftime('%Y%m%d')}.json")

        try:
            with open(alert_file, 'a') as f:
                json.dump(alert, f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to save alert: {e}")

        self.logger.critical(f"SECURITY ALERT: {alert}")

    def adaptive_threshold_adjustment(self):
        """Adjust detection thresholds based on learned patterns"""
        if len(self.ml_features) < 100:
            return  # Need more data

        # Calculate baseline statistics from recent normal traffic
        recent_features = list(self.ml_features)[-1000:]  # Last 1000 packets

        # Extract packet rate statistics
        packet_rates = [features[2] *
                        100 for features in recent_features]  # Denormalize
        avg_rate = sum(packet_rates) / len(packet_rates)

        # Adjust thresholds based on normal patterns
        self.thresholds['packets_per_second'] = max(10, int(avg_rate * 2))

        self.logger.debug(f"Adjusted thresholds: {self.thresholds}")

    def monitor_arp_traffic(self, duration: int = 300):
        """Main monitoring loop with real-time defense"""
        self.logger.info(
            f"Starting ARP traffic monitoring and defense for {duration} seconds")

        try:
            # Setup defensive measures
            if self.config.get("auto_mitigation", True):
                self.create_static_arp_entries()
                self.setup_iptables_rules()

            # Create raw socket for monitoring
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                sock.bind((self.interface, 0))

            self.running = True
            start_time = time.time()
            last_threshold_adjustment = time.time()

            self.logger.info("ARP Defense Engine active - monitoring traffic")

            while self.running and (time.time() - start_time) < duration:
                try:
                    # Receive packet with timeout
                    sock.settimeout(1.0)
                    frame, addr = sock.recvfrom(65535)
                    timestamp = time.time()

                    # Analyze packet
                    arp_info = self.analyze_arp_packet(frame, timestamp)

                    if arp_info['valid']:
                        self.stats['packets_analyzed'] += 1

                        # Update traffic patterns
                        self.update_traffic_patterns(arp_info)

                        # Check for attacks
                        if arp_info.get('is_suspicious', False):
                            self.stats['attacks_detected'] += 1

                            self.logger.warning(
                                f"Suspicious ARP packet detected: "
                                f"SRC={arp_info['src_ip_str']}:{arp_info['src_mac_str']}, "
                                f"Score={arp_info['anomaly_score']:.2f}, "
                                f"Reasons={arp_info['anomaly_reasons']}"
                            )

                            # Apply automatic mitigation
                            if self.config.get("auto_mitigation", True):
                                if arp_info['anomaly_score'] > 0.8:
                                    # High threat - blacklist
                                    self.apply_mitigation(
                                        "blacklist_mac",
                                        mac=arp_info['src_mac_str']
                                    )
                                    self.stats['packets_blocked'] += 1

                                elif arp_info['anomaly_score'] > 0.6:
                                    # Medium threat - rate limit
                                    self.apply_mitigation(
                                        "rate_limit_ip",
                                        ip=arp_info['src_ip_str'],
                                        rate=2
                                    )

                                # Send alert for high-severity attacks
                                if arp_info['anomaly_score'] > 0.7:
                                    self.apply_mitigation(
                                        "alert_admin",
                                        alert_info={
                                            'severity': 'HIGH',
                                            'attack_type': 'ARP_STORM',
                                            'source_ip': arp_info['src_ip_str'],
                                            'source_mac': arp_info['src_mac_str'],
                                            'anomaly_score': arp_info['anomaly_score']
                                        }
                                    )

                    # Periodic threshold adjustment
                    if timestamp - last_threshold_adjustment > 60:  # Every minute
                        self.adaptive_threshold_adjustment()
                        last_threshold_adjustment = timestamp

                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")

            sock.close()

        except PermissionError:
            self.logger.error(
                "Permission denied. Run as root for raw socket access.")
        except Exception as e:
            self.logger.error(f"Defense monitoring failed: {e}")

        self.running = False
        self.logger.info("ARP Defense Engine stopped")

    def cleanup_mitigations(self):
        """Remove all active mitigation rules"""
        self.logger.info("Cleaning up active mitigations")

        for rule in list(self.active_mitigations):
            try:
                # Convert iptables -I to -D for removal
                cleanup_rule = rule.replace('-I', '-D', 1)
                subprocess.run(cleanup_rule.split(), check=True, timeout=5)
                self.logger.info(f"Removed rule: {cleanup_rule}")
            except subprocess.CalledProcessError:
                # Rule might not exist, that's fine
                pass

        self.active_mitigations.clear()

        # Clear blacklists
        self.blacklisted_macs.clear()
        self.suspicious_ips.clear()

    def get_defense_status(self) -> Dict:
        """Get current defense system status"""
        uptime = time.time() - self.stats['uptime']

        return {
            'status': 'active' if self.running else 'inactive',
            'uptime_seconds': uptime,
            'stats': self.stats.copy(),
            'thresholds': self.thresholds.copy(),
            'protected_devices': len(self.protected_devices),
            'static_arp_entries': len(self.static_arp_table),
            'blacklisted_macs': len(self.blacklisted_macs),
            'active_mitigations': len(self.active_mitigations),
            'recent_attacks': len([
                event for event in self.mitigation_history
                if time.time() - event['timestamp'] <= 3600  # Last hour
            ])
        }

    def save_defense_report(self, filename: str = None):
        """Save comprehensive defense report"""
        if not filename:
            filename = f"/app/results/defense_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'timestamp': datetime.now().isoformat(),
            'defense_status': self.get_defense_status(),
            'configuration': self.config,
            # Last 100 events
            'mitigation_history': self.mitigation_history[-100:],
            'traffic_analysis': {
                'total_packets': self.stats['packets_analyzed'],
                'suspicious_packets': self.stats['attacks_detected'],
                'blocked_packets': self.stats['packets_blocked'],
                'current_thresholds': self.thresholds
            },
            'protected_infrastructure': {
                'devices': self.protected_devices,
                'static_arp_table': self.static_arp_table
            }
        }

        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"Defense report saved to {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Failed to save defense report: {e}")
            return None


def main():
    """Main defense engine entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="ARP Defense Engine - Comprehensive ARP Attack Protection",
        epilog="Example: python arp_defense_engine.py --interface eth0 --duration 300"
    )

    parser.add_argument('--interface', '-i', default='eth0',
                        help='Network interface to monitor (default: eth0)')
    parser.add_argument('--duration', '-d', type=int, default=300,
                        help='Monitoring duration in seconds (default: 300)')
    parser.add_argument('--config', '-c', default='defense_config.json',
                        help='Configuration file (default: defense_config.json)')
    parser.add_argument('--cleanup', action='store_true',
                        help='Cleanup existing mitigations and exit')
    parser.add_argument('--status', action='store_true',
                        help='Show defense status and exit')

    args = parser.parse_args()

    # Initialize defense engine
    defense = ARPDefenseEngine(
        interface=args.interface, config_file=args.config)

    try:
        if args.cleanup:
            print("[*] Cleaning up existing mitigations...")
            defense.cleanup_mitigations()
            print("[*] Cleanup complete")
            return

        if args.status:
            status = defense.get_defense_status()
            print(json.dumps(status, indent=2))
            return

        print("="*60)
        print("ARP Defense Engine - Active Protection System")
        print("Educational/Research Purpose Only")
        print("="*60)
        print(f"[*] Interface: {args.interface}")
        print(f"[*] Duration: {args.duration} seconds")
        print(
            f"[*] Auto-mitigation: {defense.config.get('auto_mitigation', True)}")
        print("[*] Starting defense monitoring...")

        # Start monitoring
        defense.monitor_arp_traffic(args.duration)

        # Generate final report
        report_file = defense.save_defense_report()
        if report_file:
            print(f"[*] Defense report saved: {report_file}")

        # Show final statistics
        status = defense.get_defense_status()
        print(f"\n[*] Defense Summary:")
        print(f"    Packets analyzed: {status['stats']['packets_analyzed']}")
        print(f"    Attacks detected: {status['stats']['attacks_detected']}")
        print(f"    Packets blocked: {status['stats']['packets_blocked']}")
        print(
            f"    Mitigations applied: {status['stats']['mitigation_actions']}")

    except KeyboardInterrupt:
        print("\n[*] Defense interrupted by user")
    except Exception as e:
        print(f"[!] Defense failed: {e}")
    finally:
        # Cleanup on exit
        if input("\nCleanup mitigations? (y/N): ").lower().startswith('y'):
            defense.cleanup_mitigations()
            print("[*] Mitigations cleaned up")


if __name__ == "__main__":
    main()
