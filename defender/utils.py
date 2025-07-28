#!/usr/bin/env python3
"""
Utility functions for the ARP Defense System

This module provides common utility functions used across
the defense system components.
"""

import socket
import struct
import subprocess
import time
import json
import os
from typing import Dict, List, Optional


def get_network_interface_info(interface: str = "eth0") -> Dict:
    """Get network interface information"""
    info = {
        'interface': interface,
        'ip_address': None,
        'mac_address': None,
        'status': 'unknown'
    }

    try:
        # Get IP address
        result = subprocess.run(['ip', 'addr', 'show', interface],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet ' in line and not '127.0.0.1' in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        info['ip_address'] = parts[1].split('/')[0]
                        break

            # Get MAC address
            for line in lines:
                if 'link/ether' in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        info['mac_address'] = parts[1]
                        break

            # Check if interface is up
            if 'UP' in result.stdout:
                info['status'] = 'up'
            else:
                info['status'] = 'down'

    except Exception as e:
        print(f"Error getting interface info: {e}")

    return info


def parse_mac_address(mac_bytes: bytes) -> str:
    """Convert MAC address bytes to string format"""
    return ':'.join([f'{b:02x}' for b in mac_bytes])


def parse_ip_address(ip_bytes: bytes) -> str:
    """Convert IP address bytes to string format"""
    return '.'.join([str(b) for b in ip_bytes])


def is_valid_ip(ip_str: str) -> bool:
    """Check if IP address string is valid"""
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False


def is_valid_mac(mac_str: str) -> bool:
    """Check if MAC address string is valid"""
    try:
        # Remove common separators
        clean_mac = mac_str.replace(':', '').replace('-', '').replace('.', '')
        # Should be 12 hex characters
        if len(clean_mac) == 12:
            int(clean_mac, 16)
            return True
    except ValueError:
        pass
    return False


def get_arp_table() -> List[Dict]:
    """Get current ARP table entries"""
    arp_entries = []

    try:
        result = subprocess.run(
            ['arp', '-a'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if '(' in line and ')' in line and 'at' in line:
                    # Parse ARP entry: hostname (ip) at mac [ether] on interface
                    try:
                        parts = line.split()
                        ip = line.split('(')[1].split(')')[0]
                        mac = None

                        for i, part in enumerate(parts):
                            if part == 'at' and i + 1 < len(parts):
                                mac = parts[i + 1]
                                break

                        if ip and mac and is_valid_ip(ip) and is_valid_mac(mac):
                            arp_entries.append({
                                'ip': ip,
                                'mac': mac.lower(),
                                'line': line.strip()
                            })
                    except:
                        continue

    except Exception as e:
        print(f"Error getting ARP table: {e}")

    return arp_entries


def create_static_arp_entry(ip: str, mac: str) -> bool:
    """Create a static ARP entry"""
    try:
        result = subprocess.run(['arp', '-s', ip, mac],
                                capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"Error creating static ARP entry: {e}")
        return False


def remove_arp_entry(ip: str) -> bool:
    """Remove an ARP entry"""
    try:
        result = subprocess.run(['arp', '-d', ip],
                                capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"Error removing ARP entry: {e}")
        return False


def check_iptables_support() -> bool:
    """Check if iptables is available and working"""
    try:
        result = subprocess.run(['iptables', '--version'],
                                capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def apply_iptables_rule(rule: str) -> bool:
    """Apply an iptables rule"""
    try:
        rule_parts = rule.split()
        result = subprocess.run(rule_parts, capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"Error applying iptables rule: {e}")
        return False


def remove_iptables_rule(rule: str) -> bool:
    """Remove an iptables rule (convert -I to -D)"""
    try:
        # Convert insert (-I) to delete (-D)
        if '-I' in rule:
            rule = rule.replace('-I', '-D', 1)
        rule_parts = rule.split()
        result = subprocess.run(rule_parts, capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"Error removing iptables rule: {e}")
        return False


def get_system_stats() -> Dict:
    """Get system performance statistics"""
    stats = {
        'timestamp': time.time(),
        'cpu_percent': 0.0,
        'memory_percent': 0.0,
        'network_connections': 0,
        'uptime': 0.0
    }

    try:
        # Try to get CPU and memory stats
        import psutil
        stats['cpu_percent'] = psutil.cpu_percent(interval=1)
        stats['memory_percent'] = psutil.virtual_memory().percent
        stats['network_connections'] = len(psutil.net_connections())
        stats['uptime'] = time.time() - psutil.boot_time()
    except ImportError:
        # Fallback to basic system commands
        try:
            # Get uptime
            with open('/proc/uptime', 'r') as f:
                stats['uptime'] = float(f.read().split()[0])
        except:
            pass

    return stats


def save_json_log(filename: str, data: Dict) -> bool:
    """Save data to JSON log file"""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'a') as f:
            json.dump(data, f, default=str)
            f.write('\n')
        return True
    except Exception as e:
        print(f"Error saving JSON log: {e}")
        return False


def load_json_config(filename: str, default: Dict = None) -> Dict:
    """Load configuration from JSON file"""
    if default is None:
        default = {}

    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                default.update(config)
        return default
    except Exception as e:
        print(f"Error loading config from {filename}: {e}")
        return default


def format_bytes(bytes_count: int) -> str:
    """Format byte count in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_time_delta(seconds: float) -> str:
    """Format time delta in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def calculate_packet_rate(packet_count: int, time_window: float) -> float:
    """Calculate packets per second rate"""
    if time_window <= 0:
        return 0.0
    return packet_count / time_window


def normalize_mac_address(mac: str) -> str:
    """Normalize MAC address to standard format (lowercase with colons)"""
    if not mac:
        return ""

    # Remove separators and convert to lowercase
    clean_mac = mac.replace(':', '').replace('-', '').replace('.', '').lower()

    # Add colons every 2 characters
    if len(clean_mac) == 12:
        return ':'.join([clean_mac[i:i+2] for i in range(0, 12, 2)])

    return mac  # Return original if can't normalize


def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range"""
    try:
        import ipaddress
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_private
    except:
        # Fallback manual check
        octets = ip.split('.')
        if len(octets) != 4:
            return False

        try:
            first = int(octets[0])
            second = int(octets[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            elif first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            elif first == 192 and second == 168:
                return True
        except ValueError:
            pass

    return False


class PacketAnalyzer:
    """Helper class for analyzing network packets"""

    @staticmethod
    def parse_ethernet_frame(frame: bytes) -> Optional[Dict]:
        """Parse Ethernet frame header"""
        if len(frame) < 14:
            return None

        return {
            'dst_mac': frame[0:6],
            'src_mac': frame[6:12],
            'ethertype': struct.unpack('!H', frame[12:14])[0],
            'payload': frame[14:],
            'dst_mac_str': parse_mac_address(frame[0:6]),
            'src_mac_str': parse_mac_address(frame[6:12])
        }

    @staticmethod
    def parse_arp_packet(arp_data: bytes) -> Optional[Dict]:
        """Parse ARP packet"""
        if len(arp_data) < 28:
            return None

        try:
            header = struct.unpack('!HHBBH6s4s6s4s', arp_data[:28])

            return {
                'htype': header[0],
                'ptype': header[1],
                'hlen': header[2],
                'plen': header[3],
                'operation': header[4],
                'sha': header[5],  # Sender hardware address
                'spa': header[6],  # Sender protocol address
                'tha': header[7],  # Target hardware address
                'tpa': header[8],  # Target protocol address
                'sha_str': parse_mac_address(header[5]),
                'spa_str': parse_ip_address(header[6]),
                'tha_str': parse_mac_address(header[7]),
                'tpa_str': parse_ip_address(header[8])
            }
        except struct.error:
            return None

    @staticmethod
    def is_gratuitous_arp(arp: Dict) -> bool:
        """Check if ARP packet is gratuitous"""
        return (arp['operation'] == 2 and  # ARP Reply
                arp['spa'] == arp['tpa'])   # Sender IP == Target IP
