#!/usr/bin/env python3
"""
ARP Storm Attack Analyzer and Detection

This tool analyzes network traffic to detect ARP storm attacks
and provides insights into the attack patterns.

Now this code has some ways to do so
the main point would eb the ARPOO analyzer class which is the core engine of the analysis
it has different datastrcutures which tracks ther metrics
arp_stats is like this 
{
    'total_packets': 0,           # Total ARP packets observed
    'gratuitous_arp': 0,          # Gratuitous ARP replies
    'arp_requests': 0,            # ARP requests
    'arp_replies': 0,             # ARP replies
    'unique_senders': set(),      # Unique MAC addresses
    'ip_mac_pairs': {},           # IP-to-MAC mappings
    'suspicious_activity': []     # Detected anomalies
}
now it has thresholds for detecting anomalies, like if 50 ARP packets are sent every second,
 it is very suspicious
It parses packets and decodes gratuitous ARP replies, by parsing the frames and ARP headers,
It can identify gratuitous ARP like if the sender IP is the target IP

The logic behind this is simple 
it analyzes the packet and updates the statistics accordingly
And also it tracks IP_MAX inconsistencies, like if an IP address has multiple MAC addresses
now the detect anomalies method checks for suspicious patterns based on the thresholds
like high packet rates more then 50 in a second
excessive uinique senders more then 20 in a minute
high gratuitous ARP ratio more then 70%
and excessive MAC address changes for an IP more then 3 times in 5 minutes


Now the workflow
First it setup itself by binding itself to a network interface, and uses raw sockets 
to capture all traffics
NOw for each packet it filters for ARPm, by reccognising the ethertype as 0x0806 is the ethertype
for ARP packets
Parses and classifies according to the above standards, and then update stats
Flags suspicious patterns

NOw it has its own way top see that 

DETECTION TECHNIQUES
--------------------
A. Threshold-Based Detection

Metric                      Threshold      Attack Indicator
----------------------------------------------------------
ARP packets/second          > 50           Flooding as it is clear someone is trying to flood the network
Unique MACs/minute          > 20           Distributed attack - because multiple devices are trying to spoof ARP
Gratuitous ARP/replies      > 70%          ARP spoofing, as it indicates excessive gratuitous ARP replies
MAC changes per IP (5 min)  > 3            IP spoofing, as it indicates an IP address is changing its MAC address too frequently
now there is commadn line uages for --interface, --duration, --output, --quiet
"""

import socket
import struct
import time
import threading
import collections
from datetime import datetime, timedelta
import argparse
import json

class ARPAnalyzer:
    """ARP Traffic Analyzer for detecting storm attacks"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.running = False
        self.arp_stats = {
            'total_packets': 0,
            'gratuitous_arp': 0,
            'arp_requests': 0,
            'arp_replies': 0,
            'unique_senders': set(),
            'ip_mac_pairs': {},
            'suspicious_activity': []
        }
        
        # Detection thresholds
        self.thresholds = {
            'packets_per_second': 50,      # Suspicious if > 50 ARP/sec
            'unique_senders_per_minute': 20, # Suspicious if > 20 unique senders/min
            'gratuitous_ratio': 0.7,       # Suspicious if > 70% gratuitous ARP
            'mac_changes_per_ip': 3        # Suspicious if IP changes MAC > 3 times
        }
        
        # Time windows for analysis
        self.time_windows = {
            'packets_1sec': collections.deque(maxlen=1000),
            'senders_1min': collections.deque(maxlen=6000),
            'mac_changes': collections.defaultdict(list)
        }
    
    def parse_ethernet_frame(self, frame):
        """Parse ethernet frame"""
        if len(frame) < 14:
            return None
        
        dst_mac = frame[0:6]
        src_mac = frame[6:12]
        ethertype = struct.unpack('!H', frame[12:14])[0]
        payload = frame[14:]
        
        return {
            'dst_mac': dst_mac,
            'src_mac': src_mac,
            'ethertype': ethertype,
            'payload': payload
        }
    
    def parse_arp_packet(self, arp_data):
        """Parse ARP packet"""
        if len(arp_data) < 28:
            return None
        
        arp_header = struct.unpack('!HHBBH6s4s6s4s', arp_data[:28])
        
        return {
            'htype': arp_header[0],
            'ptype': arp_header[1],
            'hlen': arp_header[2],
            'plen': arp_header[3],
            'operation': arp_header[4],
            'sha': arp_header[5],  # Sender hardware address
            'spa': arp_header[6],  # Sender protocol address
            'tha': arp_header[7],  # Target hardware address
            'tpa': arp_header[8]   # Target protocol address
        }
    
    def mac_to_string(self, mac_bytes):
        """Convert MAC bytes to string"""
        return ':'.join([f'{b:02x}' for b in mac_bytes])
    
    def ip_to_string(self, ip_bytes):
        """Convert IP bytes to string"""
        return '.'.join([str(b) for b in ip_bytes])
    
    def is_gratuitous_arp(self, arp):
        """Check if ARP packet is gratuitous"""
        # Gratuitous ARP: sender IP == target IP and operation is reply
        return (arp['operation'] == 2 and  # ARP Reply
                arp['spa'] == arp['tpa'])   # Sender IP == Target IP
    
    def analyze_packet(self, frame, timestamp):
        """Analyze a single packet"""
        eth = self.parse_ethernet_frame(frame)
        if not eth or eth['ethertype'] != 0x0806:  # Not ARP
            return
        
        arp = self.parse_arp_packet(eth['payload'])
        if not arp:
            return
        
        # Update statistics
        self.arp_stats['total_packets'] += 1
        
        sender_mac = self.mac_to_string(arp['sha'])
        sender_ip = self.ip_to_string(arp['spa'])
        target_ip = self.ip_to_string(arp['tpa'])
        
        self.arp_stats['unique_senders'].add(sender_mac)
        
        # Track operation types
        if arp['operation'] == 1:
            self.arp_stats['arp_requests'] += 1
        elif arp['operation'] == 2:
            self.arp_stats['arp_replies'] += 1
            
            if self.is_gratuitous_arp(arp):
                self.arp_stats['gratuitous_arp'] += 1
        
        # Track IP-MAC mappings for inconsistency detection
        if sender_ip in self.arp_stats['ip_mac_pairs']:
            if self.arp_stats['ip_mac_pairs'][sender_ip] != sender_mac:
                # IP changed MAC address
                self.time_windows['mac_changes'][sender_ip].append({
                    'timestamp': timestamp,
                    'old_mac': self.arp_stats['ip_mac_pairs'][sender_ip],
                    'new_mac': sender_mac
                })
        
        self.arp_stats['ip_mac_pairs'][sender_ip] = sender_mac
        
        # Add to time windows
        self.time_windows['packets_1sec'].append(timestamp)
        self.time_windows['senders_1min'].append((timestamp, sender_mac))
        
        # Check for suspicious activity
        self.detect_anomalies(timestamp)
    
    def detect_anomalies(self, current_time):
        """Detect suspicious patterns"""
        suspicious = []
        
        # Check packet rate
        recent_packets = [t for t in self.time_windows['packets_1sec'] 
                         if current_time - t <= 1.0]
        pps = len(recent_packets)
        
        if pps > self.thresholds['packets_per_second']:
            suspicious.append(f"High ARP packet rate: {pps} packets/second")
        
        # Check unique senders
        minute_ago = current_time - 60.0
        recent_senders = set()
        for timestamp, sender in self.time_windows['senders_1min']:
            if timestamp >= minute_ago:
                recent_senders.add(sender)
        
        if len(recent_senders) > self.thresholds['unique_senders_per_minute']:
            suspicious.append(f"High number of unique senders: {len(recent_senders)} in 1 minute")
        
        # Check gratuitous ARP ratio
        total_replies = self.arp_stats['arp_replies']
        if total_replies > 0:
            grat_ratio = self.arp_stats['gratuitous_arp'] / total_replies
            if grat_ratio > self.thresholds['gratuitous_ratio']:
                suspicious.append(f"High gratuitous ARP ratio: {grat_ratio:.2%}")
        
        # Check MAC address changes
        for ip, changes in self.time_windows['mac_changes'].items():
            recent_changes = [c for c in changes 
                            if current_time - c['timestamp'] <= 300.0]  # 5 minutes
            if len(recent_changes) > self.thresholds['mac_changes_per_ip']:
                suspicious.append(f"IP {ip} changed MAC {len(recent_changes)} times in 5 minutes")
        
        # Add new suspicious activities
        for activity in suspicious:
            if activity not in [s['description'] for s in self.arp_stats['suspicious_activity']]:
                self.arp_stats['suspicious_activity'].append({
                    'timestamp': current_time,
                    'description': activity
                })
    
    def monitor_traffic(self, duration=300):
        """Monitor network traffic for ARP packets"""
        print(f"[*] Starting ARP traffic monitoring for {duration} seconds...")
        print(f"[*] Monitoring interface: {self.interface or 'default'}")
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                sock.bind((self.interface, 0))
            
            self.running = True
            start_time = time.time()
            
            print("[*] Monitoring started. Press Ctrl+C to stop early.")
            
            while self.running and (time.time() - start_time) < duration:
                try:
                    frame, addr = sock.recvfrom(65535)
                    timestamp = time.time()
                    self.analyze_packet(frame, timestamp)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Error processing packet: {e}")
            
            sock.close()
            
        except PermissionError:
            print("[!] Permission denied. Run as administrator/root for raw sockets.")
        except Exception as e:
            print(f"[!] Error creating socket: {e}")
        
        self.running = False
        print("[*] Monitoring stopped.")
    
    def print_statistics(self):
        """Print analysis results"""
        print("\n" + "="*60)
        print("ARP TRAFFIC ANALYSIS RESULTS")
        print("="*60)
        
        print(f"Total ARP packets: {self.arp_stats['total_packets']}")
        print(f"ARP requests: {self.arp_stats['arp_requests']}")
        print(f"ARP replies: {self.arp_stats['arp_replies']}")
        print(f"Gratuitous ARP: {self.arp_stats['gratuitous_arp']}")
        print(f"Unique senders: {len(self.arp_stats['unique_senders'])}")
        
        if self.arp_stats['arp_replies'] > 0:
            grat_ratio = self.arp_stats['gratuitous_arp'] / self.arp_stats['arp_replies']
            print(f"Gratuitous ARP ratio: {grat_ratio:.2%}")
        
        print(f"\nIP-MAC mappings tracked: {len(self.arp_stats['ip_mac_pairs'])}")
        
        # Show MAC changes
        if self.time_windows['mac_changes']:
            print(f"\nIPs with MAC address changes:")
            for ip, changes in self.time_windows['mac_changes'].items():
                print(f"  {ip}: {len(changes)} changes")
        
        # Show suspicious activities
        if self.arp_stats['suspicious_activity']:
            print(f"\nSUSPICIOUS ACTIVITIES DETECTED:")
            for activity in self.arp_stats['suspicious_activity']:
                timestamp = datetime.fromtimestamp(activity['timestamp'])
                print(f"  [{timestamp.strftime('%H:%M:%S')}] {activity['description']}")
        else:
            print(f"\nNo suspicious activities detected.")
        
        # Assessment
        print(f"\n" + "="*60)
        print("ATTACK ASSESSMENT")
        print("="*60)
        
        attack_indicators = 0
        
        # Check indicators
        if self.arp_stats['total_packets'] > 1000:
            print("[WARNING] Very high ARP packet count")
            attack_indicators += 1
        
        if len(self.arp_stats['unique_senders']) > 50:
            print("[WARNING] Unusually high number of unique senders")
            attack_indicators += 1
        
        if self.arp_stats['arp_replies'] > 0:
            grat_ratio = self.arp_stats['gratuitous_arp'] / self.arp_stats['arp_replies']
            if grat_ratio > 0.7:
                print("[WARNING] Very high gratuitous ARP ratio")
                attack_indicators += 1
        
        if len(self.arp_stats['suspicious_activity']) > 0:
            print("[WARNING] Suspicious activities detected")
            attack_indicators += 1
        
        # Final assessment
        if attack_indicators >= 3:
            print(f"\n[CRITICAL] High probability of ARP storm attack!")
        elif attack_indicators >= 2:
            print(f"\n[WARNING] Possible ARP storm attack detected.")
        elif attack_indicators >= 1:
            print(f"\n[INFO] Some suspicious ARP activity detected.")
        else:
            print(f"\n[OK] No clear signs of ARP storm attack.")
    
    def save_results(self, filename):
        """Save analysis results to JSON file"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'total_packets': self.arp_stats['total_packets'],
                'arp_requests': self.arp_stats['arp_requests'],
                'arp_replies': self.arp_stats['arp_replies'],
                'gratuitous_arp': self.arp_stats['gratuitous_arp'],
                'unique_senders_count': len(self.arp_stats['unique_senders']),
                'ip_mac_mappings_count': len(self.arp_stats['ip_mac_pairs'])
            },
            'suspicious_activities': self.arp_stats['suspicious_activity'],
            'mac_changes': {ip: len(changes) for ip, changes in self.time_windows['mac_changes'].items()},
            'thresholds': self.thresholds
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"[*] Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="ARP Storm Attack Analyzer and Detection Tool",
        epilog="Example: python arp_analyzer.py --interface eth0 --duration 60"
    )
    
    parser.add_argument('--interface', '-i',
                       help='Network interface to monitor')
    parser.add_argument('--duration', '-d', type=int, default=300,
                       help='Monitoring duration in seconds (default: 300)')
    parser.add_argument('--output', '-o',
                       help='Save results to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Quiet mode - minimal output')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("="*60)
        print("ARP Storm Attack Analyzer and Detection Tool")
        print("Educational/Research Purpose Only")
        print("="*60)
    
    analyzer = ARPAnalyzer(args.interface)
    
    try:
        analyzer.monitor_traffic(args.duration)
        
        if not args.quiet:
            analyzer.print_statistics()
        
        if args.output:
            analyzer.save_results(args.output)
    
    except KeyboardInterrupt:
        print("\n[*] Monitoring interrupted by user")
        if not args.quiet:
            analyzer.print_statistics()
    
    except Exception as e:
        print(f"[!] Analysis failed: {e}")

if __name__ == "__main__":
    main()
