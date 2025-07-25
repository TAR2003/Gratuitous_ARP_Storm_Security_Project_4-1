Here it is the project for ARP DoS via Gratuitous ARP Storm. This project is a part of the Security Project


use this command to run the project attack
docker-compose exec attacker python /app/attacker_main.py --iface eth0



Now in this project, an attacker will attack a victim server by sending a lot of Gratuitous ARP packets to the victim server. The victim server will be overwhelmed by the Gratuitous ARP packets and will not be able to respond to legitimate ARP requests. This will cause the victim server to be unable to communicate with other devices on the network.

Attacker: 
Contains python and C++ tools to generate ARP storms
Can send gratuitous ARP packets to a target server to flood the network
Implements vboth basic  and high performance Attacks

Victim:
Simulates a target machine with web services
Will get the effect of ARP storm
Provides monitoring endpoints to observe attack impact

Observer:
Monitors the network traffic in real time 
Detects abnormal ARP patterns
Analyzes attack characteristics

Web Monitor: 
Provides a visual dashboard at localhost:8080
Displays attack statistics and network health

Gratuitous ARP generation:
The attacker creafts ARP reply packets wihtout corresponding requests 
These pacjers contain spoofed IP-MAC mappings
Packets are sent to the broadcast address (ff:ff:ff:ff:ff:ff)

Network flooding:
THousands of these fake ARP packets are sent per second 
The flood overwhelms network devices and hosts
Legitimate ARP traffic gets drowned out

Impact:
Victim's ARP cache gets corrupted with false entries
Network devices spend resources processing fake ARP packets
Legitimate communication becomes unreliable or impossible
Services may become unresponsive

Now let me explain what the attacker arp_dos_storm.py file does:
user runs the script with command line  arguments 
The script is started from the command line 
The user can use one of two modes, one is the gratuitous ARP storm attack 
and the other is targeted ARP poisoning attack

Can additionally include parameters like network interface to send the packets on
Target subnet or victim IPs
Duration of the attack
Number of threads 
Packet rate per thread

Initialization and User confirmation


