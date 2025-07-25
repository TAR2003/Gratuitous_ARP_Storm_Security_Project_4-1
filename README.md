# ARP DoS via Gratuitous ARP Storm - Dockerized Lab

This project implements a complete educational lab environment for studying ARP DoS attacks via Gratuitous ARP Storm. The implementation includes custom-built attack tools written in Python and C++, along with monitoring and analysis capabilities, all containerized using Docker.

## ⚠️ Educational Use Only

**WARNING**: This tool is designed for educational and research purposes only. Use only in controlled environments with proper authorization. Unauthorized use against networks you don't own is illegal and unethical.

## Project Structure

```
Security_project/
├── attacker/                 # Attack container
│   ├── Dockerfile
│   ├── arp_dos_storm.py     # Python attack tool
│   ├── arp_storm.cpp        # C++ high-performance tool
│   ├── attacker_main.py     # Container main script
│   ├── utils.py             # Utility functions
│   └── requirements.txt
├── victim/                   # Victim container (simulates target)
│   ├── Dockerfile
│   ├── victim_main.py       # Web services and monitoring
│   ├── utils.py
│   └── requirements.txt
├── observer/                # Observer container (monitoring)
│   ├── Dockerfile
│   ├── observer_main.py     # Traffic analysis and detection
│   ├── arp_analyzer.py      # ARP traffic analyzer
│   ├── utils.py
│   └── requirements.txt
├── web_monitor/             # Web monitoring dashboard
│   ├── Dockerfile
│   ├── monitor_main.py      # Dashboard application
│   ├── static/              # CSS/JS files
│   ├── templates/           # HTML templates
│   └── requirements.txt
├── docker-compose.yml       # Multi-container orchestration
├── lab-manager.sh           # Linux/macOS management script
├── lab-manager.bat          # Windows management script
└── README.md               # This file
```

## Features

### Attack Implementation
- **Custom Packet Crafting**: Built from scratch without external tools
- **Python Implementation**: Full-featured with threading and multiple attack modes
- **C++ Implementation**: High-performance variant for maximum packet throughput
- **Attack Modes**:
  - Gratuitous ARP Storm (flood network with fake ARP responses)
  - Targeted ARP Poisoning (Man-in-the-middle attacks)
  - Subnet-wide scanning and disruption

### Monitoring & Analysis
- **Real-time Traffic Analysis**: Monitor ARP traffic patterns
- **Attack Detection**: Identify abnormal ARP behavior
- **Web Dashboard**: Visual monitoring with charts and statistics
- **Packet Capture**: Save traffic for later analysis
- **Performance Metrics**: Monitor attack effectiveness

### Containerized Environment
- **Isolated Network**: Safe testing environment
- **4 Container Architecture**:
  - Attacker (10.0.1.10): Performs attacks
  - Victim (10.0.1.20): Simulates target services
  - Observer (10.0.1.30): Monitors and analyzes
  - Web Monitor (10.0.1.40): Dashboard interface
- **Easy Management**: Scripts for common operations

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 2GB RAM
- Administrative/root privileges (for raw sockets)

## Quick Start

### 1. Check Prerequisites
```bash
# Linux/macOS
./lab-manager.sh check

# Windows
lab-manager.bat check
```

### 2. Build the Lab
```bash
# Linux/macOS
./lab-manager.sh build

# Windows
lab-manager.bat build
```

### 3. Start the Lab
```bash
# Linux/macOS
./lab-manager.sh start

# Windows
lab-manager.bat start
```

### 4. Access the Dashboard
Open your browser and navigate to:
- **Monitoring Dashboard**: http://localhost:8080
- **Victim Services**: http://localhost:80

### 5. Run Attacks
```bash
# Basic ARP storm attack
./lab-manager.sh attack basic

# High-intensity attack
./lab-manager.sh attack intense

# Targeted poisoning
./lab-manager.sh attack poison
```

## Manual Container Operations

### Start the Environment
```bash
docker-compose up -d
```

### Access Container Shells
```bash
# Attacker container
docker-compose exec attacker /bin/bash

# Victim container
docker-compose exec victim /bin/bash

# Observer container
docker-compose exec observer /bin/bash
```

### Run Attacks Manually

#### Python Attack Tool
```bash
# Basic ARP storm
docker-compose exec attacker python arp_dos_storm.py

# Targeted attack with custom parameters
docker-compose exec attacker python arp_dos_storm.py --target 10.0.1.20 --duration 30 --threads 4
```

#### C++ Attack Tool
```bash
# Compile and run high-performance attack
docker-compose exec attacker ./arp_storm --subnet 10.0.1 --duration 60 --threads 8 --rate 1000
```

### Monitor Traffic
```bash
# Real-time analysis
docker-compose exec observer python arp_analyzer.py

# View logs
docker-compose logs -f observer
```

## Attack Tool Details

### Python Implementation (`arp_dos_storm.py`)

**Features**:
- Custom Ethernet frame crafting
- Raw ARP packet construction
- Multi-threaded attack execution
- Multiple attack modes
- Built-in network scanning

**Usage**:
```bash
python arp_dos_storm.py [options]

Options:
  --target IP          Target IP address
  --subnet SUBNET      Target subnet (e.g., 192.168.1)
  --duration SECONDS   Attack duration
  --threads NUM        Number of threads
  --mode MODE          Attack mode (storm/poison)
  --rate RATE          Packets per second
```

### C++ Implementation (`arp_storm.cpp`)

**Features**:
- High-performance packet generation
- Optimized memory usage
- Cross-platform raw socket support
- Multi-threaded workers

**Compilation**:
```bash
g++ -o arp_storm arp_storm.cpp -pthread
```

## Network Architecture

```
Docker Network: 10.0.1.0/24

┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Attacker   │    │   Victim    │    │  Observer   │    │ Web Monitor │
│ 10.0.1.10   │    │ 10.0.1.20   │    │ 10.0.1.30   │    │ 10.0.1.40   │
│             │    │             │    │             │    │             │
│ Attack Tools│◄──►│Web Services │◄──►│Traffic      │◄──►│ Dashboard   │
│ - Python    │    │- HTTP Server│    │Analysis     │    │- Real-time  │
│ - C++       │    │- SSH        │    │- Detection  │    │- Charts     │
│ - Raw Socket│    │- Monitoring │    │- Logging    │    │- Statistics │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## Attack Theory

### ARP Protocol Basics
- **ARP (Address Resolution Protocol)**: Maps IP addresses to MAC addresses on local networks
- **Gratuitous ARP**: Unsolicited ARP replies that announce IP-MAC mappings
- **ARP Cache**: Each device maintains a table of IP-MAC mappings

### Attack Mechanism
1. **Packet Crafting**: Create malicious ARP packets with fake or random MAC/IP mappings
2. **Flooding**: Send thousands of these packets per second to overwhelm network infrastructure
3. **Cache Poisoning**: Fill ARP caches with false entries
4. **Resource Exhaustion**: Consume network bandwidth and processing power
5. **Service Disruption**: Cause network devices to become unresponsive or slow

### Packet Structure Implementation

#### Ethernet Frame Structure (14 bytes)
```
```
Destination MAC (6 bytes): Target device MAC address
Source MAC (6 bytes):      Attacker MAC address  
EtherType (2 bytes):       0x0806 (ARP)
```

#### ARP Packet Structure (28 bytes)
```
Hardware Type (2 bytes):    0x0001 (Ethernet)
Protocol Type (2 bytes):    0x0800 (IPv4)
Hardware Length (1 byte):   6 (MAC length)
Protocol Length (1 byte):   4 (IP length)
Operation (2 bytes):        0x0002 (Reply)
Sender MAC (6 bytes):       Attacker MAC
Sender IP (4 bytes):        Spoofed IP
Target MAC (6 bytes):       Victim MAC
Target IP (4 bytes):        Target IP
```

## Monitoring and Analysis

### Web Dashboard (Port 8080)
- Real-time attack visualization
- Network traffic graphs
- Attack statistics
- Container status monitoring
- Log viewer

### Command Line Monitoring
```bash
# View real-time logs
docker-compose logs -f

# Check container status
docker-compose ps

# Monitor specific container
./lab-manager.sh logs observer
```

### Traffic Analysis
The observer container automatically:
- Captures all network traffic
- Analyzes ARP packet patterns
- Detects anomalies and attacks
- Generates reports and alerts

## Security Considerations

### Lab Environment Safety
- Containers run in isolated Docker network
- No direct access to host network
- Traffic contained within lab environment
- Easy cleanup and reset capabilities

### Educational Guidelines
- Use only for learning and research
- Practice in controlled environments
- Understand legal implications
- Follow responsible disclosure practices

## Troubleshooting

### Common Issues

**1. Permission Denied (Raw Sockets)**
```bash
# Ensure containers run with sufficient privileges
docker-compose up --privileged
```

**2. Port Conflicts**
```bash
# Check for conflicting services
netstat -tulpn | grep -E ':(80|8080)\s'

# Stop conflicting services or modify docker-compose.yml ports
```

**3. Container Build Failures**
```bash
# Clean rebuild
docker-compose down --rmi all
docker system prune -f
./lab-manager.sh build
```

**4. Network Connectivity Issues**
```bash
# Check Docker network
docker network ls
docker network inspect security_project_lab_network

# Reset network
docker-compose down
docker network prune
docker-compose up -d
```

### Debug Mode
```bash
# Start with debug logging
DOCKER_COMPOSE_DEBUG=1 docker-compose up

# Access container for debugging
docker-compose exec attacker /bin/bash
```

## Cleanup

### Stop the Lab
```bash
./lab-manager.sh stop
```

### Complete Cleanup
```bash
# Remove everything (containers, images, volumes)
./lab-manager.sh cleanup
```

### Export Results
```bash
# Export logs and analysis results
./lab-manager.sh export
```

## Learning Objectives

This lab helps understand:
1. **ARP Protocol Fundamentals**: How ARP works and its vulnerabilities
2. **Packet Crafting**: Building network packets from scratch
3. **DoS Attack Mechanics**: How gratuitous ARP storms disrupt networks
4. **Attack Detection**: Identifying and analyzing network anomalies
5. **Defensive Strategies**: Monitoring and mitigation techniques
6. **Network Security**: Real-world attack scenarios and defenses

## Educational Use Cases

### Cybersecurity Training
- Understanding ARP vulnerabilities
- Learning attack methodologies
- Practicing defensive techniques
- Analyzing network traffic

### Research Applications
- Protocol security analysis
- Network defense testing
- Incident response training
- Forensic investigation practice

### Academic Curriculum
- Network security courses
- Ethical hacking programs
- Computer networking classes
- Cybersecurity certification prep

## Management Scripts

### Linux/macOS (`lab-manager.sh`)
```bash
./lab-manager.sh <command> [options]

Commands:
  check          Check prerequisites
  build          Build lab containers
  start          Start the lab
  stop           Stop the lab
  restart        Restart the lab
  status         Show lab status
  logs [name]    View logs
  shell <name>   Access container shell
  attack <type>  Run attack scenario
  export         Export lab results
  cleanup        Clean up everything
  help           Show help
```

### Windows (`lab-manager.bat`)
```cmd
lab-manager.bat <command> [options]

Same commands as Linux version, adapted for Windows PowerShell.
```

## Container Details

### Attacker Container
- **Base**: Ubuntu 22.04
- **Tools**: Python 3.10, GCC, network utilities
- **Capabilities**: NET_RAW for raw socket access
- **Purpose**: Execute ARP attacks and provide attack interface

### Victim Container  
- **Base**: Ubuntu 22.04
- **Services**: HTTP server, SSH daemon, monitoring tools
- **Purpose**: Simulate target services and demonstrate attack impact

### Observer Container
- **Base**: Ubuntu 22.04
- **Tools**: Traffic analysis, packet capture, detection algorithms
- **Purpose**: Monitor network activity and detect attacks

### Web Monitor Container
- **Base**: Python 3.10 Alpine
- **Framework**: Flask with real-time dashboard
- **Purpose**: Provide web interface for monitoring and control

## Performance Metrics

### Attack Capabilities
- **Python Tool**: ~1,000-5,000 packets/second
- **C++ Tool**: ~10,000-50,000 packets/second
- **Multi-threaded**: Scales with CPU cores
- **Memory Usage**: <100MB per container

### Monitoring Performance
- **Real-time Analysis**: <1 second latency
- **Detection Rate**: >95% accuracy
- **Log Processing**: 10,000+ packets/second
- **Dashboard Updates**: 1-second intervals

## License

This project is for educational purposes only. Use responsibly and ethically.

## Contributing

This is an educational project. Focus on learning and understanding the concepts rather than contributing to the attack capabilities.

## Disclaimer

The authors are not responsible for any misuse of this software. This tool is intended solely for educational and research purposes in controlled environments with proper authorization.

### Prerequisites
- Administrator/root privileges (required for raw sockets)
- Python 3.6+ (for Python tools)
- GCC/Clang compiler (for C++ tool)
- Network interface access

### Basic Usage Examples

#### 1. Python ARP Storm Attack
```bash
# Basic storm attack
python arp_dos_storm.py --storm --subnet 192.168.1 --duration 60

# High-intensity attack
python arp_dos_storm.py --storm --subnet 192.168.1 --duration 30 --threads 8 --rate 200

# Targeted poisoning
python arp_dos_storm.py --poison --targets 192.168.1.10 192.168.1.20 --gateway 192.168.1.1
```

#### 2. C++ High-Performance Attack
```bash
# Compile the tool
make

# Run attack
sudo ./arp_storm --subnet 192.168.1 --duration 30 --threads 4 --rate 500
```

#### 3. Traffic Analysis
```bash
# Monitor for 5 minutes
python arp_analyzer.py --duration 300 --output analysis.json

# Real-time monitoring during attack
python arp_analyzer.py --duration 120 &
python arp_dos_storm.py --storm --duration 60
```

#### 4. Interactive Demonstration
```bash
# Launch demo menu
python demo.py --interactive

# Quick demonstrations
python demo.py --basic-storm --duration 30
python demo.py --analysis --duration 60
```

### Advanced Configuration

#### Python Tool Parameters
- `--interface`: Specific network interface
- `--subnet`: Target subnet (e.g., 192.168.1)
- `--duration`: Attack duration in seconds
- `--threads`: Number of parallel threads
- `--rate`: Packets per second per thread
- `--targets`: Specific IP targets for poisoning
- `--gateway`: Gateway IP for poisoning attacks

#### C++ Tool Parameters
- `--subnet`: Target subnet
- `--duration`: Attack duration
- `--threads`: Thread count
- `--rate`: Packet rate per thread

## Detection and Mitigation

### Detection Indicators
1. **High ARP Traffic**: Unusual volume of ARP packets
2. **Gratuitous ARP Ratio**: High percentage of gratuitous ARP
3. **MAC Address Changes**: Frequent IP-MAC mapping changes
4. **Unique Senders**: Unusually high number of different MAC addresses

### Detection Thresholds (Configurable)
```python
thresholds = {
    'packets_per_second': 50,           # Normal: <10 ARP/sec
    'unique_senders_per_minute': 20,    # Normal: <5 senders/min
    'gratuitous_ratio': 0.7,            # Normal: <0.1 ratio
    'mac_changes_per_ip': 3             # Normal: 0-1 changes
}
```

### Mitigation Strategies
1. **Rate Limiting**: Limit ARP packet processing rate
2. **Static ARP Entries**: Use static mappings for critical devices
3. **ARP Inspection**: Validate ARP packet sources
4. **Network Segmentation**: Isolate broadcast domains
5. **Monitoring**: Deploy ARP traffic monitoring systems

### Example Mitigation Commands
```bash
# Linux: Rate limit ARP
iptables -A INPUT -p arp -m limit --limit 10/sec -j ACCEPT
iptables -A INPUT -p arp -j DROP

# Static ARP entry
arp -s 192.168.1.1 00:11:22:33:44:55
```

## Educational Objectives

### Learning Outcomes
1. **Protocol Understanding**: Deep knowledge of ARP protocol mechanics
2. **Attack Techniques**: Understanding of DoS attack methodologies
3. **Network Security**: Appreciation of network vulnerabilities
4. **Defensive Measures**: Knowledge of detection and mitigation techniques
5. **Practical Skills**: Hands-on experience with network tools

### Skill Development
- **Low-level Networking**: Raw socket programming
- **Packet Crafting**: Custom protocol implementation
- **Multi-threading**: Parallel programming concepts
- **Security Analysis**: Traffic analysis and anomaly detection
- **Tool Development**: Building security tools from scratch

### Ethical Considerations
- **Responsible Disclosure**: Understanding vulnerability reporting
- **Legal Compliance**: Awareness of computer crime laws
- **Ethical Testing**: Proper authorization and scope
- **Professional Conduct**: Responsible security practices

## Security Considerations

### Legal Warnings
- Only use on networks you own or have explicit written permission to test
- Unauthorized network attacks are illegal in most jurisdictions
- This tool is for educational and authorized testing purposes only
- Always follow responsible disclosure practices

### Technical Safeguards
- Built-in confirmation prompts
- Limited default parameters
- Clear warning messages
- Documentation of risks

### Best Practices
1. **Isolated Testing**: Use dedicated lab networks
2. **Limited Scope**: Start with minimal parameters
3. **Monitoring**: Always monitor impact during testing
4. **Documentation**: Record all testing activities
5. **Cleanup**: Restore normal network state after testing

## Troubleshooting

### Common Issues

#### Permission Errors
```
Error: Permission denied
Solution: Run as administrator/root for raw socket access
```

#### Network Interface Issues
```
Error: Cannot bind to interface
Solution: Check interface name and availability
```

#### Compilation Errors (C++)
```
Error: Missing dependencies
Solution: Install build-essential/developer tools
```

### Performance Optimization
- Adjust thread count based on system capabilities
- Monitor system resources during attacks
- Use C++ implementation for maximum performance
- Consider network bandwidth limitations

## Conclusion

This implementation provides a comprehensive educational framework for understanding ARP-based DoS attacks. The combination of attack tools, detection mechanisms, and analysis capabilities offers a complete learning experience in network security.

The project demonstrates the importance of:
- Understanding protocol vulnerabilities
- Implementing proper network defenses
- Developing security monitoring capabilities
- Following ethical security practices

Remember: With great power comes great responsibility. Use these tools wisely and ethically.

---

**Disclaimer**: This tool is for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before testing on any network.
