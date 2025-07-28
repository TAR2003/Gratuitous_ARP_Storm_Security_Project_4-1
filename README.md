# ARP DoS Defense and Attack Simulation Project

This comprehensive security project simulates ARP-based attacks and implements advanced defense mechanisms. The project includes both offensive and defensive capabilities for educational and testing purposes.

## 🛡️ NEW: Defense System Features

The project now includes a sophisticated **ARP Defense System** with:

- **Real-time Attack Detection**: Advanced anomaly detection using statistical analysis and machine learning
- **Automated Mitigation**: Intelligent response to different types of ARP attacks
- **Web Dashboard**: Real-time monitoring and control interface at `http://localhost:8082`
- **Machine Learning**: Adaptive threat detection using Isolation Forest and pattern recognition
- **Rate Limiting**: Dynamic traffic control with token bucket algorithms
- **Static ARP Protection**: Maintains trusted IP-MAC mappings for critical hosts
- **Threat Intelligence**: Attack pattern recognition and automated response
- **Recovery Systems**: Automatic network state restoration after attacks

## Quick Start

### Deploy Complete Environment
```bash
# Build and start all containers
docker-compose up -d

# Monitor defense system
docker-compose logs -f defender
```

### Access Interfaces
- **Defense Dashboard**: http://localhost:8082 (NEW!)
- **Web Monitor**: http://localhost:8080
- **Defense API**: http://localhost:8082/api/status

### Run Attack Simulation
```bash
# Execute ARP storm attack
docker-compose exec attacker python /app/attacker_main.py --iface eth0

# Watch defense system respond in real-time!
```

## Architecture Overview

### 🔴 Attack Components

**Attacker Container**:
- Contains Python and C++ tools for ARP storm generation
- Implements high-performance gratuitous ARP flooding
- Supports targeted ARP poisoning attacks
- Configurable attack parameters (rate, duration, targets)

**Victim Container**:
- Simulates target machine with web services
- Experiences and logs attack impacts
- Provides monitoring endpoints for impact assessment

### 🔵 Monitoring Components

**Observer Container**:
- Real-time network traffic monitoring
- Detects abnormal ARP patterns and attack characteristics
- Generates PCAP captures for forensic analysis

**Web Monitor Container**:
- Visual dashboard for attack statistics
- Network health monitoring and reporting

### 🛡️ Defense Components (NEW!)

**Defender Container**:
- **Core Defense Engine**: Real-time packet analysis and mitigation
- **ML Anomaly Detection**: Unsupervised learning for threat identification
- **Adaptive Thresholds**: Statistical baseline learning and adaptation
- **Automated Response**: Dynamic blacklisting and rate limiting
- **Web Interface**: Real-time defense monitoring and control
- **API Endpoints**: Programmatic defense system management

## Attack Mechanisms

### Gratuitous ARP Storm
- Crafts ARP reply packets without corresponding requests
- Contains spoofed IP-MAC mappings sent to broadcast address
- Floods network with thousands of fake packets per second
- Overwhelms network devices and corrupts ARP caches

### ARP Poisoning
- Targeted manipulation of specific IP-MAC associations
- Man-in-the-middle attack preparation
- Network traffic redirection capabilities

### Network Impact
- Victim's ARP cache corruption with false entries
- Network device resource exhaustion
- Legitimate communication disruption
- Service unavailability and performance degradation

## Defense Mechanisms

### 1. Real-time Detection
- **Statistical Analysis**: Baseline traffic pattern learning
- **Anomaly Detection**: ML-based threat identification
- **Pattern Recognition**: Attack signature matching

### 2. Automated Mitigation
- **Rate Limiting**: Per-source packet rate enforcement
- **Dynamic Blacklisting**: Automatic malicious source blocking
- **Static ARP Protection**: Critical host mapping preservation
- **Network Isolation**: Infected segment quarantine

### 3. Intelligence and Recovery
- **Threat Intelligence**: Attack pattern database and correlation
- **Auto-Recovery**: Network state restoration procedures
- **Adaptive Learning**: Continuous defense improvement

## Container Configuration

### a. Attacker Container
- **Purpose**: ARP DoS attack simulation
- **Privileges**: NET_ADMIN, NET_RAW for raw socket access
- **Network**: Static IP (10.0.1.10) on arp_lab
- **Capabilities**: High-performance packet crafting and transmission

### b. Victim Container  
- **Purpose**: Attack target simulation
- **Network**: Static IP (10.0.1.20) on arp_lab
- **Services**: Web services and ARP response simulation

### c. Observer Container
- **Purpose**: Traffic monitoring and analysis
- **Privileges**: NET_ADMIN, NET_RAW for packet capture
- **Network**: Static IP (10.0.1.30) on arp_lab
- **Output**: PCAP files and anomaly reports

### d. Web Monitor Container
- **Purpose**: Attack visualization dashboard
- **Access**: Host port 8080
- **Networks**: arp_lab + monitor_net
- **Interface**: Real-time attack statistics and visualizations

### e. Defender Container (NEW!)
- **Purpose**: Real-time attack defense and mitigation
- **Privileges**: NET_ADMIN, NET_RAW, SYS_ADMIN for network control
- **Access**: Host ports 8082 (dashboard), 8083 (monitoring)
- **Networks**: arp_lab + monitor_net
- **Features**: ML-based detection, automated response, web interface

## Usage Examples

### Basic Attack Simulation
```bash
# Start environment
docker-compose up -d

# Execute gratuitous ARP storm
docker-compose exec attacker python attacker_main.py --mode storm --duration 60

# Monitor defense response
curl http://localhost:8082/api/status
```

### Advanced Defense Testing
```bash
# Run comprehensive defense tests
docker-compose exec defender python test_defense.py

# Generate test report
docker-compose exec defender python test_defense.py --output /app/logs/test_report.json

# Check ML detection capabilities
curl http://localhost:8082/api/ml-status
```

### Configuration Management
```bash
# Update defense configuration
curl -X POST http://localhost:8082/api/config \
  -H "Content-Type: application/json" \
  -d '{"protection_level": "high", "rate_limit": 5}'

# Manual threat response
curl -X POST http://localhost:8082/api/block-source \
  -d '{"ip": "10.0.1.100", "duration": 3600}'
```

## Monitoring and Analysis

### Real-time Dashboards
1. **Defense Dashboard** (localhost:8082): Live threat detection and mitigation status
2. **Attack Monitor** (localhost:8080): Attack statistics and impact visualization

### Log Analysis
- **Attack Logs**: `/logs/attacker_*.log` - Attack execution details
- **Defense Logs**: `/logs/defense_*.log` - Defense actions and decisions
- **Victim Logs**: `/logs/victim_*.log` - Impact assessment data
- **Observer Logs**: `/logs/observer_*.log` - Traffic analysis results

### Capture Analysis
- **PCAP Files**: `/captures/arp_capture_*.pcap` - Network traffic recordings
- **Analysis Tools**: Wireshark, tcpdump integration
- **Forensic Data**: Attack signatures and patterns

## Educational Objectives

This project demonstrates:
- **Attack Vectors**: ARP protocol vulnerabilities and exploitation techniques
- **Defense Strategies**: Multi-layered security approaches and automated response
- **Network Security**: Traffic analysis, anomaly detection, and incident response
- **Machine Learning**: Applied ML for cybersecurity and threat detection
- **DevOps Security**: Containerized security testing and defense deployment

## Testing and Validation

### Defense System Testing
```bash
# Comprehensive test suite
python defender/test_defense.py

# Quick connectivity tests
python defender/test_defense.py --quick

# Performance benchmarks
python defender/test_defense.py --performance
```

### Attack Effectiveness Testing
```bash
# Measure attack impact
docker-compose exec observer python arp_analyzer.py --measure-impact

# Generate attack reports
docker-compose exec web_monitor python monitor_main.py --generate-report
```

## Security Considerations

⚠️ **Important**: This project is for educational and authorized testing purposes only.

- Deploy only in isolated lab environments
- Ensure proper network segmentation
- Monitor system resources during testing
- Follow responsible disclosure for any vulnerabilities discovered

## Documentation

- **[Defense Deployment Guide](defender/DEPLOYMENT_GUIDE.md)**: Comprehensive defense system setup
- **[Testing Guide](TESTING_GUIDE.md)**: Attack and defense testing procedures
- **[Technical Documentation](DOC_README.md)**: Detailed technical specifications

## Contributing

This project welcomes contributions in:
- Additional attack vectors and techniques
- Enhanced defense mechanisms and ML models
- Improved monitoring and visualization capabilities
- Performance optimizations and scalability improvements

---

*This project provides a comprehensive platform for understanding ARP-based attacks and implementing effective defense strategies through practical, hands-on experimentation.*
