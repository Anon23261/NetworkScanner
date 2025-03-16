# Enhanced Network Scanner

A professional-grade network analysis and security assessment tool for authorized network administrators and security professionals. This tool helps identify devices, services, and potential security issues within your network infrastructure.

## ⚠️ Important Notice

This tool is for **AUTHORIZED USE ONLY**. You must have explicit permission to scan any network. Unauthorized scanning may be illegal and unethical.

## Features

### Core Functionality
- **Network Discovery**: Advanced ARP-based device detection
- **OS Detection**: Operating system fingerprinting
- **Service Analysis**: Port scanning and service identification
- **Device Information**:
  - MAC address vendor lookup
  - Hostname resolution
  - Response time analysis
  - Gateway detection

### Security Assessment
- **Port Analysis**: Identifies open ports and running services
- **Service Fingerprinting**: Banner grabbing and service version detection
- **Network Topology**: Maps network structure and identifies key devices
- **Vulnerability Checking**: Basic security configuration assessment
- **Security Logging**: Comprehensive security event logging

### Output Features
- **Real-time Display**: Live scanning progress and results
- **Multiple Formats**: CSV and JSON export options
- **Detailed Logging**: Comprehensive activity logging
- **Custom Reports**: Configurable output formats

## Requirements

### System Requirements
- Python 3.8 or higher
- Administrator/root privileges for full functionality
- Network access permissions

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/NetworkScanner.git
cd NetworkScanner

# Install dependencies
pip install -r requirements.txt
```

## Usage Guide

### Basic Commands

1. Basic Network Scan:
```bash
python src/network_scanner.py 192.168.1.0/24
```

2. Advanced Scan with Custom Ports:
```bash
python src/network_scanner.py 192.168.1.0/24 -s 2 -p 80 443 3389 8080
```

3. Full Security Assessment:
```bash
python src/network_scanner.py 192.168.1.0/24 --security-check --format json
```

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| network | Target network in CIDR notation | 192.168.1.0/24 |
| -s, --stealth | Stealth level (1-3) | -s 2 |
| -p, --ports | Specific ports to scan | -p 80 443 8080 |
| -f, --format | Output format (csv/json) | -f json |
| --security-check | Enable security assessment | --security-check |

### Output Files

1. **Scan Results**:
   - `scan_results_[timestamp].csv`: Detailed CSV report
   - `scan_results_[timestamp].json`: JSON formatted data
   - `network_scan.log`: Complete scan log

2. **Security Reports**:
   - `security_assessment_[timestamp].txt`: Security findings
   - `vulnerability_report_[timestamp].txt`: Potential vulnerabilities

### Log File Locations

```plaintext
./logs/
  ├── network_scan.log       # Main application log
  ├── security_events.log    # Security-related events
  └── error.log             # Error tracking
```

## Security Assessment Features

### 1. Port Security
- Open port detection
- Service identification
- Common misconfiguration checks
- Default credential testing (requires authorization)

### 2. Network Analysis
- Device enumeration
- Service mapping
- Network topology
- Gateway configuration

### 3. Security Checks
- Default port detection
- Service version analysis
- Basic vulnerability assessment
- Configuration review

## Best Practices

1. **Authorization**:
   - Always obtain written permission before scanning
   - Document all scanning activities
   - Follow organization's security policies

2. **Network Impact**:
   - Use appropriate stealth levels
   - Schedule intensive scans during off-hours
   - Monitor network performance

3. **Data Handling**:
   - Secure scan results
   - Remove sensitive data from reports
   - Follow data retention policies

## Logging and Monitoring

### Log Types

1. **Network Scan Log**:
   - Device discoveries
   - Port scan results
   - Service detections

2. **Security Event Log**:
   - Potential vulnerabilities
   - Configuration issues
   - Security alerts

3. **Error Log**:
   - Scan failures
   - Connection issues
   - System errors

### Log Format
```plaintext
[TIMESTAMP] [LEVEL] [COMPONENT] Message
Example: [2024-03-14 15:30:45] [INFO] [PortScanner] Found open port 80 on 192.168.1.100
```

## License

MIT License

Copyright (c) 2024 Network Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

1. The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

2. Authorization and Ethical Use:
   - Users must obtain explicit permission before scanning any network
   - The tool shall not be used for malicious purposes
   - Users must comply with all applicable laws and regulations

3. Disclaimer:
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

- GitHub Issues: Report bugs and feature requests
- Documentation: Wiki and inline code documentation
- Community: Discussions and contributions welcome

Remember to always use this tool responsibly and legally!
