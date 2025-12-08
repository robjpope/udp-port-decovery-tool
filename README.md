# UDP Port Discovery Tool

A Python-based Linux tool for UDP port discovery and service identification. This tool attempts to elicit responses from UDP services discovered during port scans by sending protocol-specific probes.

## Overview

Unlike TCP ports which provide clear open/closed states, UDP port scanning is challenging because:
- UDP services don't send acknowledgments
- "Open" UDP ports may not respond without valid protocol data
- Many UDP services only respond to specific, properly formatted requests

This tool addresses these challenges by:
1. Accepting UDP port scan results (open/filtered ports)
2. Sending protocol-specific probes to potentially open UDP ports
3. Analyzing responses to identify running services
4. Providing detailed service information when possible

## Features

- Multiple UDP protocol probe support (DNS, SNMP, NTP, DHCP, etc.)
- Concurrent scanning for faster results
- Service version detection where possible
- Rate limiting to avoid overwhelming targets
- JSON and text output formats
- Integration with common port scanning tools

## Requirements

- Python 3.8+
- Linux operating system
- Root/sudo privileges (for raw socket operations)
- Python packages (see requirements.txt)

## Installation

```bash
git clone https://github.com/yourusername/udp-port-discovery-tool.git
cd udp-port-discovery-tool
pip install -r requirements.txt
```

## Quick Test with Docker

For safe testing without affecting your host system, use the included Docker test environment:

```bash
# Start internal test network (no host ports exposed)
docker compose up -d

# Run tests inside the isolated network
docker exec udp-scanner python3 test_internal.py

# Manual testing inside container
docker exec udp-scanner python3 udp_discovery.py -t udp-test-ntp -p 123
docker exec udp-scanner python3 udp_discovery.py -t udp-test-tftp -p 69

# View container logs
docker compose logs

# Cleanup
docker compose down
```

## Usage

Basic usage:
```bash
sudo python3 udp_discovery.py -t TARGET -p PORTS
```

Examples:
```bash
# Scan specific ports
sudo python3 udp_discovery.py -t 192.168.1.1 -p 53,161,123

# Scan IP range (last octet)
sudo python3 udp_discovery.py -t 192.168.1.1-10 -p common

# Scan CIDR subnet
sudo python3 udp_discovery.py -t 192.168.1.0/24 -p 53,123,161

# Scan multiple targets (comma-separated)
sudo python3 udp_discovery.py -t "192.168.1.1,10.0.0.1,example.com" -p common

# Scan from hosts file
sudo python3 udp_discovery.py -f targets.txt -p common

# Custom timeout and retries
sudo python3 udp_discovery.py -t 192.168.1.1-5 -p 53,123,161 --timeout 3 --retries 2

# Output as JSON
sudo python3 udp_discovery.py -f targets.txt -p common --output json > results.json
```

### Hosts File Format

Create a `targets.txt` file with nmap-style target specifications:

```bash
# Single IPs
192.168.1.1
10.0.0.1

# IP ranges (last octet)
192.168.1.10-20
172.16.0.100-110

# CIDR subnets
192.168.2.0/28      # 14 hosts
10.0.1.0/29         # 6 hosts

# Full IP ranges
192.168.1.50-192.168.1.60

# Hostnames
google.com
dns.google

# Comments and blank lines are ignored
# This is a comment

# Multiple targets per line (comma-separated)
192.168.1.200,192.168.1.201,192.168.1.202
```

Then scan the file:
```bash
sudo python3 udp_discovery.py -f targets.txt -p common
```

## Supported UDP Services

**Implemented and Tested:**
- **DNS (53)** - Domain queries and version detection
- **NTP (123)** - Network Time Protocol with stratum and mode detection
- **TFTP (69)** - Trivial File Transfer Protocol with file read requests
- **SNMP (161/162)** - SNMPv1/v2c community string probing and system info
- **DHCP (67/68)** - DHCP discover packets with IP offer detection
- **Echo (7)** - Echo service with request verification
- **Chargen (19)** - Character Generator with 512-character responses
- **Daytime (13)** - Daytime protocol with human-readable time
- **Time (37)** - Time protocol with binary timestamp (RFC 868)
- **Legacy services** - Full support for classic internet services

**Planned Support:**
- **SIP (5060)** - Session Initiation Protocol OPTIONS
- **NetBIOS (137/138)** - Name service queries
- **mDNS (5353)** - Multicast DNS service discovery
- **RADIUS (1812/1813)** - Authentication and accounting
- **Syslog (514)** - System logging protocol

## Output

The tool provides detailed information about discovered services:
```
[+] udp-test-ntp:123 - NTP
    protocol: NTP
    version: NTPv4
    stratum: 0
    mode: Server
    type: Kiss-of-Death

[+] udp-test-tftp:69 - TFTP
    protocol: TFTP
    response_type: DATA
    block: 1
    data_size: 75

[+] udp-test-chargen:19 - Chargen
    protocol: UDP Service
    response_size: 512
    service_type: Chargen

[+] udp-test-daytime:13 - Chargen
    protocol: UDP Service
    response: Sunday, December 07, 2025 23:55:00
```

**JSON Output:**
```json
[
  {
    "target": "udp-test-ntp",
    "port": 123,
    "service": "NTP",
    "status": "open",
    "details": {
      "protocol": "NTP",
      "version": "NTPv4",
      "stratum": 0,
      "mode": "Server",
      "type": "Kiss-of-Death"
    },
    "response_size": 48
  }
]
```

## Development

### Testing with Docker Environment

The repository includes a complete Docker test environment:

```bash
# Start all test services in isolated network
docker compose up -d

# Check service status
docker compose ps

# Run comprehensive tests
docker exec udp-scanner python3 test_internal.py

# Test individual services
docker exec udp-scanner python3 udp_discovery.py -t udp-test-ntp -p 123
docker exec udp-scanner python3 udp_discovery.py -t udp-test-tftp -p 69
docker exec udp-scanner python3 udp_discovery.py -t udp-test-chargen -p 19

# Test all legacy services
docker exec udp-scanner python3 udp_discovery.py -t "udp-test-chargen,udp-test-daytime,udp-test-time" -p "13,19,37"

# Interactive testing
docker exec -it udp-scanner bash
```

### Available Test Services

The Docker environment provides these services for testing:
- **NTP**: `udp-test-ntp:123` - Network Time Protocol with stratum detection
- **TFTP**: `udp-test-tftp:69` - Trivial File Transfer Protocol with file requests
- **DNS**: `udp-test-dns:53` - Domain Name System (BIND9)
- **Echo**: `udp-test-echo:7` - Echo service
- **Chargen**: `udp-test-chargen:19` - Character Generator (512 chars)
- **Daytime**: `udp-test-daytime:13` - Daytime protocol (human readable time)
- **Time**: `udp-test-time:37` - Time protocol (binary format since 1900)

### Code Quality

```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .
```

## Security Considerations

This tool is designed for:
- Network administrators assessing their own networks
- Security professionals conducting authorized assessments
- Researchers analyzing UDP service implementations

**Important:** Only use this tool on networks you own or have explicit permission to test. Unauthorized port scanning may violate laws and regulations.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Files and Structure

```
udp-port-discovery-tool/
├── udp_discovery.py              # Main CLI tool
├── requirements.txt              # Python dependencies
├── targets.txt                   # Example hosts file
├── docker-compose.yml            # Docker test environment
├── docker/                       # Docker service configurations
│   ├── legacy-services/          # Legacy UDP service implementations
│   │   ├── chargen.py            # Character Generator service
│   │   ├── daytime.py            # Daytime service
│   │   └── time.py               # Time protocol service
│   ├── bind/                     # DNS server configuration
│   ├── tftp/                     # TFTP server files
│   └── ...                       # Other service configs
├── probes/                       # UDP service probe implementations
│   ├── dns.py                    # DNS probe with version detection
│   ├── ntp.py                    # NTP probe with stratum analysis
│   ├── tftp.py                   # TFTP probe with file requests
│   ├── chargen.py                # Legacy service probe
│   └── ...                       # Other protocol probes
├── utils/                        # Utility modules
│   ├── network.py                # Target parsing (IPs, ranges, subnets)
│   └── output.py                 # Output formatting (JSON, CSV, text)
└── tests/                        # Test scripts
    ├── test_internal.py          # Internal Docker network tests
    └── test_local.py             # Local testing script
```

## Disclaimer

This tool is for defensive security purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before use.

**The Docker test environment is completely isolated and safe for testing without affecting your host system.**