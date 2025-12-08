# UDP Test Environment

This Docker Compose setup provides a comprehensive UDP service test environment for developing and testing the UDP Port Discovery Tool.

## Quick Start

```bash
# Build and start all services
docker compose up -d

# View running services
docker compose ps

# Check logs
docker compose logs -f

# Stop all services
docker compose down
```

## Services and Ports

All services are mapped to non-standard ports to avoid conflicts with host services:

| Service | Container Port | Host Port | Protocol | Description |
|---------|---------------|-----------|----------|-------------|
| DNS | 53 | 5353 | UDP | BIND9 DNS server |
| SNMP | 161/162 | 1161/1162 | UDP | SNMP daemon with public community |
| NTP | 123 | 1123 | UDP | NTP time server |
| TFTP | 69 | 1069 | UDP | TFTP server with test files |
| Syslog | 514/601 | 1514/1601 | UDP | Syslog-ng server |
| DHCP | 67/68 | 1067/1068 | UDP | ISC DHCP server |
| LDAP | 389 | 1389 | UDP/TCP | OpenLDAP server |
| SIP | 5060 | 5060 | UDP/TCP | Asterisk SIP server |
| Echo | 7 | 1007 | UDP | Echo service |
| Discard | 9 | 1009 | UDP | Discard service |
| Daytime | 13 | 1013 | UDP | Daytime service |
| QOTD | 17 | 1017 | UDP | Quote of the Day |
| Chargen | 19 | 1019 | UDP | Character generator |
| Time | 37 | 1037 | UDP | Time protocol |
| NetBIOS-NS | 137 | 1137 | UDP | NetBIOS name service |
| NetBIOS-DGM | 138 | 1138 | UDP | NetBIOS datagram |
| mDNS | 5353 | 5353 | UDP | Multicast DNS/Avahi |
| RADIUS | 1812/1813 | 1812/1813 | UDP | FreeRADIUS server |

## Testing Individual Services

### DNS (Port 5353)
```bash
# Query DNS server
dig @localhost -p 5353 test.local

# Query version
dig @localhost -p 5353 version.bind CH TXT
```

### SNMP (Port 1161)
```bash
# Walk SNMP tree
snmpwalk -v2c -c public localhost:1161

# Get system info
snmpget -v2c -c public localhost:1161 sysDescr.0
```

### NTP (Port 1123)
```bash
# Query NTP
ntpdate -q -p 1 localhost:1123
```

### TFTP (Port 1069)
```bash
# Get file from TFTP
tftp localhost 1069 -c get test.txt
```

### Legacy Services
```bash
# Test echo service
echo "Hello" | nc -u localhost 1007

# Test daytime
echo "" | nc -u localhost 1013

# Test chargen
echo "" | nc -u localhost 1019
```

### NetBIOS (Port 1137)
```bash
# Query NetBIOS names
nmblookup -U localhost -p 1137 '*'
```

## Testing with the UDP Discovery Tool

```bash
# Test all services on localhost
sudo python3 udp_discovery.py -t localhost -p 1007,1009,1013,1017,1019,1037,1067,1069,1123,1137,1138,1161,1389,1514,1812,5060,5353

# Test with JSON output
sudo python3 udp_discovery.py -t localhost -p 1-65535 --output json > docker_test_results.json
```

## Service Credentials

- **SNMP**: Community string = `public`
- **LDAP**: Admin DN = `cn=admin,dc=test,dc=local`, Password = `admin`
- **SIP**: Test user = `test`, Password = `test123`
- **RADIUS**: Secret = `testing123`

## Troubleshooting

### Check if services are running
```bash
docker-compose ps
```

### View service logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs dns
docker-compose logs snmp
```

### Rebuild services after changes
```bash
docker-compose build
docker-compose up -d
```

### Network issues
```bash
# Check Docker network
docker network ls
docker network inspect udp-port-decovery-tool_udp-test
```

### Permission issues
Some services may require additional capabilities:
```bash
docker-compose down
docker-compose up -d --force-recreate
```

## Customization

### Adding new services
1. Create a new service definition in `docker-compose.yml`
2. Map UDP ports to avoid conflicts
3. Add configuration files in `docker/` subdirectory
4. Update this README with testing instructions

### Modifying service configurations
Configuration files are located in:
- `docker/bind/` - DNS configuration
- `docker/snmpd/` - SNMP configuration
- `docker/samba/` - NetBIOS/Samba configuration
- `docker/asterisk/` - SIP configuration
- `docker/legacy/` - Legacy services configuration

## Security Note

This test environment is configured for maximum accessibility and should **NEVER** be exposed to public networks. All services use weak or public credentials for testing purposes only.