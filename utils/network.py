import socket
import ipaddress
import re
from typing import List, Set

def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification into list of ports

    Supports:
    - Individual ports: "53,80,443"
    - Ranges: "1-1000"
    - Mixed: "22,80-90,443"
    - Keyword: "common" for common UDP ports
    """
    ports = set()

    if port_spec.lower() == 'common':
        # Return common UDP ports
        return [
            7, 9, 13, 17, 19, 37,  # Legacy services
            53,  # DNS
            67, 68,  # DHCP
            69,  # TFTP
            123,  # NTP
            137, 138,  # NetBIOS
            161, 162,  # SNMP
            389,  # LDAP
            514,  # Syslog
            1812, 1813,  # RADIUS
            5060,  # SIP
            5353,  # mDNS
        ]

    # Parse port specification
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            # Range
            try:
                start, end = part.split('-')
                start = int(start.strip())
                end = int(end.strip())
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            except (ValueError, AttributeError) as e:
                raise ValueError(f"Invalid port range: {part}") from e
        else:
            # Individual port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port number: {port}")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Invalid port: {part}") from e

    return sorted(list(ports))

def validate_target(target: str) -> bool:
    """Validate target IP or hostname"""
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Check if it's a valid hostname
    try:
        socket.gethostbyname(target)
        return True
    except (socket.gaierror, socket.herror):
        return False

def resolve_target(target: str) -> str:
    """Resolve hostname to IP address"""
    try:
        # If already an IP, return as-is
        ipaddress.ip_address(target)
        return target
    except ValueError:
        # Try to resolve hostname
        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, socket.herror):
            raise ValueError(f"Cannot resolve target: {target}")

def parse_ip_range(ip_range: str) -> List[str]:
    """Parse IP range into list of IP addresses

    Supports:
    - Single IP: 192.168.1.1
    - IP range: 192.168.1.1-10
    - CIDR subnet: 192.168.1.0/24
    - Hostname: example.com
    """
    targets = []

    # CIDR notation (e.g., 192.168.1.0/24)
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            # Limit to reasonable size to avoid massive scans
            if network.num_addresses > 1024:
                raise ValueError(f"Network {ip_range} too large (max 1024 hosts)")
            targets.extend([str(ip) for ip in network.hosts()])
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation {ip_range}: {e}")

    # IP range with dash (e.g., 192.168.1.1-10)
    elif '-' in ip_range and not ip_range.count('.') == 0:
        try:
            # Split on last dash to handle IPv6 potentially
            parts = ip_range.rsplit('-', 1)
            if len(parts) != 2:
                raise ValueError("Invalid range format")

            start_ip, end_part = parts

            # Validate start IP
            start_addr = ipaddress.ip_address(start_ip.strip())

            # Handle different end formats
            end_part = end_part.strip()
            if '.' in end_part:
                # Full IP address
                end_addr = ipaddress.ip_address(end_part)
            else:
                # Just the last octet
                if isinstance(start_addr, ipaddress.IPv4Address):
                    octets = str(start_addr).split('.')
                    octets[-1] = end_part
                    end_addr = ipaddress.IPv4Address('.'.join(octets))
                else:
                    raise ValueError("Range notation not supported for IPv6")

            # Generate range
            start_int = int(start_addr)
            end_int = int(end_addr)

            if end_int < start_int:
                raise ValueError("End IP must be greater than start IP")

            if end_int - start_int > 1024:
                raise ValueError("IP range too large (max 1024 addresses)")

            for i in range(start_int, end_int + 1):
                targets.append(str(ipaddress.ip_address(i)))

        except ValueError as e:
            raise ValueError(f"Invalid IP range {ip_range}: {e}")

    # Single IP or hostname
    else:
        targets.append(ip_range.strip())

    return targets

def parse_targets_file(file_path: str) -> List[str]:
    """Parse targets from a file

    Supports nmap-style formats:
    - Single IPs: 192.168.1.1
    - IP ranges: 192.168.1.1-10
    - CIDR subnets: 192.168.1.0/24
    - Hostnames: example.com
    - Comments: # This is a comment
    - Blank lines (ignored)
    """
    targets = []

    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Remove inline comments
                if '#' in line:
                    line = line.split('#')[0].strip()

                try:
                    # Parse each target specification
                    line_targets = parse_ip_range(line)
                    targets.extend(line_targets)
                except ValueError as e:
                    print(f"Warning: Line {line_num} in {file_path}: {e}")
                    continue

    except FileNotFoundError:
        raise ValueError(f"Hosts file not found: {file_path}")
    except PermissionError:
        raise ValueError(f"Permission denied reading file: {file_path}")

    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)

    return unique_targets

def parse_target_spec(target_spec: str) -> List[str]:
    """Parse target specification into list of targets

    Supports comma-separated list of:
    - Single IPs
    - IP ranges
    - CIDR subnets
    - Hostnames
    """
    targets = []

    for part in target_spec.split(','):
        part = part.strip()
        if part:
            targets.extend(parse_ip_range(part))

    return targets