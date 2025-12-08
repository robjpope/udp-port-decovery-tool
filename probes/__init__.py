from typing import Dict, Optional, Type
from .base import UDPProbe
from .dns import DNSProbe
from .snmp import SNMPProbe
from .ntp import NTPProbe
from .tftp import TFTPProbe
from .dhcp import DHCPProbe
from .syslog import SyslogProbe
from .netbios import NetBIOSProbe
from .chargen import ChargenProbe
from .echo import EchoProbe
from .daytime import DaytimeProbe
from .time import TimeProbe

PROBE_REGISTRY: Dict[int, Type[UDPProbe]] = {
    7: EchoProbe,
    9: ChargenProbe,  # Discard protocol
    13: DaytimeProbe,  # Daytime (RFC 867)
    17: ChargenProbe,  # QOTD
    19: ChargenProbe,  # Character Generator
    37: TimeProbe,     # Time Protocol (RFC 868)
    53: DNSProbe,
    67: DHCPProbe,
    68: DHCPProbe,
    69: TFTPProbe,
    123: NTPProbe,
    137: NetBIOSProbe,
    138: NetBIOSProbe,
    161: SNMPProbe,
    162: SNMPProbe,
    514: SyslogProbe,
    1812: ChargenProbe,  # RADIUS - simplified
    1813: ChargenProbe,  # RADIUS Accounting
    5060: ChargenProbe,  # SIP - simplified for now
    5353: DNSProbe,  # mDNS uses DNS protocol
}

# Common UDP ports for quick scanning
COMMON_UDP_PORTS = [
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

def get_probe_for_port(port: int) -> Optional[UDPProbe]:
    """Get the appropriate probe instance for a given port"""
    probe_class = PROBE_REGISTRY.get(port)
    if probe_class:
        return probe_class()
    return None

__all__ = [
    'UDPProbe',
    'DNSProbe',
    'SNMPProbe',
    'NTPProbe',
    'TFTPProbe',
    'DHCPProbe',
    'SyslogProbe',
    'NetBIOSProbe',
    'ChargenProbe',
    'EchoProbe',
    'DaytimeProbe',
    'TimeProbe',
    'PROBE_REGISTRY',
    'COMMON_UDP_PORTS',
    'get_probe_for_port'
]