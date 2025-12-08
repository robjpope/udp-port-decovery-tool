import struct
from typing import Dict, Any, Optional
from .base import UDPProbe

class SNMPProbe(UDPProbe):
    """SNMP service probe"""

    def create_probe(self) -> bytes:
        """Create SNMPv2c GetRequest for sysDescr"""
        # SNMP v2c GetRequest for sysDescr OID (1.3.6.1.2.1.1.1.0)
        # Using community string "public"

        # This is a pre-built SNMPv2c packet for simplicity
        # Real implementation would use pysnmp or construct properly
        snmp_packet = bytes([
            0x30, 0x29,  # SEQUENCE
            0x02, 0x01, 0x01,  # Version: 2c
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # Community: "public"
            0xa0, 0x1c,  # GetRequest PDU
            0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # Request ID
            0x02, 0x01, 0x00,  # Error status: 0
            0x02, 0x01, 0x00,  # Error index: 0
            0x30, 0x0e,  # Variable bindings
            0x30, 0x0c,  # Variable binding
            0x06, 0x08,  # OID
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # sysDescr.0
            0x05, 0x00  # NULL value
        ])

        return snmp_packet

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse SNMP response"""
        if len(response) < 10:
            return None

        try:
            result = {
                'protocol': 'SNMP'
            }

            # Basic SNMP packet validation
            if response[0] != 0x30:  # SEQUENCE
                return None

            # Try to extract community string
            idx = 2  # Skip SEQUENCE header
            if idx < len(response) and response[idx] == 0x02:  # Version
                idx += response[idx + 1] + 2  # Skip version
                if idx < len(response) and response[idx] == 0x04:  # Community string
                    comm_len = response[idx + 1]
                    if idx + 2 + comm_len <= len(response):
                        community = response[idx + 2:idx + 2 + comm_len]
                        result['community'] = community.decode('utf-8', errors='ignore')

            # Check for response PDU type
            for i in range(len(response) - 1):
                if response[i] == 0xa2:  # GetResponse PDU
                    result['response_type'] = 'GetResponse'
                    break
                elif response[i] == 0xa8:  # Report PDU
                    result['response_type'] = 'Report'
                    break

            # Try to extract system description if present
            # Look for printable ASCII strings that might be sysDescr
            for i in range(len(response) - 10):
                if response[i] == 0x04:  # OCTET STRING
                    str_len = response[i + 1] if i + 1 < len(response) else 0
                    if str_len > 5 and i + 2 + str_len <= len(response):
                        potential_str = response[i + 2:i + 2 + str_len]
                        try:
                            decoded = potential_str.decode('utf-8', errors='ignore')
                            if decoded and len(decoded) > 5 and decoded.isprintable():
                                if 'Linux' in decoded or 'Windows' in decoded or 'Cisco' in decoded:
                                    result['system'] = decoded
                                    break
                        except:
                            pass

            return result

        except Exception as e:
            return {
                'protocol': 'SNMP',
                'error': str(e)
            }