import struct
import random
import socket
from typing import Dict, Any, Optional
from .base import UDPProbe

class DHCPProbe(UDPProbe):
    """DHCP service probe"""

    def create_probe(self) -> bytes:
        """Create DHCP Discover packet"""
        # DHCP Discover message
        packet = bytearray()

        # Message type: Boot Request
        packet.append(0x01)
        # Hardware type: Ethernet
        packet.append(0x01)
        # Hardware address length
        packet.append(0x06)
        # Hops
        packet.append(0x00)
        # Transaction ID
        xid = random.randint(0, 0xFFFFFFFF)
        packet.extend(struct.pack('!I', xid))
        # Seconds elapsed
        packet.extend(struct.pack('!H', 0))
        # Flags
        packet.extend(struct.pack('!H', 0x8000))  # Broadcast flag
        # Client IP
        packet.extend(struct.pack('!I', 0))
        # Your IP
        packet.extend(struct.pack('!I', 0))
        # Server IP
        packet.extend(struct.pack('!I', 0))
        # Gateway IP
        packet.extend(struct.pack('!I', 0))
        # Client hardware address (MAC) - random
        mac = bytes([random.randint(0, 255) for _ in range(6)])
        packet.extend(mac)
        # Client hardware address padding
        packet.extend(b'\x00' * 10)
        # Server host name
        packet.extend(b'\x00' * 64)
        # Boot file name
        packet.extend(b'\x00' * 128)
        # Magic cookie
        packet.extend(struct.pack('!I', 0x63825363))
        # DHCP options
        # Option 53: DHCP Message Type (Discover)
        packet.extend(b'\x35\x01\x01')
        # End option
        packet.append(0xff)

        return bytes(packet)

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse DHCP response"""
        if len(response) < 240:
            return None

        try:
            result = {
                'protocol': 'DHCP'
            }

            # Message type
            msg_type = response[0]
            if msg_type == 0x02:
                result['message_type'] = 'Boot Reply'
            else:
                result['message_type'] = f'Type {msg_type}'

            # Your IP (offered IP)
            your_ip = socket.inet_ntoa(response[16:20])
            if your_ip != '0.0.0.0':
                result['offered_ip'] = your_ip

            # Server IP
            server_ip = socket.inet_ntoa(response[20:24])
            if server_ip != '0.0.0.0':
                result['server_ip'] = server_ip

            # Check for DHCP options (after magic cookie)
            magic_cookie_offset = 236
            if len(response) > magic_cookie_offset + 4:
                magic = struct.unpack('!I', response[magic_cookie_offset:magic_cookie_offset + 4])[0]
                if magic == 0x63825363:
                    # Parse DHCP options
                    idx = magic_cookie_offset + 4
                    while idx < len(response):
                        if response[idx] == 0xff:  # End option
                            break
                        if response[idx] == 0x35 and idx + 2 < len(response):  # Message type
                            dhcp_msg_type = response[idx + 2]
                            types = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST',
                                   4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE'}
                            result['dhcp_type'] = types.get(dhcp_msg_type, f'Type {dhcp_msg_type}')
                            break
                        if idx + 1 < len(response):
                            option_len = response[idx + 1]
                            idx += 2 + option_len
                        else:
                            break

            return result

        except Exception as e:
            return {
                'protocol': 'DHCP',
                'error': str(e)
            }