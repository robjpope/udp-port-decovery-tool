"""
IKE (Internet Key Exchange) probe for VPN service discovery
Supports IKEv1 and IKEv2 on ports 500 and 4500
"""

import struct
import random
from typing import Dict, Any, Optional
from .base import UDPProbe

class IKEProbe(UDPProbe):
    def __init__(self):
        super().__init__()
        self.name = "IKE/IPSec VPN"
        self.port = 500  # Also works on 4500 for NAT-T

    def create_probe(self) -> bytes:
        """Create an IKEv1 Main Mode packet (vendor ID discovery)"""
        # IKE Header for IKEv1 Main Mode
        initiator_cookie = random.randbytes(8)  # Random initiator SPI
        responder_cookie = b'\x00' * 8  # Zero responder SPI

        # IKE Header structure
        next_payload = 0x01  # SA (Security Association)
        version = 0x10  # IKEv1
        exchange_type = 0x02  # Main Mode
        flags = 0x00  # No flags
        message_id = b'\x00' * 4  # Zero message ID for Main Mode

        # SA Payload (simplified)
        sa_next_payload = 0x0d  # Vendor ID
        sa_reserved = 0x00
        sa_payload_length = struct.pack('>H', 52)  # Length of SA payload

        # DOI and Situation
        doi = b'\x00\x00\x00\x01'  # IPSec DOI
        situation = b'\x00\x00\x00\x01'  # SIT_IDENTITY_ONLY

        # Proposal
        proposal_next = 0x00  # No more proposals
        proposal_reserved = 0x00
        proposal_length = struct.pack('>H', 40)  # Length
        proposal_num = 0x01
        protocol_id = 0x01  # ISAKMP
        spi_size = 0x00
        num_transforms = 0x01

        # Transform
        transform_next = 0x00  # No more transforms
        transform_reserved = 0x00
        transform_length = struct.pack('>H', 28)
        transform_num = 0x01
        transform_id = 0x01  # KEY_IKE
        transform_reserved2 = b'\x00\x00'

        # Transform attributes (simplified)
        # Encryption: DES-CBC
        attr1 = b'\x80\x01\x00\x01'  # Encryption Algorithm: DES-CBC
        # Hash: MD5
        attr2 = b'\x80\x02\x00\x01'  # Hash Algorithm: MD5
        # Auth: PSK
        attr3 = b'\x80\x03\x00\x01'  # Auth Method: PSK
        # DH Group 1
        attr4 = b'\x80\x04\x00\x01'  # DH Group: 1
        # Life Type: Seconds
        attr5 = b'\x80\x0b\x00\x01'  # Life Type: Seconds
        # Life Duration: 28800
        attr6 = b'\x00\x0c\x00\x04\x00\x00\x70\x80'  # Life Duration

        # Vendor ID payload (Cisco Unity)
        vendor_next = 0x00  # No more payloads
        vendor_reserved = 0x00
        vendor_length = struct.pack('>H', 20)  # 4 header + 16 data
        vendor_id = b'\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00'  # Cisco Unity

        # Assemble SA payload
        sa_payload = (
            struct.pack('BB', sa_next_payload, sa_reserved) + sa_payload_length +
            doi + situation +
            struct.pack('BB', proposal_next, proposal_reserved) + proposal_length +
            struct.pack('BBBB', proposal_num, protocol_id, spi_size, num_transforms) +
            struct.pack('BB', transform_next, transform_reserved) + transform_length +
            struct.pack('BB', transform_num, transform_id) + transform_reserved2 +
            attr1 + attr2 + attr3 + attr4 + attr5 + attr6
        )

        # Assemble Vendor ID payload
        vendor_payload = (
            struct.pack('BB', vendor_next, vendor_reserved) + vendor_length + vendor_id
        )

        # Calculate total length
        total_length = 28 + len(sa_payload) + len(vendor_payload)  # 28 for IKE header

        # Assemble IKE packet
        ike_header = (
            initiator_cookie +
            responder_cookie +
            struct.pack('BBBB', next_payload, version, exchange_type, flags) +
            message_id +
            struct.pack('>I', total_length)
        )

        return ike_header + sa_payload + vendor_payload

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse IKE response"""
        if len(response) < 28:  # Minimum IKE header size
            return None

        try:
            # Parse IKE header
            initiator_cookie = response[0:8]
            responder_cookie = response[8:16]
            next_payload = response[16]
            version = response[17]
            exchange_type = response[18]
            flags = response[19]
            message_id = response[20:24]
            length = struct.unpack('>I', response[24:28])[0]

            # Determine IKE version
            major_version = (version >> 4) & 0x0F
            minor_version = version & 0x0F

            result = {
                'protocol': 'IKE',
                'version': f"IKEv{major_version}.{minor_version}",
                'exchange_type': self._get_exchange_type(exchange_type, major_version),
                'responder_cookie': responder_cookie.hex(),
                'message_length': length,
                'vendor_ids': []
            }

            # Parse payloads to find vendor IDs
            offset = 28
            current_payload = next_payload

            while current_payload != 0 and offset < len(response):
                if offset + 4 > len(response):
                    break

                payload_next = response[offset]
                payload_length = struct.unpack('>H', response[offset+2:offset+4])[0]

                if payload_length < 4 or offset + payload_length > len(response):
                    break

                # Check for Vendor ID payload (0x0d in IKEv1, 0x2b in IKEv2)
                if current_payload in [0x0d, 0x2b]:
                    vendor_data = response[offset+4:offset+payload_length]
                    vendor_name = self._identify_vendor(vendor_data)
                    if vendor_name:
                        result['vendor_ids'].append(vendor_name)

                # Check for Notify payload to identify NAT-T
                elif current_payload in [0x0b, 0x29]:  # Notify
                    result['nat_traversal'] = True

                offset += payload_length
                current_payload = payload_next

            # Determine service type
            if result['vendor_ids']:
                result['service_type'] = f"VPN Server ({', '.join(result['vendor_ids'][:2])})"
            else:
                result['service_type'] = 'VPN Server (Generic IKE)'

            return result

        except Exception as e:
            return {
                'protocol': 'IKE',
                'error': str(e),
                'response_size': len(response)
            }

    def _get_exchange_type(self, exchange_type: int, version: int) -> str:
        """Get exchange type name"""
        if version == 1:  # IKEv1
            exchanges = {
                0: 'None',
                1: 'Base',
                2: 'Main Mode',
                3: 'Authentication Only',
                4: 'Aggressive Mode',
                5: 'Informational',
                32: 'Quick Mode'
            }
        else:  # IKEv2
            exchanges = {
                34: 'IKE_SA_INIT',
                35: 'IKE_AUTH',
                36: 'CREATE_CHILD_SA',
                37: 'INFORMATIONAL'
            }
        return exchanges.get(exchange_type, f'Unknown ({exchange_type})')

    def _identify_vendor(self, vendor_data: bytes) -> Optional[str]:
        """Identify vendor from vendor ID payload"""
        # Common vendor ID patterns (first few bytes or hashes)
        vendors = {
            b'\x12\xf5\xf2\x8c\x45\x71\x68\xa9': 'Cisco Unity',
            b'\x1f\x07\xf7\x0e\xaa\x65\x14\xd3': 'Cisco IOS',
            b'\x4a\x13\x1c\x81\x07\x03\x58\x45': 'Microsoft',
            b'\x40\x48\xb7\xd5\x6e\xbc\xe8\x85': 'SonicWall',
            b'\x90\xcb\x80\x91\x3e\xbb\x69\x6e': 'Windows',
            b'\x4f\x45\x74\x79\x7a\x56\x66\x77': 'Fortinet FortiGate',
            b'\x16\x6f\x93\x2d\x55\xeb\x64\xd8': 'Checkpoint',
            b'\x62\x50\x27\x74\x9d\x5a\xb9\x7f': 'Juniper',
            b'XAUTH': 'XAuth',
            b'draft': 'Draft/RFC',
            b'Cisco': 'Cisco',
            b'Microsoft': 'Microsoft',
            b'strongSwan': 'strongSwan',
            b'openswan': 'Openswan',
            b'libreswan': 'Libreswan',
            b'Shrew': 'Shrew Soft',
            b'Openswan': 'Openswan',
            b'FreeS/WAN': 'FreeS/WAN'
        }

        # Check for exact matches or prefixes
        for pattern, name in vendors.items():
            if vendor_data.startswith(pattern):
                return name

        # Check for ASCII vendor strings
        try:
            vendor_str = vendor_data.decode('ascii', errors='ignore')
            for pattern, name in vendors.items():
                if isinstance(pattern, bytes):
                    try:
                        pattern_str = pattern.decode('ascii', errors='ignore')
                        if pattern_str in vendor_str:
                            return name
                    except:
                        pass
        except:
            pass

        return None