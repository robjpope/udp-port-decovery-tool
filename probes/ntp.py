import struct
import time
from typing import Dict, Any, Optional
from .base import UDPProbe

class NTPProbe(UDPProbe):
    """NTP service probe"""

    def create_probe(self) -> bytes:
        """Create NTP client mode request"""
        # NTP packet structure
        # LI (2 bits): 0 (no warning)
        # VN (3 bits): 4 (NTP version 4)
        # Mode (3 bits): 3 (client)
        li_vn_mode = (0 << 6) | (4 << 3) | 3

        # Other fields
        stratum = 0
        poll = 0
        precision = 0
        root_delay = 0
        root_dispersion = 0
        ref_id = 0

        # Timestamps (we'll use current time for transmit timestamp)
        # NTP uses seconds since 1900-01-01
        ntp_epoch = 2208988800
        current_time = int(time.time()) + ntp_epoch

        reference_timestamp = 0
        origin_timestamp = 0
        receive_timestamp = 0
        transmit_timestamp = current_time

        # Pack the NTP packet
        packet = struct.pack('!BBBb', li_vn_mode, stratum, poll, precision)
        packet += struct.pack('!I', root_delay)
        packet += struct.pack('!I', root_dispersion)
        packet += struct.pack('!I', ref_id)
        packet += struct.pack('!Q', reference_timestamp)
        packet += struct.pack('!Q', origin_timestamp)
        packet += struct.pack('!Q', receive_timestamp)
        packet += struct.pack('!Q', transmit_timestamp)

        return packet

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse NTP response"""
        if len(response) < 48:
            return None

        try:
            # Unpack NTP response
            li_vn_mode = response[0]
            stratum = response[1]
            poll = response[2]
            precision = struct.unpack('!b', response[3:4])[0]

            # Extract version and mode
            version = (li_vn_mode >> 3) & 0x07
            mode = li_vn_mode & 0x07

            # Get reference ID (4 bytes at offset 12)
            ref_id_bytes = response[12:16]

            # Interpret reference ID based on stratum
            if stratum == 0 or stratum == 1:
                # Primary reference (ASCII)
                ref_id = ref_id_bytes.decode('ascii', errors='ignore').strip('\x00')
            else:
                # Secondary reference (IP address)
                ref_id = '.'.join(str(b) for b in ref_id_bytes)

            result = {
                'protocol': 'NTP',
                'version': f'NTPv{version}',
                'stratum': stratum,
                'mode': self._get_mode_name(mode),
                'precision': precision,
                'poll': poll
            }

            # Add reference ID if meaningful
            if ref_id and ref_id != '0.0.0.0':
                result['reference'] = ref_id

            # Stratum interpretation
            if stratum == 0:
                result['type'] = 'Kiss-of-Death'
            elif stratum == 1:
                result['type'] = 'Primary reference'
            elif stratum <= 15:
                result['type'] = f'Secondary reference (stratum {stratum})'
            else:
                result['type'] = 'Unsynchronized'

            return result

        except Exception as e:
            return {
                'protocol': 'NTP',
                'error': str(e)
            }

    def _get_mode_name(self, mode: int) -> str:
        """Get human-readable mode name"""
        modes = {
            0: 'Reserved',
            1: 'Symmetric active',
            2: 'Symmetric passive',
            3: 'Client',
            4: 'Server',
            5: 'Broadcast',
            6: 'Control',
            7: 'Private'
        }
        return modes.get(mode, f'Unknown ({mode})')