import struct
from typing import Dict, Any, Optional
from datetime import datetime
from .base import UDPProbe

class TimeProbe(UDPProbe):
    """Probe for RFC 868 Time Protocol (port 37)"""

    def __init__(self):
        super().__init__()
        self.name = "Time"

    def create_probe(self) -> bytes:
        """Send request packet for time service"""
        return b'\x00'  # Simple trigger packet

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse time response (32-bit timestamp since 1900)"""
        if len(response) == 0:
            return None

        result = {
            'protocol': 'RFC 868 Time',
            'response_size': len(response)
        }

        # RFC 868 specifies a 32-bit timestamp
        if len(response) == 4:
            try:
                # Unpack as big-endian 32-bit unsigned integer
                timestamp = struct.unpack('>I', response)[0]

                # RFC 868 epoch starts January 1, 1900
                # Convert to Unix timestamp (starts January 1, 1970)
                unix_timestamp = timestamp - 2208988800  # Seconds between 1900 and 1970

                if unix_timestamp > 0:  # Sanity check
                    dt = datetime.fromtimestamp(unix_timestamp)
                    result['timestamp_1900'] = timestamp
                    result['timestamp_unix'] = unix_timestamp
                    result['datetime'] = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                    result['format'] = 'RFC 868 binary'
                else:
                    result['timestamp_1900'] = timestamp
                    result['format'] = 'RFC 868 binary (invalid)'

            except (struct.error, ValueError, OverflowError):
                result['format'] = 'binary (parse error)'
                result['raw_data'] = response.hex()
        else:
            # Non-standard response size
            result['format'] = f'non-standard ({len(response)} bytes)'
            result['raw_data'] = response.hex()

            # Maybe it's a text response (some implementations vary)
            try:
                text = response.decode('utf-8', errors='ignore').strip()
                if text and text.isprintable():
                    result['text_content'] = text
                    result['possible_text_format'] = True
            except:
                pass

        return result