from typing import Dict, Any, Optional
from .base import UDPProbe

class DaytimeProbe(UDPProbe):
    """Probe for RFC 867 Daytime Protocol (port 13)"""

    def __init__(self):
        super().__init__()
        self.name = "Daytime"

    def create_probe(self) -> bytes:
        """Send request packet for daytime service"""
        return b'\x00'  # Simple trigger packet

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse daytime response (human-readable timestamp)"""
        if len(response) == 0:
            return None

        result = {
            'protocol': 'RFC 867 Daytime',
            'response_size': len(response)
        }

        # Try to decode as text
        try:
            text = response.decode('utf-8', errors='ignore').strip()
            if text and text.isprintable():
                result['timestamp'] = text
                result['format'] = 'human-readable'

                # Check for common timestamp formats
                if any(day in text for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']):
                    result['contains_weekday'] = True
                if any(tz in text for tz in ['GMT', 'UTC', 'EST', 'PST', 'CST', 'MST']):
                    result['timezone_info'] = True

        except UnicodeDecodeError:
            # Binary response is unusual for daytime
            result['format'] = 'binary'
            result['binary_data'] = response.hex()

        return result