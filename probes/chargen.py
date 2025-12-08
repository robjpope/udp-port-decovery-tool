from typing import Dict, Any, Optional
from .base import UDPProbe

class ChargenProbe(UDPProbe):
    """Generic probe for simple UDP services"""

    def create_probe(self) -> bytes:
        """Send a simple trigger packet"""
        return b'\x00'  # Single null byte to trigger response

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse response from simple UDP services"""
        if len(response) == 0:
            return None

        result = {
            'protocol': 'UDP Service',
            'response_size': len(response)
        }

        # Try to decode as text
        try:
            text = response.decode('utf-8', errors='ignore')
            if text and text.isprintable():
                # Truncate long responses
                if len(text) > 100:
                    result['response'] = text[:100] + '...'
                else:
                    result['response'] = text

                # Identify service based on response patterns
                if 'GMT' in text or 'UTC' in text:
                    result['service_type'] = 'Daytime'
                elif len(text) > 200 and all(c in text for c in 'abcdefghij'):
                    result['service_type'] = 'Chargen'
                elif '\"' in text or 'quote' in text.lower():
                    result['service_type'] = 'Quote of the Day'
        except:
            # Binary response
            if len(response) == 4:
                result['service_type'] = 'Time Protocol'
            else:
                result['binary_response'] = True

        return result