import random
import string
from typing import Dict, Any, Optional
from .base import UDPProbe

class EchoProbe(UDPProbe):
    """Echo service probe"""

    def __init__(self):
        super().__init__()
        # Generate a unique test string
        self.test_string = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def create_probe(self) -> bytes:
        """Create echo test packet"""
        return self.test_string.encode('utf-8')

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse echo response"""
        if len(response) == 0:
            return None

        result = {
            'protocol': 'Echo',
            'response_size': len(response)
        }

        try:
            response_text = response.decode('utf-8', errors='ignore')
            if response_text == self.test_string:
                result['service_type'] = 'Echo Service'
                result['echo_verified'] = True
            else:
                result['response'] = response_text[:50] + '...' if len(response_text) > 50 else response_text
                result['echo_verified'] = False
        except:
            result['binary_response'] = True

        return result