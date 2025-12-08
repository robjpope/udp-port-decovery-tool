import struct
import random
from typing import Dict, Any, Optional
from .base import UDPProbe

class DNSProbe(UDPProbe):
    """DNS service probe"""

    def create_probe(self) -> bytes:
        """Create a DNS query for version.bind TXT record"""
        # DNS Header
        transaction_id = random.randint(1, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        answers = 0
        authority = 0
        additional = 0

        header = struct.pack('!HHHHHH',
                           transaction_id,
                           flags,
                           questions,
                           answers,
                           authority,
                           additional)

        # Query for version.bind TXT in CHAOS class
        query_name = b'\x07version\x04bind\x00'  # version.bind
        query_type = 0x0010  # TXT record
        query_class = 0x0003  # CHAOS class

        query = query_name + struct.pack('!HH', query_type, query_class)

        return header + query

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNS response"""
        if len(response) < 12:
            return None

        try:
            # Parse header
            header = struct.unpack('!HHHHHH', response[:12])
            transaction_id = header[0]
            flags = header[1]
            questions = header[2]
            answers = header[3]

            # Check if this is a valid DNS response
            is_response = (flags >> 15) & 1
            if not is_response:
                return None

            # Extract basic info
            result = {
                'protocol': 'DNS',
                'response_code': flags & 0xF,
                'answers': answers,
                'questions': questions
            }

            # Try to extract version if present in TXT record
            if answers > 0 and len(response) > 12:
                # Simple extraction - look for text strings
                idx = 12
                # Skip the question section
                while idx < len(response) and response[idx] != 0:
                    idx += 1
                idx += 5  # Skip null byte + type + class

                # Try to find TXT data in answer
                if idx < len(response) - 10:
                    # Look for TXT record patterns
                    for i in range(idx, min(idx + 100, len(response) - 1)):
                        if response[i] > 0 and response[i] < 50:
                            txt_len = response[i]
                            if i + txt_len + 1 <= len(response):
                                txt_data = response[i+1:i+1+txt_len]
                                try:
                                    version_str = txt_data.decode('utf-8', errors='ignore')
                                    if version_str and len(version_str) > 2:
                                        result['version'] = version_str
                                        break
                                except:
                                    pass

            return result

        except Exception as e:
            return {
                'protocol': 'DNS',
                'error': str(e)
            }