import struct
import random
from typing import Dict, Any, Optional
from .base import UDPProbe

class NetBIOSProbe(UDPProbe):
    """NetBIOS Name Service probe"""

    def create_probe(self) -> bytes:
        """Create NetBIOS Name Service status query"""
        # NetBIOS Name Service Status Request
        transaction_id = random.randint(1, 65535)
        flags = 0x0010  # Query, broadcast
        questions = 1
        answers = 0
        authority = 0
        additional = 0

        # Header
        packet = struct.pack('!HHHHHH',
                           transaction_id,
                           flags,
                           questions,
                           answers,
                           authority,
                           additional)

        # Query for * (all names)
        # Encode NetBIOS name (wildcard)
        encoded_name = b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
        query_type = 0x0021  # NBSTAT
        query_class = 0x0001  # IN

        packet += encoded_name
        packet += struct.pack('!HH', query_type, query_class)

        return packet

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse NetBIOS response"""
        if len(response) < 12:
            return None

        try:
            result = {
                'protocol': 'NetBIOS'
            }

            # Parse header
            header = struct.unpack('!HHHHHH', response[:12])
            flags = header[1]
            answers = header[3]

            result['answers'] = answers

            # Check if this is a response
            is_response = (flags >> 15) & 1
            if not is_response:
                return None

            # Try to extract NetBIOS names from the response
            names = []
            idx = 12

            # Skip the query section if present
            while idx < len(response) and response[idx] != 0:
                idx += 1
            idx += 5  # Skip null byte + type + class

            # Parse answer records
            for _ in range(min(answers, 10)):  # Limit to prevent infinite loops
                if idx >= len(response) - 10:
                    break

                # Skip name pointer/reference
                if response[idx] == 0xc0:
                    idx += 2
                else:
                    while idx < len(response) and response[idx] != 0:
                        idx += 1
                    idx += 1

                if idx + 10 > len(response):
                    break

                # Skip type, class, TTL
                idx += 8

                # Get data length
                if idx + 2 > len(response):
                    break
                data_len = struct.unpack('!H', response[idx:idx + 2])[0]
                idx += 2

                # Extract names from data section
                if idx + data_len > len(response):
                    break

                data_end = idx + data_len
                while idx < data_end and len(names) < 10:
                    if idx + 18 <= data_end:
                        # NetBIOS name is 15 characters + type byte
                        name_bytes = response[idx:idx + 15]
                        name = name_bytes.decode('ascii', errors='ignore').strip()
                        if name and name.isprintable():
                            name_type = response[idx + 15]
                            names.append(f"{name} ({hex(name_type)})")
                        idx += 18
                    else:
                        break

            if names:
                result['names'] = names[:5]  # Limit to first 5 names

            return result

        except Exception as e:
            return {
                'protocol': 'NetBIOS',
                'error': str(e)
            }