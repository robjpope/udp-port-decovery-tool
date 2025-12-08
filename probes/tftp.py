import struct
from typing import Dict, Any, Optional
from .base import UDPProbe

class TFTPProbe(UDPProbe):
    """TFTP service probe"""

    def create_probe(self) -> bytes:
        """Create TFTP Read Request (RRQ) for a test file"""
        # TFTP Read Request
        opcode = 1  # RRQ
        filename = b'test.txt'
        mode = b'octet'

        packet = struct.pack('!H', opcode)
        packet += filename + b'\x00'
        packet += mode + b'\x00'

        return packet

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse TFTP response"""
        if len(response) < 4:
            return None

        try:
            opcode = struct.unpack('!H', response[:2])[0]

            result = {
                'protocol': 'TFTP'
            }

            if opcode == 3:  # DATA
                block_num = struct.unpack('!H', response[2:4])[0]
                result['response_type'] = 'DATA'
                result['block'] = block_num
                if len(response) > 4:
                    result['data_size'] = len(response) - 4
            elif opcode == 5:  # ERROR
                error_code = struct.unpack('!H', response[2:4])[0]
                result['response_type'] = 'ERROR'
                result['error_code'] = error_code
                if len(response) > 4:
                    error_msg = response[4:].decode('utf-8', errors='ignore').rstrip('\x00')
                    result['error_message'] = error_msg
            else:
                result['opcode'] = opcode

            return result

        except Exception as e:
            return {
                'protocol': 'TFTP',
                'error': str(e)
            }