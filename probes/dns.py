import struct
import random
from typing import Dict, Any, Optional
from .base import UDPProbe

class DNSProbe(UDPProbe):
    """DNS service probe"""

    def create_probe(self) -> bytes:
        """Create a DNS query for specified domain or version.bind TXT record"""
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

        # Get domain from parameters, default to version.bind
        domain = self.params.get('domain', 'version.bind')
        query_type = self.params.get('query_type', 'TXT')

        # Convert domain to DNS wire format
        query_name = self._encode_domain(domain)

        # Set query type and class
        if query_type.upper() == 'A':
            qtype = 0x0001  # A record
            qclass = 0x0001  # IN class
        elif query_type.upper() == 'AAAA':
            qtype = 0x001C  # AAAA record
            qclass = 0x0001  # IN class
        elif query_type.upper() == 'TXT':
            qtype = 0x0010  # TXT record
            if domain == 'version.bind':
                qclass = 0x0003  # CHAOS class for version.bind
            else:
                qclass = 0x0001  # IN class for regular TXT records
        else:
            qtype = 0x0001  # Default to A record
            qclass = 0x0001  # IN class

        query = query_name + struct.pack('!HH', qtype, qclass)

        return header + query

    def _encode_domain(self, domain: str) -> bytes:
        """Encode domain name in DNS wire format"""
        if not domain:
            return b'\x00'

        parts = domain.split('.')
        encoded = b''

        for part in parts:
            if len(part) > 63:
                raise ValueError(f"DNS label too long: {part}")
            encoded += bytes([len(part)]) + part.encode('utf-8')

        encoded += b'\x00'  # Root label
        return encoded

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
                'questions': questions,
                'queried_domain': self.params.get('domain', 'version.bind'),
                'query_type': self.params.get('query_type', 'TXT')
            }

            # Add response code meaning
            response_codes = {
                0: 'NOERROR',
                1: 'FORMERR',
                2: 'SERVFAIL',
                3: 'NXDOMAIN',
                4: 'NOTIMP',
                5: 'REFUSED'
            }
            result['response_code_name'] = response_codes.get(result['response_code'], 'UNKNOWN')

            # Try to extract answer data if present
            if answers > 0 and len(response) > 12:
                answers_data = self._parse_answers(response)
                if answers_data:
                    result['answer_data'] = answers_data

            return result

        except Exception as e:
            return {
                'protocol': 'DNS',
                'error': str(e)
            }

    def _parse_answers(self, response: bytes) -> list:
        """Parse DNS answer section"""
        answers = []
        try:
            idx = 12

            # Skip question section
            questions = struct.unpack('!H', response[4:6])[0]
            for _ in range(questions):
                # Skip name
                while idx < len(response) and response[idx] != 0:
                    if (response[idx] & 0xC0) == 0xC0:  # Compression pointer
                        idx += 2
                        break
                    else:
                        idx += response[idx] + 1
                if idx < len(response) and response[idx] == 0:
                    idx += 1
                idx += 4  # Skip type and class

            # Parse answers
            answer_count = struct.unpack('!H', response[6:8])[0]
            for _ in range(min(answer_count, 10)):  # Limit to prevent issues
                if idx >= len(response) - 10:
                    break

                # Skip name (same format as question)
                while idx < len(response) and response[idx] != 0:
                    if (response[idx] & 0xC0) == 0xC0:  # Compression pointer
                        idx += 2
                        break
                    else:
                        idx += response[idx] + 1
                if idx < len(response) and response[idx] == 0:
                    idx += 1

                if idx + 10 > len(response):
                    break

                # Parse answer fields
                rr_type = struct.unpack('!H', response[idx:idx+2])[0]
                rr_class = struct.unpack('!H', response[idx+2:idx+4])[0]
                ttl = struct.unpack('!I', response[idx+4:idx+8])[0]
                data_len = struct.unpack('!H', response[idx+8:idx+10])[0]
                idx += 10

                if idx + data_len > len(response):
                    break

                rdata = response[idx:idx+data_len]
                idx += data_len

                # Parse different record types
                answer = {'type': rr_type, 'class': rr_class, 'ttl': ttl}

                if rr_type == 1:  # A record
                    if len(rdata) == 4:
                        answer['ip'] = '.'.join(str(b) for b in rdata)
                elif rr_type == 28:  # AAAA record
                    if len(rdata) == 16:
                        answer['ipv6'] = ':'.join(f'{rdata[i]:02x}{rdata[i+1]:02x}' for i in range(0, 16, 2))
                elif rr_type == 16:  # TXT record
                    txt_data = []
                    i = 0
                    while i < len(rdata):
                        if i >= len(rdata):
                            break
                        txt_len = rdata[i]
                        if i + txt_len + 1 > len(rdata):
                            break
                        txt_data.append(rdata[i+1:i+1+txt_len].decode('utf-8', errors='ignore'))
                        i += txt_len + 1
                    answer['txt'] = txt_data
                else:
                    answer['raw_data'] = rdata.hex()

                answers.append(answer)

        except Exception:
            pass

        return answers