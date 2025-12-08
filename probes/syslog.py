import time
from typing import Dict, Any, Optional
from .base import UDPProbe

class SyslogProbe(UDPProbe):
    """Syslog service probe"""

    def create_probe(self) -> bytes:
        """Create a test syslog message"""
        # Syslog message format: <priority>timestamp hostname message
        priority = 16 * 8 + 6  # facility=16 (local0), severity=6 (info)
        timestamp = time.strftime('%b %d %H:%M:%S', time.localtime())
        hostname = 'scanner'
        message = 'UDP Discovery Tool Test Message'

        syslog_msg = f'<{priority}>{timestamp} {hostname} {message}'
        return syslog_msg.encode('utf-8')

    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse syslog response (usually no response expected)"""
        # Most syslog servers don't respond to messages
        # If we get a response, it might be an error or acknowledgment
        if len(response) > 0:
            return {
                'protocol': 'Syslog',
                'response_received': True,
                'response_size': len(response)
            }
        return None