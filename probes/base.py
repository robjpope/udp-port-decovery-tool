from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class UDPProbe(ABC):
    """Base class for UDP service probes"""

    def __init__(self):
        self.name = self.__class__.__name__.replace('Probe', '')

    @abstractmethod
    def create_probe(self) -> bytes:
        """Create the UDP probe packet to send"""
        pass

    @abstractmethod
    def parse_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse the response and extract service information"""
        pass

    def validate_response(self, response: bytes) -> bool:
        """Validate if the response is from the expected service"""
        return len(response) > 0