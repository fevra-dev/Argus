"""Base plugin class."""
from abc import ABC, abstractmethod
from typing import Tuple, Optional
from ..models import Credential

class BasePlugin(ABC):
    """Base class for credential testing plugins."""
    
    SERVICE_NAME: str = "unknown"
    DEFAULT_PORT: int = 0
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    @abstractmethod
    def test_credential(
        self,
        host: str,
        port: int,
        credential: Credential
    ) -> Tuple[bool, Optional[str], str]:
        """
        Test a credential against the service.
        
        Args:
            host: Target host
            port: Target port
            credential: Credential to test
            
        Returns:
            Tuple of (success, error_message, banner/response)
        """
        pass
    
    def get_access_level(self, username: str) -> str:
        """Determine access level from username."""
        admin_users = ['root', 'admin', 'administrator', 'sa']
        if username.lower() in admin_users:
            return "admin"
        elif username.lower() in ['guest']:
            return "guest"
        return "user"

