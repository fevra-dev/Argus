"""FTP credential testing plugin."""

from ftplib import FTP, error_perm
from typing import Tuple, Optional
import logging

from .base import BasePlugin
from ..models import Credential

logger = logging.getLogger(__name__)


class FTPPlugin(BasePlugin):
    """FTP credential testing."""
    
    SERVICE_NAME = "ftp"
    DEFAULT_PORT = 21
    
    def test_credential(
        self,
        host: str,
        port: int,
        credential: Credential
    ) -> Tuple[bool, Optional[str], str]:
        """Test FTP credential."""
        
        try:
            logger.debug(
                f"FTP: Testing {credential.username}:{credential.password} "
                f"on {host}:{port}"
            )
            
            ftp = FTP(timeout=self.timeout)
            ftp.connect(host, port)
            banner = ftp.getwelcome()
            
            # Handle empty username/password
            username = credential.username or ""
            password = credential.password or ""
            
            ftp.login(
                user=username,
                passwd=password
            )
            
            logger.info(
                f"FTP SUCCESS: {credential.username}@{host}:{port}"
            )
            
            ftp.quit()
            return (True, None, banner)
            
        except error_perm as e:
            return (False, "Authentication failed", "")
            
        except TimeoutError:
            return (False, "Timeout", "")
            
        except Exception as e:
            return (False, str(e), "")

