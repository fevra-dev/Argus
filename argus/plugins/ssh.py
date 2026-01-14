"""SSH credential testing plugin."""

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    SSHException,
    NoValidConnectionsError
)
from typing import Tuple, Optional
import logging

from .base import BasePlugin
from ..models import Credential

logger = logging.getLogger(__name__)


class SSHPlugin(BasePlugin):
    """SSH credential testing."""
    
    SERVICE_NAME = "ssh"
    DEFAULT_PORT = 22
    
    def test_credential(
        self,
        host: str,
        port: int,
        credential: Credential
    ) -> Tuple[bool, Optional[str], str]:
        """Test SSH credential."""
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            logger.debug(
                f"SSH: Testing {credential.username}:{credential.password} "
                f"on {host}:{port}"
            )
            
            client.connect(
                hostname=host,
                port=port,
                username=credential.username,
                password=credential.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=self.timeout
            )
            
            # Get banner
            transport = client.get_transport()
            banner = transport.remote_version if transport else ""
            
            logger.info(
                f"SSH SUCCESS: {credential.username}@{host}:{port}"
            )
            
            client.close()
            return (True, None, banner)
            
        except AuthenticationException:
            return (False, "Authentication failed", "")
            
        except NoValidConnectionsError:
            return (False, "Connection refused", "")
            
        except SSHException as e:
            return (False, f"SSH error: {e}", "")
            
        except TimeoutError:
            return (False, "Timeout", "")
            
        except Exception as e:
            return (False, str(e), "")
            
        finally:
            client.close()

