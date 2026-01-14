"""Telnet credential testing plugin."""

import telnetlib
import re
from typing import Tuple, Optional
import logging

from .base import BasePlugin
from ..models import Credential

logger = logging.getLogger(__name__)


class TelnetPlugin(BasePlugin):
    """Telnet credential testing."""
    
    SERVICE_NAME = "telnet"
    DEFAULT_PORT = 23
    
    def test_credential(
        self,
        host: str,
        port: int,
        credential: Credential
    ) -> Tuple[bool, Optional[str], str]:
        """Test Telnet credential."""
        
        try:
            logger.debug(
                f"Telnet: Testing {credential.username}:{credential.password} "
                f"on {host}:{port}"
            )
            
            tn = telnetlib.Telnet(host, port, timeout=self.timeout)
            
            # Wait for login prompt (try common patterns)
            try:
                response = tn.read_until(b"login: ", timeout=self.timeout)
            except EOFError:
                try:
                    response = tn.read_until(b"Login: ", timeout=self.timeout)
                except EOFError:
                    response = tn.read_until(b"Username: ", timeout=self.timeout)
            
            banner = response.decode('utf-8', errors='ignore')
            
            # Send username
            tn.write(credential.username.encode('ascii') + b"\n")
            
            # Wait for password prompt (try common patterns)
            try:
                tn.read_until(b"Password: ", timeout=self.timeout)
            except EOFError:
                try:
                    tn.read_until(b"password: ", timeout=self.timeout)
                except EOFError:
                    # Some systems don't have a password prompt
                    pass
            
            # Send password
            tn.write(credential.password.encode('ascii') + b"\n")
            
            # Read response (wait for shell prompt or error)
            try:
                response = tn.read_until(b"$", timeout=self.timeout)
            except EOFError:
                try:
                    response = tn.read_until(b"#", timeout=self.timeout)
                except EOFError:
                    response = tn.read_until(b">", timeout=self.timeout)
            
            response_text = response.decode('utf-8', errors='ignore')
            
            tn.close()
            
            # Check for success indicators
            fail_patterns = [
                "incorrect", "invalid", "failed", "denied",
                "Login incorrect", "Authentication failed"
            ]
            
            for pattern in fail_patterns:
                if pattern.lower() in response_text.lower():
                    return (False, "Authentication failed", banner)
            
            # Check for success indicators
            success_patterns = ["$", "#", ">", "Welcome", "Last login"]
            
            for pattern in success_patterns:
                if pattern in response_text:
                    logger.info(
                        f"Telnet SUCCESS: {credential.username}@{host}:{port}"
                    )
                    return (True, None, banner)
            
            return (False, "Unknown response", banner)
            
        except EOFError:
            return (False, "Connection closed", "")
            
        except TimeoutError:
            return (False, "Timeout", "")
            
        except Exception as e:
            return (False, str(e), "")

