"""HTTP Basic Auth credential testing plugin."""

import urllib.request
import urllib.error
import base64
from typing import Tuple, Optional
import ssl
import logging

from .base import BasePlugin
from ..models import Credential

logger = logging.getLogger(__name__)


class HTTPPlugin(BasePlugin):
    """HTTP Basic Authentication testing."""
    
    SERVICE_NAME = "http"
    DEFAULT_PORT = 80
    
    # Common paths requiring authentication
    AUTH_PATHS = [
        "/",
        "/admin",
        "/admin/",
        "/administrator",
        "/manager",
        "/login",
        "/manager/html",  # Tomcat
        "/phpmyadmin",
    ]
    
    def test_credential(
        self,
        host: str,
        port: int,
        credential: Credential
    ) -> Tuple[bool, Optional[str], str]:
        """Test HTTP Basic Auth credential."""
        
        # Determine scheme
        scheme = "https" if port in [443, 8443] else "http"
        
        # Create auth header
        auth_string = f"{credential.username}:{credential.password}"
        auth_bytes = base64.b64encode(auth_string.encode('utf-8'))
        auth_header = f"Basic {auth_bytes.decode('utf-8')}"
        
        # Create SSL context that doesn't verify
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        for path in self.AUTH_PATHS:
            url = f"{scheme}://{host}:{port}{path}"
            
            try:
                request = urllib.request.Request(url)
                request.add_header("Authorization", auth_header)
                request.add_header("User-Agent", "Argus/1.0")
                
                response = urllib.request.urlopen(
                    request,
                    timeout=self.timeout,
                    context=ssl_context
                )
                
                status = response.getcode()
                
                if status == 200:
                    # Read some response
                    body = response.read(500).decode('utf-8', errors='ignore')
                    server = response.headers.get('Server', '')
                    
                    logger.info(
                        f"HTTP SUCCESS: {credential.username}@{host}:{port}{path}"
                    )
                    
                    return (True, None, f"Server: {server}")
                    
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    # Auth required but failed
                    continue
                elif e.code == 403:
                    # Forbidden - might still be valid auth
                    continue
                    
            except urllib.error.URLError:
                continue
                
            except Exception as e:
                continue
        
        return (False, "Authentication failed", "")

