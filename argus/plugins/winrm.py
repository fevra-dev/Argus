"""
WinRM (Windows Remote Management) default credential testing plugin.

Tests for WinRM authentication with common default credentials.
WinRM is the Windows implementation of WS-Management protocol.

Ports:
- 5985: HTTP (unencrypted)
- 5986: HTTPS (encrypted)

Reference: MITRE ATT&CK T1021.006 (Remote Services: Windows Remote Management)
"""

import socket
import base64
from typing import List, Optional
from .base import BasePlugin
from ..models import CredentialResult, Service


class WinRMPlugin(BasePlugin):
    """
    WinRM authentication testing plugin.
    
    WinRM servers commonly have:
    - Default administrator credentials
    - Service accounts with weak passwords
    - Basic auth enabled (cleartext credentials)
    
    This plugin tests:
    1. HTTP Basic authentication
    2. NTLM authentication (negotiate)
    3. Service availability detection
    
    Risk: Remote command execution, lateral movement
    
    Reference: MITRE ATT&CK T1021.006
    """
    
    name = "winrm"
    service = Service.UNKNOWN
    default_ports = [5985, 5986]
    
    # Common WinRM credentials (Windows accounts)
    DEFAULT_CREDENTIALS = [
        ("Administrator", ""),
        ("Administrator", "password"),
        ("Administrator", "Password1"),
        ("Administrator", "P@ssw0rd"),
        ("Administrator", "admin"),
        ("Administrator", "Admin123"),
        ("Administrator", "Welcome1"),
        ("Admin", "admin"),
        ("admin", "admin"),
        ("admin", "password"),
        ("svc_account", "password"),
        ("service", "service"),
        ("backup", "backup"),
        ("ansible", "ansible"),          # Automation accounts
        ("terraform", "terraform"),
        ("winrm", "winrm"),
        ("vagrant", "vagrant"),          # Vagrant boxes
        ("Administrator", "vagrant"),
    ]
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float = 5.0
    ) -> CredentialResult:
        """
        Test WinRM authentication.
        
        Attempts:
        1. Basic authentication (if enabled)
        2. NTLM negotiate authentication
        
        Args:
            host: Target WinRM server
            port: WinRM port (5985/5986)
            username: Username (can include domain: DOMAIN\\user)
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            CredentialResult with auth status
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # First, check if WinRM is available
            availability = self._check_winrm_availability(sock, host, port)
            
            if not availability:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="winrm",
                    error="Not a WinRM service"
                )
            
            sock.close()
            
            # Try Basic authentication
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            result = self._try_basic_auth(sock, host, port, username, password)
            sock.close()
            
            if result.get('success'):
                return CredentialResult(
                    success=True,
                    host=host,
                    port=port,
                    service="winrm",
                    username=username,
                    password=password,
                    banner=result.get('banner', 'WinRM'),
                    access_level="remote_command",
                    details="WinRM Basic auth successful - remote command execution possible"
                )
            
            # If basic auth failed with 401, try to detect NTLM
            if result.get('ntlm_available'):
                # NTLM requires more complex handshake
                # Report as potential target
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="winrm",
                    username=username,
                    password=password,
                    banner=result.get('banner', 'WinRM'),
                    error="NTLM auth required - use pywinrm or evil-winrm for testing"
                )
            
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="winrm",
                username=username,
                password=password,
                error=result.get('error', 'Authentication failed')
            )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="winrm",
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="winrm",
                error="Connection refused"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="winrm",
                error=str(e)
            )
    
    def _check_winrm_availability(
        self,
        sock: socket.socket,
        host: str,
        port: int
    ) -> bool:
        """
        Check if WinRM service is available.
        
        Sends an unauthenticated request to the WinRM endpoint.
        """
        try:
            request = (
                f"POST /wsman HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Argus/0.3.0\r\n"
                f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            
            sock.send(request.encode())
            response = sock.recv(4096)
            
            response_str = response.decode('utf-8', errors='ignore')
            
            # WinRM should respond with 401 or 403
            if "401" in response_str or "403" in response_str:
                return True
            
            # Or it might have a WinRM-specific header
            if "wsman" in response_str.lower() or "microsoft" in response_str.lower():
                return True
            
            return False
            
        except Exception:
            return False
    
    def _try_basic_auth(
        self,
        sock: socket.socket,
        host: str,
        port: int,
        username: str,
        password: str
    ) -> dict:
        """
        Try WinRM Basic authentication.
        
        Basic auth sends credentials in base64.
        Only works if Basic auth is enabled on the server.
        """
        result = {
            'success': False,
            'ntlm_available': False,
            'banner': 'WinRM',
            'error': None
        }
        
        try:
            # Encode credentials
            auth_str = f"{username}:{password}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
            
            # Minimal WS-Management Identify request
            soap_body = '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
    <s:Header/>
    <s:Body>
        <wsmid:Identify/>
    </s:Body>
</s:Envelope>'''
            
            request = (
                f"POST /wsman HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Argus/0.3.0\r\n"
                f"Authorization: Basic {auth_b64}\r\n"
                f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
                f"Content-Length: {len(soap_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{soap_body}"
            )
            
            sock.send(request.encode())
            
            # Receive response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            
            response_str = response.decode('utf-8', errors='ignore')
            
            # Check response
            if "HTTP/1.1 200" in response_str:
                result['success'] = True
                
                # Try to extract server info
                if "ProductVendor" in response_str:
                    result['banner'] = 'Microsoft WinRM'
                if "ProductVersion" in response_str:
                    import re
                    version_match = re.search(r'ProductVersion[^>]*>([^<]+)<', response_str)
                    if version_match:
                        result['banner'] = f"Microsoft WinRM {version_match.group(1)}"
                
            elif "HTTP/1.1 401" in response_str:
                result['error'] = "Authentication failed"
                
                # Check for NTLM/Negotiate
                if "WWW-Authenticate: Negotiate" in response_str:
                    result['ntlm_available'] = True
                if "WWW-Authenticate: NTLM" in response_str:
                    result['ntlm_available'] = True
                    
            elif "HTTP/1.1 403" in response_str:
                result['error'] = "Forbidden - Basic auth may be disabled"
                
            else:
                result['error'] = "Unexpected response"
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
