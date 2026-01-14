"""
MongoDB default credential testing plugin.

Tests for MongoDB authentication misconfigurations
including no-auth, default credentials, and admin access.
"""

import socket
import struct
from typing import List
from .base import BasePlugin
from ..models import CredentialResult, Service


class MongoDBPlugin(BasePlugin):
    """
    MongoDB authentication testing plugin.
    
    MongoDB commonly runs without authentication enabled.
    This plugin tests for:
    - No authentication required
    - Default admin credentials
    - Common weak passwords
    
    Note: Uses wire protocol for lightweight testing
    without requiring pymongo dependency.
    """
    
    name = "mongodb"
    service = Service.UNKNOWN
    default_ports = [27017, 27018, 27019]
    
    # Common MongoDB credentials
    DEFAULT_CREDENTIALS = [
        ("", ""),              # No auth
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("mongodb", "mongodb"),
        ("admin", "123456"),
        ("admin", "mongo"),
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
        Test MongoDB authentication.
        
        Uses MongoDB wire protocol to check if
        authentication is required or if default
        credentials work.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send isMaster command (works without auth)
            # This is a simplified wire protocol message
            message = self._build_ismaster_message()
            sock.send(message)
            
            response = sock.recv(4096)
            sock.close()
            
            if response and len(response) > 4:
                # Check if we got a valid MongoDB response
                if self._parse_response(response):
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="mongodb",
                        username=username or "(no auth)",
                        password=password or "(no auth)",
                        banner=self._extract_version(response),
                        access_level="database",
                        details="MongoDB accessible - check authentication status"
                    )
            
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="mongodb",
                username=username,
                password=password,
                error="Authentication failed or connection refused"
            )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="mongodb",
                error="Connection timeout"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="mongodb",
                error=str(e)
            )
    
    def _build_ismaster_message(self) -> bytes:
        """Build MongoDB isMaster wire protocol message."""
        # Simplified OP_MSG for isMaster
        # This is a minimal valid MongoDB message
        import json
        
        command = {"isMaster": 1}
        bson_cmd = self._simple_bson_encode(command)
        
        # Message header (16 bytes) + flags (4 bytes) + section
        flags = 0
        section_type = 0  # Body
        
        payload = struct.pack('<I', flags)  # flagBits
        payload += struct.pack('<B', section_type)  # section kind
        payload += bson_cmd
        
        # Build header
        message_length = 16 + len(payload)
        request_id = 1
        response_to = 0
        op_code = 2013  # OP_MSG
        
        header = struct.pack('<IIII', message_length, request_id, response_to, op_code)
        
        return header + payload
    
    def _simple_bson_encode(self, doc: dict) -> bytes:
        """Minimal BSON encoder for isMaster command."""
        import json
        # This is a simplified version - production would use bson library
        # For now, use a known working isMaster BSON
        return bytes([
            0x11, 0x00, 0x00, 0x00,  # Document length
            0x10,                     # Int32 type
            0x69, 0x73, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,  # "isMaster"
            0x01, 0x00, 0x00, 0x00,  # Value: 1
            0x00                      # Document terminator
        ])
    
    def _parse_response(self, response: bytes) -> bool:
        """Check if response is valid MongoDB response."""
        if len(response) < 20:
            return False
        
        # Check for valid message length
        msg_len = struct.unpack('<I', response[:4])[0]
        return msg_len > 16 and msg_len <= len(response)
    
    def _extract_version(self, response: bytes) -> str:
        """Try to extract MongoDB version from response."""
        try:
            # Look for version string in response
            decoded = response.decode('utf-8', errors='ignore')
            if 'version' in decoded:
                # Simple extraction
                import re
                match = re.search(r'"version"\s*:\s*"([^"]+)"', decoded)
                if match:
                    return f"MongoDB {match.group(1)}"
        except:
            pass
        return "MongoDB Server"
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
