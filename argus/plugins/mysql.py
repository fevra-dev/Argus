"""
MySQL default credential testing plugin.

Tests for MySQL authentication with common default
credentials and misconfigurations.
"""

import socket
import struct
import hashlib
from typing import List
from .base import BasePlugin
from ..models import CredentialResult, Service


class MySQLPlugin(BasePlugin):
    """
    MySQL authentication testing plugin.
    
    MySQL servers often have:
    - Root with no password
    - Default test accounts
    - Weak passwords
    
    This plugin implements MySQL native authentication
    without requiring mysql-connector dependency.
    """
    
    name = "mysql"
    service = Service.UNKNOWN
    default_ports = [3306]
    
    DEFAULT_CREDENTIALS = [
        ("root", ""),           # Most common!
        ("root", "root"),
        ("root", "password"),
        ("root", "mysql"),
        ("root", "admin"),
        ("root", "123456"),
        ("root", "toor"),
        ("mysql", "mysql"),
        ("admin", "admin"),
        ("test", "test"),
        ("guest", "guest"),
        ("dbadmin", "dbadmin"),
        ("user", "user"),
        ("root", "P@ssw0rd"),
        ("root", "changeme"),
    ]
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float = 5.0
    ) -> CredentialResult:
        """Test MySQL authentication."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Read server greeting
            greeting = sock.recv(4096)
            if not greeting or len(greeting) < 20:
                sock.close()
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="mysql",
                    error="Invalid server greeting"
                )
            
            # Parse greeting
            server_info = self._parse_greeting(greeting)
            
            if not server_info:
                sock.close()
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="mysql",
                    error="Failed to parse server greeting"
                )
            
            # Build auth response
            auth_packet = self._build_auth_packet(
                username,
                password,
                server_info['salt'],
                server_info['auth_plugin']
            )
            
            sock.send(auth_packet)
            
            # Read response
            response = sock.recv(4096)
            sock.close()
            
            if response and len(response) > 4:
                # Check for OK packet (0x00) or Error (0xff)
                packet_type = response[4] if len(response) > 4 else 0xff
                
                if packet_type == 0x00:
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="mysql",
                        username=username,
                        password=password or "(empty)",
                        banner=f"MySQL {server_info.get('version', '')}",
                        access_level="database",
                        details="MySQL authentication successful"
                    )
                elif packet_type == 0xfe:
                    # Auth switch request - partial success
                    return CredentialResult(
                        success=False,
                        host=host,
                        port=port,
                        service="mysql",
                        username=username,
                        password=password,
                        error="Auth method switch required"
                    )
            
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="mysql",
                username=username,
                password=password,
                error="Authentication failed"
            )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="mysql",
                error="Connection timeout"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="mysql",
                error=str(e)
            )
    
    def _parse_greeting(self, data: bytes) -> dict:
        """Parse MySQL server greeting packet."""
        try:
            # Skip packet header (4 bytes)
            pos = 4
            
            # Protocol version (1 byte)
            protocol = data[pos]
            pos += 1
            
            # Server version (null-terminated string)
            version_end = data.index(0, pos)
            version = data[pos:version_end].decode('utf-8', errors='ignore')
            pos = version_end + 1
            
            # Connection ID (4 bytes)
            pos += 4
            
            # Auth plugin data part 1 (8 bytes)
            salt1 = data[pos:pos + 8]
            pos += 9  # +1 for filler
            
            # Server capabilities (2 bytes)
            pos += 2
            
            # Character set (1 byte)
            pos += 1
            
            # Status flags (2 bytes)
            pos += 2
            
            # Extended capabilities (2 bytes)
            pos += 2
            
            # Auth plugin data length (1 byte)
            auth_len = data[pos] if pos < len(data) else 0
            pos += 1
            
            # Reserved (10 bytes)
            pos += 10
            
            # Auth plugin data part 2
            salt2 = b''
            if auth_len > 8:
                salt2_len = max(13, auth_len - 8)
                salt2 = data[pos:pos + salt2_len - 1]  # -1 for null terminator
                pos += salt2_len
            
            # Auth plugin name
            auth_plugin = "mysql_native_password"
            if pos < len(data):
                plugin_end = data.find(0, pos)
                if plugin_end > pos:
                    auth_plugin = data[pos:plugin_end].decode('utf-8', errors='ignore')
            
            return {
                'version': version,
                'salt': salt1 + salt2,
                'auth_plugin': auth_plugin
            }
        except:
            return None
    
    def _build_auth_packet(
        self,
        username: str,
        password: str,
        salt: bytes,
        auth_plugin: str
    ) -> bytes:
        """Build MySQL authentication packet."""
        # Client capabilities
        client_caps = 0x000fa285
        
        # Max packet size
        max_packet = 0x01000000
        
        # Character set (utf8)
        charset = 33
        
        # Build packet content
        content = struct.pack('<I', client_caps)
        content += struct.pack('<I', max_packet)
        content += struct.pack('<B', charset)
        content += b'\x00' * 23  # Reserved
        content += username.encode('utf-8') + b'\x00'
        
        # Password hash
        if password:
            auth_response = self._mysql_native_password(password, salt)
            content += struct.pack('<B', len(auth_response)) + auth_response
        else:
            content += b'\x00'
        
        content += auth_plugin.encode('utf-8') + b'\x00'
        
        # Build packet with header
        packet_len = len(content)
        packet = struct.pack('<I', packet_len)[:3]  # 3-byte length
        packet += b'\x01'  # Sequence number
        packet += content
        
        return packet
    
    def _mysql_native_password(self, password: str, salt: bytes) -> bytes:
        """MySQL native password authentication hash."""
        # SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
        password_hash = hashlib.sha1(password.encode('utf-8')).digest()
        double_hash = hashlib.sha1(password_hash).digest()
        salted = hashlib.sha1(salt[:20] + double_hash).digest()
        
        return bytes(a ^ b for a, b in zip(password_hash, salted))
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
