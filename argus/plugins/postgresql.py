"""
PostgreSQL default credential testing plugin.

Tests for PostgreSQL authentication with common default
credentials and misconfigurations.
"""

import socket
import struct
import hashlib
from typing import List, Optional
from .base import BasePlugin
from ..models import CredentialResult, Service


class PostgreSQLPlugin(BasePlugin):
    """
    PostgreSQL authentication testing plugin.
    
    PostgreSQL servers commonly have:
    - postgres user with weak/default password
    - Trust authentication misconfiguration
    - Default database accounts
    
    This plugin implements PostgreSQL protocol authentication
    without requiring psycopg2 dependency.
    
    Reference: MITRE ATT&CK T1078.001 (Default Accounts)
    """
    
    name = "postgresql"
    service = Service.UNKNOWN
    default_ports = [5432]
    
    # Common PostgreSQL default credentials
    # Sources: Default installs, Docker images, credential databases
    DEFAULT_CREDENTIALS = [
        ("postgres", ""),            # Empty password (common in dev)
        ("postgres", "postgres"),    # Most common default
        ("postgres", "password"),
        ("postgres", "admin"),
        ("postgres", "root"),
        ("postgres", "123456"),
        ("postgres", "pg"),
        ("postgres", "postgrespass"),
        ("admin", "admin"),
        ("root", "root"),
        ("user", "password"),
        ("pgsql", "pgsql"),
        ("postgres", "secret"),
        ("postgres", "P@ssw0rd"),
        ("postgres", "changeme"),
    ]
    
    # PostgreSQL protocol constants
    SSL_REQUEST = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float = 5.0,
        database: str = "postgres"
    ) -> CredentialResult:
        """
        Test PostgreSQL authentication.
        
        Args:
            host: Target PostgreSQL server
            port: PostgreSQL port (default 5432)
            username: Username to test
            password: Password to test
            timeout: Connection timeout
            database: Database to connect to
            
        Returns:
            CredentialResult with auth status
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send startup message
            startup = self._build_startup_message(username, database)
            sock.send(startup)
            
            # Read response
            response = sock.recv(4096)
            
            if not response:
                sock.close()
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="postgresql",
                    error="No response from server"
                )
            
            # Parse response type
            msg_type = chr(response[0])
            
            # 'R' = Authentication request
            if msg_type == 'R':
                auth_result = self._handle_auth(sock, response, username, password)
                sock.close()
                
                if auth_result:
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="postgresql",
                        username=username,
                        password=password or "(empty)",
                        banner=f"PostgreSQL",
                        access_level="database",
                        details=f"PostgreSQL auth successful (db: {database})"
                    )
                else:
                    return CredentialResult(
                        success=False,
                        host=host,
                        port=port,
                        service="postgresql",
                        username=username,
                        password=password,
                        error="Authentication failed"
                    )
            
            # 'E' = Error
            elif msg_type == 'E':
                error_msg = self._parse_error(response)
                sock.close()
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="postgresql",
                    username=username,
                    password=password,
                    error=error_msg
                )
            
            sock.close()
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="postgresql",
                error=f"Unexpected response type: {msg_type}"
            )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="postgresql",
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="postgresql",
                error="Connection refused"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="postgresql",
                error=str(e)
            )
    
    def _build_startup_message(self, username: str, database: str) -> bytes:
        """
        Build PostgreSQL startup message.
        
        Format:
        - Length (4 bytes, includes self)
        - Protocol version (4 bytes): 3.0 = 0x00030000
        - Parameters (null-terminated key-value pairs)
        - Final null byte
        """
        # Protocol version 3.0
        protocol = struct.pack('>I', 0x00030000)
        
        # Build parameters
        params = b''
        params += b'user\x00' + username.encode('utf-8') + b'\x00'
        params += b'database\x00' + database.encode('utf-8') + b'\x00'
        params += b'client_encoding\x00UTF8\x00'
        params += b'\x00'  # Terminator
        
        # Calculate total length (4 bytes for length + content)
        content = protocol + params
        length = struct.pack('>I', len(content) + 4)
        
        return length + content
    
    def _handle_auth(
        self,
        sock: socket.socket,
        response: bytes,
        username: str,
        password: str
    ) -> bool:
        """
        Handle PostgreSQL authentication handshake.
        
        Returns True if authentication successful.
        """
        try:
            # Parse auth request
            # R message: type(1) + length(4) + auth_type(4) + [salt(4)]
            if len(response) < 9:
                return False
            
            msg_len = struct.unpack('>I', response[1:5])[0]
            auth_type = struct.unpack('>I', response[5:9])[0]
            
            # Auth type 0 = Trust (no password needed!)
            if auth_type == 0:
                # Check for ReadyForQuery message
                return self._wait_for_ready(sock)
            
            # Auth type 3 = Cleartext password
            elif auth_type == 3:
                pwd_msg = self._build_password_message(password)
                sock.send(pwd_msg)
                return self._check_auth_response(sock)
            
            # Auth type 5 = MD5 password
            elif auth_type == 5:
                if len(response) < 13:
                    return False
                salt = response[9:13]
                pwd_msg = self._build_md5_password(username, password, salt)
                sock.send(pwd_msg)
                return self._check_auth_response(sock)
            
            # Auth type 10 = SCRAM-SHA-256 (more complex, skip for now)
            elif auth_type == 10:
                return False  # SCRAM not implemented
            
            return False
            
        except Exception:
            return False
    
    def _build_password_message(self, password: str) -> bytes:
        """Build cleartext password message."""
        pwd = password.encode('utf-8') + b'\x00'
        length = struct.pack('>I', len(pwd) + 4)
        return b'p' + length + pwd
    
    def _build_md5_password(self, username: str, password: str, salt: bytes) -> bytes:
        """
        Build MD5 password message.
        
        PostgreSQL MD5: 'md5' + md5(md5(password + username) + salt)
        """
        # First hash: md5(password + username)
        inner = hashlib.md5((password + username).encode('utf-8')).hexdigest()
        
        # Second hash: md5(inner_hash + salt)
        outer = hashlib.md5(inner.encode('utf-8') + salt).hexdigest()
        
        # Format: 'md5' + hex_digest
        pwd = ('md5' + outer).encode('utf-8') + b'\x00'
        length = struct.pack('>I', len(pwd) + 4)
        
        return b'p' + length + pwd
    
    def _check_auth_response(self, sock: socket.socket) -> bool:
        """Check authentication response after password sent."""
        try:
            response = sock.recv(4096)
            if not response:
                return False
            
            msg_type = chr(response[0])
            
            # 'R' with auth_type 0 = AuthenticationOk
            if msg_type == 'R' and len(response) >= 9:
                auth_type = struct.unpack('>I', response[5:9])[0]
                if auth_type == 0:
                    return True
            
            # 'E' = Error (auth failed)
            elif msg_type == 'E':
                return False
            
            return False
            
        except Exception:
            return False
    
    def _wait_for_ready(self, sock: socket.socket) -> bool:
        """Wait for ReadyForQuery message (trust auth)."""
        try:
            response = sock.recv(4096)
            # Look for 'Z' (ReadyForQuery) anywhere in response
            return b'Z' in response
        except Exception:
            return False
    
    def _parse_error(self, response: bytes) -> str:
        """Parse PostgreSQL error message."""
        try:
            # Error format: E + length + (code + string\0)*
            pos = 5  # Skip type and length
            errors = []
            
            while pos < len(response) - 1:
                code = chr(response[pos])
                pos += 1
                
                # Find null terminator
                end = response.index(0, pos)
                value = response[pos:end].decode('utf-8', errors='ignore')
                pos = end + 1
                
                if code == 'M':  # Message
                    errors.append(value)
                elif code == '\x00':
                    break
            
            return errors[0] if errors else "Unknown error"
            
        except Exception:
            return "Failed to parse error"
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
