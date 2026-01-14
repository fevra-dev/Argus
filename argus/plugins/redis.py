"""
Redis default credential testing plugin.

Tests for common Redis authentication misconfigurations
including no-auth, default passwords, and weak passwords.
"""

import socket
from typing import Optional, List
from .base import BasePlugin
from ..models import CredentialResult, Service


class RedisPlugin(BasePlugin):
    """
    Redis authentication testing plugin.
    
    Redis commonly runs without authentication or with
    weak passwords. This plugin tests for:
    - No authentication required
    - Default/common passwords
    - AUTH command injection
    
    Reference: MITRE ATT&CK T1078.001 (Default Accounts)
    """
    
    name = "redis"
    service = Service.UNKNOWN  # Redis not in base Service enum
    default_ports = [6379]
    
    # Common Redis passwords from credential databases
    DEFAULT_PASSWORDS = [
        "",          # No password (most common!)
        "redis",
        "password",
        "admin",
        "root",
        "foobared",  # Redis default in some configs
        "123456",
        "redis123",
        "redispassword",
    ]
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,  # Redis doesn't use usernames pre-6.0
        password: str,
        timeout: float = 5.0
    ) -> CredentialResult:
        """
        Test Redis authentication.
        
        Args:
            host: Target Redis server
            port: Redis port (default 6379)
            username: Ignored for Redis < 6.0
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            CredentialResult with auth status
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            if password:
                # Send AUTH command
                auth_cmd = f"AUTH {password}\r\n"
                sock.send(auth_cmd.encode())
            else:
                # Test if auth is required
                sock.send(b"PING\r\n")
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse response
            if "+PONG" in response or "+OK" in response:
                return CredentialResult(
                    success=True,
                    host=host,
                    port=port,
                    service="redis",
                    username="",
                    password=password or "(no auth)",
                    banner=self._get_info(host, port, password, timeout),
                    access_level="full",
                    details="Redis server accessible - full database access"
                )
            elif "-NOAUTH" in response:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="redis",
                    username="",
                    password=password,
                    error="Authentication required"
                )
            else:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="redis",
                    username="",
                    password=password,
                    error=response.strip()
                )
                
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="redis",
                error="Connection timeout"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="redis",
                error=str(e)
            )
    
    def _get_info(
        self,
        host: str,
        port: int,
        password: Optional[str],
        timeout: float
    ) -> str:
        """Get Redis server info for banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            if password:
                sock.send(f"AUTH {password}\r\n".encode())
                sock.recv(1024)
            
            sock.send(b"INFO server\r\n")
            info = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            
            # Extract version
            for line in info.split('\n'):
                if line.startswith('redis_version:'):
                    return f"Redis {line.split(':')[1].strip()}"
            
            return "Redis Server"
        except:
            return "Redis Server"
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return [("", pwd) for pwd in self.DEFAULT_PASSWORDS]
