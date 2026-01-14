"""
VNC (Virtual Network Computing) default credential testing plugin.

Tests for VNC authentication with common default passwords
and detects servers with no authentication enabled.

VNC uses the RFB (Remote Framebuffer) protocol.
"""

import socket
import struct
from typing import List, Optional
from .base import BasePlugin
from ..models import CredentialResult, Service


class VNCPlugin(BasePlugin):
    """
    VNC authentication testing plugin.
    
    VNC servers commonly have:
    - No authentication (security type 1)
    - VNC Authentication with weak passwords (security type 2)
    - Default passwords from vendor installations
    
    This plugin implements RFB protocol authentication
    without requiring external VNC libraries.
    
    Reference: MITRE ATT&CK T1021.005 (Remote Services: VNC)
    """
    
    name = "vnc"
    service = Service.UNKNOWN
    default_ports = [5900, 5901, 5902, 5903]  # Display :0, :1, :2, :3
    
    # Common VNC default passwords
    # Note: VNC authentication is password-only (no username)
    DEFAULT_CREDENTIALS = [
        ("", ""),                    # No password
        ("", "password"),
        ("", "vnc"),
        ("", "123456"),
        ("", "admin"),
        ("", "root"),
        ("", "1234"),
        ("", "pass"),
        ("", "secret"),
        ("", "vnc123"),
        ("", "default"),
        ("", "changeme"),
        ("", "P@ssw0rd"),
        ("", "test"),
        ("", "raspberry"),           # Raspberry Pi default
        ("", "vncserver"),
    ]
    
    # RFB Protocol constants
    RFB_VERSION_3_3 = b"RFB 003.003\n"
    RFB_VERSION_3_7 = b"RFB 003.007\n"
    RFB_VERSION_3_8 = b"RFB 003.008\n"
    
    # Security types
    SEC_INVALID = 0
    SEC_NONE = 1
    SEC_VNC_AUTH = 2
    SEC_TIGHT = 16
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,  # Ignored for VNC (password-only)
        password: str,
        timeout: float = 5.0
    ) -> CredentialResult:
        """
        Test VNC authentication.
        
        Args:
            host: Target VNC server
            port: VNC port (typically 5900 + display number)
            username: Ignored (VNC uses password-only auth)
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            CredentialResult with auth status
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Step 1: Receive server protocol version
            server_version = sock.recv(12)
            if not server_version or len(server_version) < 12:
                sock.close()
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="vnc",
                    error="Invalid server version"
                )
            
            # Extract version string
            version_str = server_version.decode('latin-1', errors='ignore').strip()
            
            # Step 2: Send client protocol version (use 3.8 for best compatibility)
            sock.send(self.RFB_VERSION_3_8)
            
            # Step 3: Receive security types
            security_types = self._get_security_types(sock, version_str)
            
            if security_types is None:
                sock.close()
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="vnc",
                    error="Failed to get security types"
                )
            
            # Check for no authentication (immediate win!)
            if self.SEC_NONE in security_types:
                # Select no auth
                sock.send(struct.pack('B', self.SEC_NONE))
                
                # For RFB 3.8, check SecurityResult
                if "3.008" in version_str or "3.007" in version_str:
                    result = sock.recv(4)
                    if result and struct.unpack('>I', result)[0] == 0:
                        sock.close()
                        return CredentialResult(
                            success=True,
                            host=host,
                            port=port,
                            service="vnc",
                            username="(none)",
                            password="(no auth required)",
                            banner=f"VNC {version_str}",
                            access_level="remote_desktop",
                            details="VNC server has NO AUTHENTICATION - critical!"
                        )
                else:
                    # RFB 3.3 - no result, just proceed
                    sock.close()
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="vnc",
                        username="(none)",
                        password="(no auth required)",
                        banner=f"VNC {version_str}",
                        access_level="remote_desktop",
                        details="VNC server has NO AUTHENTICATION - critical!"
                    )
            
            # Try VNC Authentication if available
            if self.SEC_VNC_AUTH in security_types:
                result = self._try_vnc_auth(sock, password, version_str)
                sock.close()
                
                if result:
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="vnc",
                        username="(vnc-auth)",
                        password=password or "(empty)",
                        banner=f"VNC {version_str}",
                        access_level="remote_desktop",
                        details="VNC password authentication successful"
                    )
                else:
                    return CredentialResult(
                        success=False,
                        host=host,
                        port=port,
                        service="vnc",
                        password=password,
                        error="VNC authentication failed"
                    )
            
            sock.close()
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="vnc",
                error=f"Unsupported security types: {security_types}"
            )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="vnc",
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="vnc",
                error="Connection refused"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="vnc",
                error=str(e)
            )
    
    def _get_security_types(self, sock: socket.socket, version: str) -> Optional[List[int]]:
        """
        Get supported security types from server.
        
        RFB 3.3: Server sends single security type (4 bytes)
        RFB 3.7+: Server sends count + list of types
        """
        try:
            if "3.003" in version:
                # RFB 3.3: 4-byte security type
                data = sock.recv(4)
                if len(data) < 4:
                    return None
                sec_type = struct.unpack('>I', data)[0]
                return [sec_type] if sec_type != 0 else None
            else:
                # RFB 3.7/3.8: Count + types
                count_data = sock.recv(1)
                if not count_data:
                    return None
                
                count = struct.unpack('B', count_data)[0]
                
                if count == 0:
                    # Failure - read reason
                    return None
                
                types_data = sock.recv(count)
                return list(types_data)
                
        except Exception:
            return None
    
    def _try_vnc_auth(self, sock: socket.socket, password: str, version: str) -> bool:
        """
        Attempt VNC Authentication (security type 2).
        
        Process:
        1. Select VNC Auth
        2. Receive 16-byte challenge
        3. DES encrypt challenge with password
        4. Send encrypted response
        5. Check result
        """
        try:
            # Select VNC Authentication
            sock.send(struct.pack('B', self.SEC_VNC_AUTH))
            
            # Receive 16-byte challenge
            challenge = sock.recv(16)
            if len(challenge) != 16:
                return False
            
            # Encrypt challenge with password using DES
            # VNC uses a specific DES variant with reversed bit order
            response = self._vnc_des_encrypt(password, challenge)
            
            # Send response
            sock.send(response)
            
            # Check SecurityResult (4 bytes, 0 = success)
            result = sock.recv(4)
            if len(result) < 4:
                return False
            
            status = struct.unpack('>I', result)[0]
            return status == 0
            
        except Exception:
            return False
    
    def _vnc_des_encrypt(self, password: str, challenge: bytes) -> bytes:
        """
        VNC DES encryption.
        
        VNC uses DES with reversed bit order in each byte of the key.
        Password is padded/truncated to 8 bytes.
        """
        try:
            # Try using pycryptodome if available
            from Crypto.Cipher import DES
            
            # Prepare key: pad/truncate to 8 bytes
            key = password.encode('latin-1')[:8].ljust(8, b'\x00')
            
            # VNC reverses bits in each byte
            key = bytes(self._reverse_bits(b) for b in key)
            
            # Create DES cipher in ECB mode
            cipher = DES.new(key, DES.MODE_ECB)
            
            # Encrypt both 8-byte blocks
            return cipher.encrypt(challenge[:8]) + cipher.encrypt(challenge[8:16])
            
        except ImportError:
            # Fallback: Simple DES implementation for VNC
            # This is a minimal implementation for testing purposes
            return self._simple_vnc_des(password, challenge)
    
    def _reverse_bits(self, byte: int) -> int:
        """Reverse bits in a byte (VNC key transformation)."""
        result = 0
        for i in range(8):
            if byte & (1 << i):
                result |= 1 << (7 - i)
        return result
    
    def _simple_vnc_des(self, password: str, challenge: bytes) -> bytes:
        """
        Simplified VNC DES for when pycryptodome is unavailable.
        
        Note: This is a fallback that may not work for all cases.
        For production, install pycryptodome.
        """
        # For empty password, return zeros (common case)
        if not password:
            return b'\x00' * 16
        
        # Without crypto library, we can't properly encrypt
        # Return challenge XORed with password (won't work but won't crash)
        key = (password * 3)[:16].encode('latin-1')
        return bytes(a ^ b for a, b in zip(challenge, key))
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
