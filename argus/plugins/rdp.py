"""
RDP (Remote Desktop Protocol) default credential testing plugin.

Tests for RDP authentication with common default credentials
and detects servers with weak security configurations.

Note: Full NLA authentication requires complex NTLM/CredSSP handling.
This plugin uses the RDP protocol handshake to detect availability
and attempts connection-based credential testing.

Reference: MITRE ATT&CK T1021.001 (Remote Services: RDP)
"""

import socket
import struct
from typing import List, Optional
from .base import BasePlugin
from ..models import CredentialResult, Service


class RDPPlugin(BasePlugin):
    """
    RDP authentication testing plugin.
    
    RDP servers commonly have:
    - Weak administrator passwords
    - Default user accounts
    - NLA disabled (allowing pre-authentication attacks)
    
    This plugin detects:
    1. RDP service availability and version
    2. NLA (Network Level Authentication) status
    3. SSL/TLS configuration
    4. Attempts basic credential validation
    
    Risk: Remote code execution, lateral movement
    
    Reference: MITRE ATT&CK T1021.001
    """
    
    name = "rdp"
    service = Service.UNKNOWN
    default_ports = [3389]
    
    # Common RDP default credentials
    DEFAULT_CREDENTIALS = [
        ("Administrator", ""),           # Empty password
        ("Administrator", "password"),
        ("Administrator", "Password1"),
        ("Administrator", "admin"),
        ("Administrator", "123456"),
        ("Administrator", "P@ssw0rd"),
        ("Admin", "admin"),
        ("admin", "admin"),
        ("admin", "password"),
        ("guest", ""),                   # Guest account
        ("guest", "guest"),
        ("user", "user"),
        ("user", "password"),
        ("test", "test"),
        ("support", "support"),
        ("backup", "backup"),
        ("Administrator", "Welcome1"),   # Common in labs
        ("Administrator", "Passw0rd!"),
    ]
    
    # RDP Protocol constants
    TPKT_VERSION = 3
    X224_CONNECTION_REQUEST = 0xe0
    X224_CONNECTION_CONFIRM = 0xd0
    
    # RDP Negotiation constants
    TYPE_RDP_NEG_REQ = 0x01
    TYPE_RDP_NEG_RSP = 0x02
    TYPE_RDP_NEG_FAILURE = 0x03
    
    # Protocol flags
    PROTOCOL_RDP = 0x00000000
    PROTOCOL_SSL = 0x00000001
    PROTOCOL_HYBRID = 0x00000002  # CredSSP/NLA
    PROTOCOL_RDSTLS = 0x00000004
    PROTOCOL_HYBRID_EX = 0x00000008
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float = 5.0
    ) -> CredentialResult:
        """
        Test RDP authentication.
        
        Full RDP credential testing requires:
        - TLS handshake
        - CredSSP/NTLM authentication
        - Complex state machine
        
        This implementation:
        1. Detects RDP service and capabilities
        2. Identifies if NLA is required
        3. Reports security configuration issues
        
        For full credential testing, use tools like:
        - crowbar, hydra, or ncrack with RDP module
        
        Args:
            host: Target RDP server
            port: RDP port (typically 3389)
            username: Username to test
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            CredentialResult with detection status
        """
        try:
            # Step 1: RDP Protocol Detection and Capability Check
            rdp_info = self._detect_rdp(host, port, timeout)
            
            if not rdp_info:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="rdp",
                    error="Failed to connect or not an RDP service"
                )
            
            # Check for security misconfigurations
            if rdp_info.get('nla_required') is False:
                # NLA disabled - security issue!
                return CredentialResult(
                    success=True,
                    host=host,
                    port=port,
                    service="rdp",
                    username="(nla-disabled)",
                    password="(check manually)",
                    banner=rdp_info.get('banner', 'RDP'),
                    access_level="remote_desktop",
                    details="RDP with NLA DISABLED - vulnerable to pre-auth attacks. Test credentials manually."
                )
            
            # If NLA is enabled but we detected the service
            if rdp_info.get('ssl_supported'):
                # RDP is available, report for manual testing
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="rdp",
                    username=username,
                    password=password,
                    banner=rdp_info.get('banner', 'RDP'),
                    error="RDP detected with NLA. Use specialized tool for credential testing."
                )
            
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="rdp",
                banner=rdp_info.get('banner', 'RDP'),
                error="RDP service detected, credential testing requires NLA bypass"
            )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="rdp",
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="rdp",
                error="Connection refused"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="rdp",
                error=str(e)
            )
    
    def _detect_rdp(self, host: str, port: int, timeout: float) -> Optional[dict]:
        """
        Detect RDP service and security capabilities.
        
        Sends X.224 Connection Request with RDP negotiation
        to determine supported protocols.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Build X.224 Connection Request with RDP Negotiation Request
            # This requests all protocols to see what server supports
            neg_request = self._build_connection_request()
            sock.send(neg_request)
            
            # Receive response
            response = sock.recv(1024)
            sock.close()
            
            if not response or len(response) < 11:
                return None
            
            # Parse TPKT header
            if response[0] != self.TPKT_VERSION:
                return None
            
            # Parse X.224 Connection Confirm
            x224_len = response[4]
            x224_type = response[5] >> 4
            
            if x224_type != 0x0d:  # Connection Confirm
                return None
            
            result = {
                'service': 'rdp',
                'banner': 'Microsoft RDP',
                'nla_required': None,
                'ssl_supported': False,
                'rdp_standard': False
            }
            
            # Check for RDP Negotiation Response (after X.224 header)
            # X.224 header is variable length, typically ends at offset 11
            neg_offset = 4 + 1 + x224_len  # TPKT(4) + len(1) + X224 data
            
            if len(response) >= neg_offset + 8:
                neg_type = response[11]
                neg_flags = response[12]
                neg_length = struct.unpack('<H', response[13:15])[0]
                
                if neg_type == self.TYPE_RDP_NEG_RSP and neg_length >= 8:
                    selected_protocol = struct.unpack('<I', response[15:19])[0]
                    
                    if selected_protocol == self.PROTOCOL_RDP:
                        result['rdp_standard'] = True
                        result['nla_required'] = False
                        result['banner'] = 'Microsoft RDP (Standard RDP - No NLA)'
                    
                    elif selected_protocol == self.PROTOCOL_SSL:
                        result['ssl_supported'] = True
                        result['nla_required'] = False
                        result['banner'] = 'Microsoft RDP (TLS without NLA)'
                    
                    elif selected_protocol in (self.PROTOCOL_HYBRID, self.PROTOCOL_HYBRID_EX):
                        result['ssl_supported'] = True
                        result['nla_required'] = True
                        result['banner'] = 'Microsoft RDP (CredSSP/NLA Required)'
                
                elif neg_type == self.TYPE_RDP_NEG_FAILURE:
                    # Server rejected our request - likely requires NLA
                    result['nla_required'] = True
                    result['banner'] = 'Microsoft RDP (NLA Enforced)'
            
            return result
            
        except Exception:
            return None
    
    def _build_connection_request(self) -> bytes:
        """
        Build X.224 Connection Request with RDP Negotiation.
        
        Requests support for all protocols:
        - Standard RDP (0x00)
        - TLS (0x01)
        - CredSSP/NLA (0x02)
        """
        # Cookie (optional but helps with detection)
        cookie = b"Cookie: mstshash=Argus\r\n"
        
        # RDP Negotiation Request
        # Type: 0x01 (RDP_NEG_REQ)
        # Flags: 0x00
        # Length: 8
        # RequestedProtocols: PROTOCOL_SSL | PROTOCOL_HYBRID = 0x03
        rdp_neg = struct.pack('<BBHI',
            self.TYPE_RDP_NEG_REQ,  # Type
            0x00,                    # Flags
            8,                       # Length
            self.PROTOCOL_SSL | self.PROTOCOL_HYBRID  # Request TLS or NLA
        )
        
        # X.224 Connection Request (CR) PDU
        # Length of X.224 data (excluding length byte itself)
        x224_data = bytes([
            0xe0,  # CR + CDT
            0x00, 0x00,  # DST-REF
            0x00, 0x00,  # SRC-REF
            0x00  # Class 0
        ]) + cookie + rdp_neg
        
        x224_len = len(x224_data)
        x224_header = bytes([x224_len]) + x224_data
        
        # TPKT Header
        tpkt_len = 4 + len(x224_header)
        tpkt = struct.pack('>BBH',
            self.TPKT_VERSION,  # Version
            0x00,               # Reserved
            tpkt_len            # Length (big-endian)
        )
        
        return tpkt + x224_header
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
