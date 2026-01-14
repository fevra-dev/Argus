"""
SNMP community string testing plugin.

Tests for default SNMP community strings on network
devices - a critical finding for network security.
"""

import socket
import struct
from typing import List
from .base import BasePlugin
from ..models import CredentialResult, Service


class SNMPPlugin(BasePlugin):
    """
    SNMP community string testing plugin.
    
    SNMP v1/v2c uses community strings as passwords.
    Default community strings are extremely common
    on network devices, printers, and IoT devices.
    
    This is a CRITICAL finding - SNMP access often
    allows full device configuration access.
    
    Reference: MITRE ATT&CK T1078.001, T1040
    """
    
    name = "snmp"
    service = Service.SNMP
    default_ports = [161]
    
    # Common default community strings
    # Source: Multiple credential databases + vendor defaults
    DEFAULT_COMMUNITIES = [
        "public",          # Read-only default
        "private",         # Read-write default
        "community",
        "snmp",
        "admin",
        "default",
        "password",
        "cisco",
        "switch",
        "router",
        "secret",
        "monitor",
        "manager",
        "internal",
        "write",
        "system",
        "all private",
        "all public",
        "snmpd",
        "network",
        "cable-docsis",    # Cable modems
        "ILMI",            # ATM
        "Cisco router",
        "freekevin",       # Infamous
        "volition",
        "NoGaH$@!",        # Some HP devices
        "OrigEquipMfr",    # Dell
        "xyzzy",           # NetApp
        "c",               # Minimal
        "cc",
        "test",
        "guest",
    ]
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,  # Unused, community goes here
        password: str,  # Or here
        timeout: float = 3.0
    ) -> CredentialResult:
        """
        Test SNMP community string.
        
        Sends an SNMP GET request for sysDescr.0
        to test if community string is valid.
        """
        # Use password as community, or username if password empty
        community = password or username or "public"
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Build SNMP GET request for sysDescr.0 (1.3.6.1.2.1.1.1.0)
            packet = self._build_snmp_get(community)
            
            sock.sendto(packet, (host, port))
            
            try:
                response, _ = sock.recvfrom(4096)
                sock.close()
                
                # Parse response
                sys_descr = self._parse_snmp_response(response)
                
                if sys_descr:
                    # Determine access level
                    access = "read-only" if community == "public" else "read-write"
                    
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="snmp",
                        username="",
                        password=community,
                        banner=sys_descr[:200],
                        access_level=access,
                        details=f"SNMP community '{community}' valid - device info exposed"
                    )
                    
            except socket.timeout:
                pass
            
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="snmp",
                username="",
                password=community,
                error="No response or invalid community"
            )
            
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="snmp",
                error=str(e)
            )
    
    def _build_snmp_get(self, community: str) -> bytes:
        """
        Build SNMP v2c GET request for sysDescr.0
        
        OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        """
        # OID for sysDescr.0: 1.3.6.1.2.1.1.1.0
        oid = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        
        # Build PDU
        # VarBind: OID + NULL value
        varbind = bytes([0x30, len(oid) + 4])  # SEQUENCE
        varbind += bytes([0x06, len(oid)]) + oid  # OID
        varbind += bytes([0x05, 0x00])  # NULL
        
        # VarBindList
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        
        # GetRequest PDU
        request_id = bytes([0x02, 0x01, 0x01])  # INTEGER 1
        error_status = bytes([0x02, 0x01, 0x00])  # INTEGER 0
        error_index = bytes([0x02, 0x01, 0x00])  # INTEGER 0
        
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = bytes([0xa0, len(pdu_content)]) + pdu_content  # GetRequest
        
        # Community string
        community_bytes = community.encode('utf-8')
        community_tlv = bytes([0x04, len(community_bytes)]) + community_bytes
        
        # Version (v2c = 1)
        version = bytes([0x02, 0x01, 0x01])
        
        # SNMP message
        message_content = version + community_tlv + pdu
        message = bytes([0x30, len(message_content)]) + message_content
        
        return message
    
    def _parse_snmp_response(self, response: bytes) -> str:
        """Parse SNMP response to extract sysDescr value."""
        try:
            # Look for OCTET STRING with system description
            # Simple parsing - look for 0x04 (OCTET STRING) tags
            i = 0
            while i < len(response) - 2:
                if response[i] == 0x04:  # OCTET STRING
                    length = response[i + 1]
                    if length > 0 and i + 2 + length <= len(response):
                        value = response[i + 2:i + 2 + length]
                        try:
                            decoded = value.decode('utf-8', errors='ignore')
                            if len(decoded) > 5:  # Likely sysDescr
                                return decoded
                        except:
                            pass
                i += 1
        except:
            pass
        return ""
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default community strings to test."""
        return [("", community) for community in self.DEFAULT_COMMUNITIES]
