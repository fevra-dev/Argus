"""
Memcached no-authentication and info disclosure testing plugin.

Memcached is an in-memory caching system that historically
has NO AUTHENTICATION by default. This is a critical security issue.

Common exposures:
- Data exfiltration (cached sensitive data)
- DDoS amplification attacks
- Cache poisoning

Reference: MITRE ATT&CK T1190 (Exploit Public-Facing Application)
"""

import socket
from typing import List, Optional, Dict
from .base import BasePlugin
from ..models import CredentialResult, Service


class MemcachedPlugin(BasePlugin):
    """
    Memcached authentication/access testing plugin.
    
    Memcached servers:
    - Have NO authentication by default
    - Often exposed on public IPs by mistake
    - Can be used for DDoS amplification
    - May contain sensitive cached data
    
    This plugin:
    1. Detects unauthenticated access
    2. Retrieves server statistics
    3. Identifies potential data exposure
    
    Risk: Data exfiltration, DDoS amplification, cache poisoning
    
    Reference: CVE-2018-1000115 (Memcached amplification)
    """
    
    name = "memcached"
    service = Service.UNKNOWN
    default_ports = [11211]
    
    # Memcached doesn't have traditional credentials
    # We check for unauthenticated access
    DEFAULT_CREDENTIALS = [
        ("", ""),  # No auth - the main check
    ]
    
    def test_credential(
        self,
        host: str,
        port: int,
        username: str,  # Ignored - Memcached has no auth
        password: str,  # Ignored - Memcached has no auth
        timeout: float = 5.0
    ) -> CredentialResult:
        """
        Test Memcached access (no authentication).
        
        Memcached uses a simple text protocol.
        We send 'stats' command to check access.
        
        Args:
            host: Target Memcached server
            port: Memcached port (typically 11211)
            username: Ignored (no auth)
            password: Ignored (no auth)
            timeout: Connection timeout
            
        Returns:
            CredentialResult with access status
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send stats command (text protocol)
            sock.send(b"stats\r\n")
            
            # Receive response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Memcached ends stats with "END\r\n"
                if b"END\r\n" in response:
                    break
                if len(response) > 65536:
                    break
            
            sock.close()
            
            response_str = response.decode('utf-8', errors='ignore')
            
            # Check if we got stats (unauthenticated access!)
            if "STAT " in response_str and "END" in response_str:
                # Parse stats for useful info
                stats = self._parse_stats(response_str)
                
                # Calculate severity based on exposure
                items_count = stats.get('curr_items', 0)
                bytes_stored = stats.get('bytes', 0)
                
                details = f"NO AUTH - {items_count} items, {self._format_bytes(bytes_stored)} stored"
                
                if stats.get('version'):
                    banner = f"Memcached {stats['version']}"
                else:
                    banner = "Memcached"
                
                return CredentialResult(
                    success=True,
                    host=host,
                    port=port,
                    service="memcached",
                    username="(anonymous)",
                    password="(no auth required)",
                    banner=banner,
                    access_level="cache_data",
                    details=details
                )
            
            elif "ERROR" in response_str:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="memcached",
                    error="Memcached returned error - possibly SASL auth required"
                )
            
            else:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="memcached",
                    error="Unexpected response - may not be Memcached"
                )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="memcached",
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="memcached",
                error="Connection refused"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="memcached",
                error=str(e)
            )
    
    def _parse_stats(self, response: str) -> Dict:
        """
        Parse Memcached stats response.
        
        Format: STAT <name> <value>\r\n
        """
        stats = {}
        
        for line in response.split('\r\n'):
            if line.startswith('STAT '):
                parts = line.split(' ', 2)
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2]
                    
                    # Convert numeric values
                    try:
                        if '.' in value:
                            stats[key] = float(value)
                        else:
                            stats[key] = int(value)
                    except ValueError:
                        stats[key] = value
        
        return stats
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable string."""
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_val / (1024 * 1024 * 1024):.1f} GB"
    
    def get_keys(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
        limit: int = 100
    ) -> Optional[List[str]]:
        """
        Attempt to enumerate cached keys (info gathering).
        
        Note: This uses 'stats items' and 'stats cachedump' which
        may not work on all Memcached versions.
        
        Returns list of keys if successful.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Get slab statistics
            sock.send(b"stats items\r\n")
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"END\r\n" in response:
                    break
            
            sock.close()
            
            # Parse slabs and try to get keys
            # This is limited in newer Memcached versions
            keys = []
            response_str = response.decode('utf-8', errors='ignore')
            
            # Extract slab IDs
            import re
            slab_ids = set()
            for match in re.finditer(r'STAT items:(\d+):', response_str):
                slab_ids.add(int(match.group(1)))
            
            # For each slab, try to dump keys
            for slab_id in list(slab_ids)[:5]:  # Limit slabs
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((host, port))
                    
                    cmd = f"stats cachedump {slab_id} {limit}\r\n"
                    sock.send(cmd.encode())
                    
                    dump = b""
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        dump += chunk
                        if b"END\r\n" in dump:
                            break
                    
                    sock.close()
                    
                    dump_str = dump.decode('utf-8', errors='ignore')
                    for match in re.finditer(r'ITEM (\S+) ', dump_str):
                        keys.append(match.group(1))
                        
                except Exception:
                    continue
            
            return keys if keys else None
            
        except Exception:
            return None
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
