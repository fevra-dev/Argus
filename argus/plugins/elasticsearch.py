"""
Elasticsearch default credential and no-auth testing plugin.

Tests for Elasticsearch clusters with:
- No authentication enabled (extremely common in dev)
- Default/weak credentials on X-Pack Security
- Anonymous access to cluster data

Reference: MITRE ATT&CK T1190 (Exploit Public-Facing Application)
"""

import socket
import json
from typing import List, Optional
from .base import BasePlugin
from ..models import CredentialResult, Service


class ElasticsearchPlugin(BasePlugin):
    """
    Elasticsearch authentication testing plugin.
    
    Elasticsearch clusters commonly have:
    - No authentication (default before v8.0)
    - X-Pack Security with default credentials
    - Misconfigured network bindings (exposed to internet)
    
    This is one of the most commonly exploited misconfigurations
    in cloud and container environments.
    
    Risk: Data exfiltration, ransomware, cryptojacking
    
    Reference: MITRE ATT&CK T1190, T1530
    """
    
    name = "elasticsearch"
    service = Service.UNKNOWN
    default_ports = [9200, 9300]  # HTTP API, Transport
    
    # Common Elasticsearch credentials
    # elastic/changeme was the default for X-Pack
    DEFAULT_CREDENTIALS = [
        ("", ""),                         # No auth (check first!)
        ("elastic", "changeme"),          # X-Pack default
        ("elastic", "elastic"),
        ("elastic", "password"),
        ("elastic", ""),
        ("admin", "admin"),
        ("admin", "password"),
        ("kibana", "kibana"),             # Kibana service account
        ("kibana_system", "kibana"),
        ("logstash_system", "logstash"),
        ("beats_system", "beats"),
        ("apm_system", "apm"),
        ("remote_monitoring_user", "monitoring"),
        ("elastic", "P@ssw0rd"),
        ("elastic", "123456"),
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
        Test Elasticsearch authentication.
        
        Args:
            host: Target Elasticsearch server
            port: HTTP API port (typically 9200)
            username: Username (or empty for no-auth check)
            password: Password to test
            timeout: Connection timeout
            
        Returns:
            CredentialResult with auth status
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Build HTTP request
            if username or password:
                # Basic authentication
                import base64
                auth_str = f"{username}:{password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                auth_header = f"Authorization: Basic {auth_b64}\r\n"
            else:
                auth_header = ""
            
            # Request cluster info endpoint
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Argus/0.3.0 Security Scanner\r\n"
                f"Accept: application/json\r\n"
                f"{auth_header}"
                f"Connection: close\r\n"
                f"\r\n"
            )
            
            sock.send(request.encode())
            
            # Receive response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:  # Limit response size
                    break
            
            sock.close()
            
            # Parse response
            response_str = response.decode('utf-8', errors='ignore')
            
            # Check HTTP status
            if "HTTP/1.1 200" in response_str or "HTTP/1.0 200" in response_str:
                # Success! Parse cluster info
                cluster_info = self._parse_cluster_info(response_str)
                
                if not username and not password:
                    # No auth required - critical finding!
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="elasticsearch",
                        username="(anonymous)",
                        password="(no auth required)",
                        banner=cluster_info.get('banner', 'Elasticsearch'),
                        access_level="database",
                        details=f"NO AUTHENTICATION - Cluster: {cluster_info.get('cluster_name', 'unknown')}, Version: {cluster_info.get('version', 'unknown')}"
                    )
                else:
                    return CredentialResult(
                        success=True,
                        host=host,
                        port=port,
                        service="elasticsearch",
                        username=username,
                        password=password,
                        banner=cluster_info.get('banner', 'Elasticsearch'),
                        access_level="database",
                        details=f"Auth successful - Cluster: {cluster_info.get('cluster_name', 'unknown')}"
                    )
            
            elif "HTTP/1.1 401" in response_str:
                # Authentication required
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="elasticsearch",
                    username=username,
                    password=password,
                    error="Authentication failed (401)"
                )
            
            elif "HTTP/1.1 403" in response_str:
                # Forbidden - auth might be correct but no permission
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="elasticsearch",
                    username=username,
                    password=password,
                    error="Forbidden (403) - credentials may be valid but restricted"
                )
            
            else:
                return CredentialResult(
                    success=False,
                    host=host,
                    port=port,
                    service="elasticsearch",
                    error=f"Unexpected response"
                )
            
        except socket.timeout:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="elasticsearch",
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="elasticsearch",
                error="Connection refused"
            )
        except Exception as e:
            return CredentialResult(
                success=False,
                host=host,
                port=port,
                service="elasticsearch",
                error=str(e)
            )
    
    def _parse_cluster_info(self, response: str) -> dict:
        """Parse Elasticsearch cluster info from HTTP response."""
        info = {
            'cluster_name': 'unknown',
            'version': 'unknown',
            'banner': 'Elasticsearch'
        }
        
        try:
            # Find JSON body (after blank line)
            parts = response.split('\r\n\r\n', 1)
            if len(parts) < 2:
                return info
            
            body = parts[1].strip()
            
            # Parse JSON
            data = json.loads(body)
            
            info['cluster_name'] = data.get('cluster_name', 'unknown')
            
            if 'version' in data:
                version = data['version']
                if isinstance(version, dict):
                    info['version'] = version.get('number', 'unknown')
                    build_flavor = version.get('build_flavor', '')
                    info['banner'] = f"Elasticsearch {info['version']} ({build_flavor})"
                else:
                    info['version'] = str(version)
                    info['banner'] = f"Elasticsearch {info['version']}"
            
            # Check for tagline
            if 'tagline' in data:
                info['tagline'] = data['tagline']
            
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
        
        return info
    
    def check_indices(
        self,
        host: str,
        port: int,
        username: str = "",
        password: str = "",
        timeout: float = 5.0
    ) -> Optional[List[str]]:
        """
        Check accessible indices (bonus information gathering).
        
        This helps assess the severity of the exposure.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Build request for indices
            if username or password:
                import base64
                auth_str = f"{username}:{password}"
                auth_b64 = base64.b64encode(auth_str.encode()).decode()
                auth_header = f"Authorization: Basic {auth_b64}\r\n"
            else:
                auth_header = ""
            
            request = (
                f"GET /_cat/indices?format=json HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"User-Agent: Argus/0.3.0\r\n"
                f"Accept: application/json\r\n"
                f"{auth_header}"
                f"Connection: close\r\n"
                f"\r\n"
            )
            
            sock.send(request.encode())
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            
            sock.close()
            
            response_str = response.decode('utf-8', errors='ignore')
            
            if "200" in response_str:
                parts = response_str.split('\r\n\r\n', 1)
                if len(parts) >= 2:
                    indices = json.loads(parts[1])
                    return [idx.get('index', 'unknown') for idx in indices]
            
            return None
            
        except Exception:
            return None
    
    def get_default_credentials(self) -> List[tuple]:
        """Return default credentials to test."""
        return self.DEFAULT_CREDENTIALS
