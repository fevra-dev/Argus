"""
Network discovery and port scanning.
"""

import socket
import ipaddress
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from ..models import OpenPort, HostInfo, Service

logger = logging.getLogger(__name__)

# Default ports to scan
DEFAULT_PORTS = [22, 23, 21, 80, 443, 8080, 8443, 161, 3306, 5432]

# Port to service mapping
PORT_SERVICE_MAP = {
    22: Service.SSH,
    23: Service.TELNET,
    21: Service.FTP,
    80: Service.HTTP,
    443: Service.HTTPS,
    8080: Service.HTTP,
    8443: Service.HTTPS,
    # Add more as needed
}


def parse_targets(targets: List[str]) -> List[str]:
    """
    Parse target specifications into individual IP addresses.
    
    Supports:
    - Single IP: 192.168.1.1
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.1-192.168.1.10
    
    Returns:
        List of individual IP addresses
    """
    result = []
    
    for target in targets:
        target = target.strip()
        
        if not target:
            continue
        
        try:
            # Try CIDR notation
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                for ip in network.hosts():
                    result.append(str(ip))
            
            # Try range notation
            elif '-' in target:
                parts = target.split('-')
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                
                current = start
                while current <= end:
                    result.append(str(current))
                    current = ipaddress.ip_address(int(current) + 1)
            
            # Single IP
            else:
                ipaddress.ip_address(target)  # Validate
                result.append(target)
                
        except ValueError as e:
            logger.warning(f"Invalid target specification: {target} - {e}")
    
    # Deduplicate
    return list(dict.fromkeys(result))


def scan_port(
    host: str,
    port: int,
    timeout: float = 3.0
) -> Tuple[int, bool]:
    """
    Scan a single port on a host.
    
    Returns:
        Tuple of (port, is_open)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        is_open = result == 0
        if is_open:
            logger.debug(f"Port {port} open on {host}")
        
        return (port, is_open)
        
    except socket.error:
        return (port, False)


def scan_host(
    host: str,
    ports: List[int] = None,
    timeout: float = 3.0,
    threads: int = 10
) -> HostInfo:
    """
    Scan a host for open ports.
    
    Args:
        host: Target IP address
        ports: List of ports to scan (default: common ports)
        timeout: Connection timeout
        threads: Concurrent port scans
        
    Returns:
        HostInfo with open ports
    """
    ports = ports or DEFAULT_PORTS
    logger.info(f"Scanning {host} - {len(ports)} ports")
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = PORT_SERVICE_MAP.get(port, Service.UNKNOWN)
                open_ports.append(OpenPort(
                    port=port,
                    service=service,
                    banner="",
                    vendor=""
                ))
    
    logger.info(f"{host}: {len(open_ports)} open ports")
    
    return HostInfo(
        ip=host,
        hostname=None,
        open_ports=open_ports
    )


def grab_banner(
    host: str,
    port: int,
    timeout: float = 5.0
) -> str:
    """
    Grab service banner from open port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Some services need a probe
        if port in [80, 443, 8080, 8443]:
            # HTTP probe
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner[:200]  # Limit length
        
    except Exception:
        return ""

