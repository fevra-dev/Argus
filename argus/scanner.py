"""
Argus - Main scanning orchestrator.

Core scanning engine that coordinates network discovery,
credential testing, and vulnerability analysis.
"""

from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging

from .models import (
    HostInfo, Finding, ScanResult, Credential,
    CredentialResult, Service, Severity
)
from .network.discovery import parse_targets, scan_host, grab_banner
from .plugins import get_plugin, PLUGINS
from .credentials.database import CredentialDatabase

logger = logging.getLogger(__name__)


class ArgusScanner:
    """
    Argus - Intelligence-driven default credential scanner.
    
    Named after the all-seeing giant from Greek mythology,
    Argus provides comprehensive visibility into network
    security vulnerabilities.
    """
    
    def __init__(
        self,
        threads: int = 10,
        timeout: int = 5,
        creds_file: Optional[str] = None,
        stop_on_success: bool = True,
        grab_banners: bool = True
    ):
        """
        Initialize Argus scanner.
        
        Args:
            threads: Concurrent threads for scanning
            timeout: Connection timeout in seconds
            creds_file: Custom credentials file path
            stop_on_success: Stop testing host after first success
            grab_banners: Whether to grab service banners
        """
        self.threads = threads
        self.timeout = timeout
        self.stop_on_success = stop_on_success
        self.grab_banners = grab_banners
        
        self.cred_db = CredentialDatabase(creds_file)
        
        logger.info(
            f"Argus scanner initialized: threads={threads}, timeout={timeout}s"
        )
    
    def _test_credentials(
        self,
        host: str,
        port: int,
        service: Service,
        credentials: List[Credential]
    ) -> List[Finding]:
        """Test credentials against a single service."""
        
        findings = []
        service_name = service.value
        
        plugin_class = get_plugin(service_name)
        if not plugin_class:
            logger.debug(f"No plugin for service: {service_name}")
            return findings
        
        plugin = plugin_class(timeout=self.timeout)
        
        for cred in credentials:
            success, error, banner = plugin.test_credential(
                host, port, cred
            )
            
            if success:
                # Determine severity based on access level
                access_level = plugin.get_access_level(cred.username)
                severity = (
                    Severity.CRITICAL if access_level == "admin"
                    else Severity.HIGH if access_level == "user"
                    else Severity.MEDIUM
                )
                
                findings.append(Finding(
                    host=host,
                    port=port,
                    service=service,
                    username=cred.username,
                    password=cred.password,
                    severity=severity,
                    banner=banner,
                    vendor=cred.vendor,
                    access_level=access_level
                ))
                
                if self.stop_on_success:
                    logger.debug(f"Stopping after first success for {host}:{port}")
                    break
        
        return findings
    
    def scan_host(
        self,
        host_info: HostInfo
    ) -> List[Finding]:
        """Scan a single host for default credentials."""
        
        findings = []
        
        for open_port in host_info.open_ports:
            # Grab banner if enabled
            if self.grab_banners and not open_port.banner:
                open_port.banner = grab_banner(
                    host_info.ip,
                    open_port.port,
                    self.timeout
                )
            
            # Get credentials for this service
            credentials = self.cred_db.get_for_service(
                open_port.service.value,
                vendor=open_port.vendor
            )
            
            logger.debug(
                f"Testing {len(credentials)} credentials on "
                f"{host_info.ip}:{open_port.port} ({open_port.service.value})"
            )
            
            # Test credentials
            port_findings = self._test_credentials(
                host_info.ip,
                open_port.port,
                open_port.service,
                credentials
            )
            
            findings.extend(port_findings)
            
            if findings and self.stop_on_success:
                break
        
        return findings
    
    def scan(
        self,
        targets: List[str],
        ports: List[int] = None
    ) -> ScanResult:
        """
        Scan multiple targets for default credentials.
        
        Args:
            targets: List of target specifications (IPs, CIDR, ranges)
            ports: Ports to scan (None = default ports)
            
        Returns:
            ScanResult with all findings and metadata
        """
        start_time = datetime.now()
        logger.info(f"Argus starting scan of {len(targets)} target(s)")
        
        # Parse targets to individual IPs
        ips = parse_targets(targets)
        logger.info(f"Expanded to {len(ips)} IP addresses")
        
        all_findings = []
        all_hosts = []
        
        # Scan hosts for open ports and test credentials
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {
                executor.submit(scan_host, ip, ports, self.timeout, 5): ip
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    host_info = future.result()
                    all_hosts.append(host_info)
                    
                    if host_info.open_ports:
                        # Test credentials on open ports
                        findings = self.scan_host(host_info)
                        all_findings.extend(findings)
                        
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
        
        end_time = datetime.now()
        duration = int((end_time - start_time).total_seconds() * 1000)
        
        # Build result summary
        hosts_with_findings = len(set(f.host for f in all_findings))
        
        result = ScanResult(
            hosts_scanned=len(ips),
            hosts_with_findings=hosts_with_findings,
            total_findings=len(all_findings),
            critical_count=sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in all_findings if f.severity == Severity.HIGH),
            scan_start=start_time.isoformat(),
            scan_end=end_time.isoformat(),
            scan_duration_ms=duration,
            findings=all_findings,
            host_info=all_hosts
        )
        
        logger.info(
            f"Argus scan complete: {len(ips)} hosts, "
            f"{len(all_findings)} findings ({result.critical_count} critical)"
        )
        
        return result


# Backward compatibility alias for migration
CredScanner = ArgusScanner
