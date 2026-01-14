"""
SIEM integration for Argus.

Supports Splunk, Elasticsearch/ELK, Syslog, and CEF formats
for enterprise security event logging.
"""

import socket
import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import requests
    HAS_HTTPX = False


@dataclass
class SIEMConfig:
    """
    SIEM integration configuration.
    
    Attributes:
        siem_type: Target SIEM (splunk, elk, syslog, cef)
        
        Splunk HEC:
            splunk_hec_url: HEC endpoint URL
            splunk_token: HEC authentication token
            splunk_index: Target index
            splunk_source: Event source
            splunk_sourcetype: Event sourcetype
        
        Elasticsearch:
            elk_url: Elasticsearch URL
            elk_index: Target index
            elk_api_key: API key for authentication
        
        Syslog:
            host: Syslog server hostname
            port: Syslog server port
            protocol: udp or tcp
    """
    siem_type: str = "splunk"  # splunk, elk, syslog, cef
    
    # Splunk HEC
    splunk_hec_url: Optional[str] = None
    splunk_token: Optional[str] = None
    splunk_index: str = "argus"
    splunk_source: str = "argus"
    splunk_sourcetype: str = "argus:finding"
    
    # Elasticsearch
    elk_url: Optional[str] = None
    elk_index: str = "argus-findings"
    elk_api_key: Optional[str] = None
    
    # Syslog
    host: Optional[str] = None
    port: int = 514
    protocol: str = "udp"


class SIEMIntegration:
    """
    SIEM integration for security event logging.
    
    Sends scan findings to enterprise SIEM platforms in
    their native formats for correlation and alerting.
    
    Usage:
        config = SIEMConfig(
            siem_type="splunk",
            splunk_hec_url="https://splunk:8088/services/collector",
            splunk_token="your-hec-token"
        )
        siem = SIEMIntegration(config)
        siem.send_findings(findings, scan_metadata)
    """
    
    def __init__(self, config: SIEMConfig):
        """
        Initialize SIEM integration.
        
        Args:
            config: SIEMConfig with target SIEM details
        """
        self.config = config
        
        if HAS_HTTPX:
            self.http_client = httpx.Client(timeout=30.0, verify=False)
        else:
            self.http_client = None
        
        logger.info(f"SIEM Integration initialized: {config.siem_type}")
    
    def send_findings(
        self,
        findings: List[Dict],
        scan_metadata: Dict = None
    ) -> bool:
        """
        Send findings to configured SIEM.
        
        Args:
            findings: List of finding dictionaries
            scan_metadata: Optional scan metadata (scan_id, timestamps, etc.)
            
        Returns:
            True if sent successfully
        """
        siem_type = self.config.siem_type.lower()
        
        if siem_type == "splunk":
            return self._send_to_splunk(findings, scan_metadata)
        elif siem_type == "elk":
            return self._send_to_elk(findings, scan_metadata)
        elif siem_type in ["syslog", "cef"]:
            return self._send_to_syslog(findings, scan_metadata)
        else:
            logger.error(f"Unsupported SIEM type: {siem_type}")
            return False
    
    def _send_to_splunk(
        self,
        findings: List[Dict],
        scan_metadata: Dict = None
    ) -> bool:
        """Send findings to Splunk HEC."""
        config = self.config
        
        if not config.splunk_hec_url or not config.splunk_token:
            logger.error("Splunk HEC not configured")
            return False
        
        events = []
        for finding in findings:
            event = self._create_splunk_event(finding, scan_metadata)
            events.append(event)
        
        # Send to Splunk HEC
        headers = {
            "Authorization": f"Splunk {config.splunk_token}",
            "Content-Type": "application/json"
        }
        
        try:
            # Send events in batch
            payload = "".join(json.dumps(e) for e in events)
            
            if HAS_HTTPX:
                response = self.http_client.post(
                    config.splunk_hec_url,
                    content=payload,
                    headers=headers
                )
            else:
                response = requests.post(
                    config.splunk_hec_url,
                    data=payload,
                    headers=headers,
                    verify=False,
                    timeout=30
                )
            
            if response.status_code == 200:
                logger.info(f"Sent {len(findings)} events to Splunk")
                return True
            else:
                logger.error(f"Splunk HEC error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to Splunk: {e}")
            return False
    
    def _create_splunk_event(
        self,
        finding: Dict,
        scan_metadata: Dict = None
    ) -> Dict:
        """Create Splunk HEC event payload."""
        config = self.config
        
        # Extract finding details
        finding_data = finding.get('finding', finding)
        intelligence = finding.get('intelligence', {})
        
        event = {
            "event_type": "default_credential_detected",
            "source": "argus",
            "mitre_attack": "T1078.001",
            "host": finding_data.get('host'),
            "port": finding_data.get('port'),
            "service": finding_data.get('service'),
            "username": finding_data.get('username'),
            "severity": finding_data.get('severity'),
            "access_level": finding_data.get('access_level'),
        }
        
        # Add intelligence data if available
        if intelligence:
            event["risk_score"] = intelligence.get('risk_score')
            event["risk_level"] = intelligence.get('risk_level')
            event["cve_count"] = len(intelligence.get('cves', []))
        
        # Add scan metadata
        if scan_metadata:
            event["scan_id"] = scan_metadata.get('scan_id')
            event["scan_time"] = scan_metadata.get('started_at')
        
        return {
            "event": event,
            "time": int(datetime.now().timestamp()),
            "host": finding_data.get('host'),
            "source": config.splunk_source,
            "sourcetype": config.splunk_sourcetype,
            "index": config.splunk_index
        }
    
    def _send_to_elk(
        self,
        findings: List[Dict],
        scan_metadata: Dict = None
    ) -> bool:
        """Send findings to Elasticsearch."""
        config = self.config
        
        if not config.elk_url:
            logger.error("Elasticsearch URL not configured")
            return False
        
        headers = {"Content-Type": "application/json"}
        if config.elk_api_key:
            headers["Authorization"] = f"ApiKey {config.elk_api_key}"
        
        # Build bulk index payload
        bulk_data = []
        for finding in findings:
            # Index action
            bulk_data.append(json.dumps({
                "index": {"_index": config.elk_index}
            }))
            
            # Document
            doc = self._create_elk_document(finding, scan_metadata)
            bulk_data.append(json.dumps(doc))
        
        payload = "\n".join(bulk_data) + "\n"
        
        try:
            url = f"{config.elk_url}/_bulk"
            
            if HAS_HTTPX:
                response = self.http_client.post(
                    url,
                    content=payload,
                    headers=headers
                )
            else:
                response = requests.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=30
                )
            
            if response.status_code in [200, 201]:
                logger.info(f"Sent {len(findings)} documents to Elasticsearch")
                return True
            else:
                logger.error(f"Elasticsearch error: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to Elasticsearch: {e}")
            return False
    
    def _create_elk_document(
        self,
        finding: Dict,
        scan_metadata: Dict = None
    ) -> Dict:
        """Create Elasticsearch document."""
        finding_data = finding.get('finding', finding)
        intelligence = finding.get('intelligence', {})
        
        doc = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.type": "default_credential_detected",
            "event.category": "authentication",
            "event.kind": "alert",
            "source.address": finding_data.get('host'),
            "source.port": finding_data.get('port'),
            "service.name": finding_data.get('service'),
            "user.name": finding_data.get('username'),
            "event.severity": finding_data.get('severity'),
            "argus.access_level": finding_data.get('access_level'),
            "threat.technique.id": "T1078.001",
            "threat.technique.name": "Default Accounts"
        }
        
        if intelligence:
            doc["argus.risk_score"] = intelligence.get('risk_score')
            doc["argus.risk_level"] = intelligence.get('risk_level')
        
        if scan_metadata:
            doc["argus.scan_id"] = scan_metadata.get('scan_id')
        
        return doc
    
    def _send_to_syslog(
        self,
        findings: List[Dict],
        scan_metadata: Dict = None
    ) -> bool:
        """Send findings via Syslog (CEF format)."""
        config = self.config
        
        if not config.host:
            logger.error("Syslog host not configured")
            return False
        
        try:
            # Create socket
            if config.protocol.lower() == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((config.host, config.port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            for finding in findings:
                message = self._create_cef_message(finding, scan_metadata)
                
                if config.protocol.lower() == "tcp":
                    sock.send((message + "\n").encode())
                else:
                    sock.sendto(message.encode(), (config.host, config.port))
            
            sock.close()
            logger.info(f"Sent {len(findings)} events via Syslog")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send to Syslog: {e}")
            return False
    
    def _create_cef_message(
        self,
        finding: Dict,
        scan_metadata: Dict = None
    ) -> str:
        """Create CEF (Common Event Format) message."""
        finding_data = finding.get('finding', finding)
        
        # CEF severity mapping (0-10)
        severity_map = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 5,
            "LOW": 3
        }
        severity = severity_map.get(finding_data.get('severity', 'MEDIUM'), 5)
        
        # Build CEF message
        cef = (
            f"CEF:0|Argus|SecurityScanner|2.0|"
            f"DefaultCredential|Default Credential Detected|{severity}|"
            f"dst={finding_data.get('host')} "
            f"dpt={finding_data.get('port')} "
            f"proto={finding_data.get('service')} "
            f"duser={finding_data.get('username')} "
            f"cs1={finding_data.get('access_level')} "
            f"cs1Label=AccessLevel "
            f"cs2=T1078.001 "
            f"cs2Label=MitreAttackID"
        )
        
        if scan_metadata:
            cef += f" cs3={scan_metadata.get('scan_id', '')} cs3Label=ScanID"
        
        return cef


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("SIEM Integration module loaded")
    print("Supported SIEM types: splunk, elk, syslog, cef")
