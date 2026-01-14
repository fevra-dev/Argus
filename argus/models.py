# ============================================================
# FILE: argus/models.py
# ============================================================
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum


class Service(Enum):
    """Supported services."""
    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    TELNET = "telnet"
    SNMP = "snmp"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Finding severity."""
    CRITICAL = "CRITICAL"   # Admin/root access gained
    HIGH = "HIGH"           # User access gained
    MEDIUM = "MEDIUM"       # Limited access
    LOW = "LOW"             # Info disclosure only


@dataclass
class Credential:
    """A username/password combination."""
    username: str
    password: str
    category: str = "generic"    # router, camera, printer, etc.
    vendor: str = ""             # TP-Link, Netgear, etc.
    description: str = ""


@dataclass
class OpenPort:
    """Information about an open port."""
    port: int
    service: Service
    banner: str = ""
    vendor: str = ""             # Detected vendor from banner
    version: str = ""


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    hostname: Optional[str] = None
    open_ports: List[OpenPort] = field(default_factory=list)
    os_guess: Optional[str] = None


@dataclass
class CredentialResult:
    """Result of a credential test."""
    host: str
    port: int
    service: Service
    username: str
    password: str
    success: bool
    error: Optional[str] = None
    banner: str = ""
    response: str = ""           # Response on success
    

@dataclass
class Finding:
    """A successful credential finding."""
    host: str
    port: int
    service: Service
    username: str
    password: str
    severity: Severity
    banner: str
    vendor: str
    access_level: str            # "admin", "user", "guest"
    

@dataclass
class ScanResult:
    """Complete scan result."""
    hosts_scanned: int
    hosts_with_findings: int
    total_findings: int
    critical_count: int
    high_count: int
    scan_start: str
    scan_end: str
    scan_duration_ms: int
    findings: List[Finding]
    host_info: List[HostInfo]

