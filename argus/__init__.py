"""
Argus - Intelligence-Driven Security Scanner.

Named after Argus Panoptes, the all-seeing giant with 100 eyes from Greek
mythology. A comprehensive security tool for identifying default credentials
and vulnerabilities in network services with real-time intelligence analysis.

Features:
- High-performance async network scanning
- Real-time CVE enrichment via NIST NVD
- Exploit availability checking (CISA KEV)
- Modern Rich TUI with progress visualization
- REST API with Swagger documentation
- Multi-channel notifications (Slack, Discord, Teams, Email)
- SIEM integration (Splunk, ELK, Syslog/CEF)
- Scheduled automated scanning
- Professional HTML reports with interactive charts

Usage:
    # CLI Scanning
    argus scan 192.168.1.0/24 -p 22,80,443 --enrich-cves
    
    # API Server
    argus api
    
    # Python API
    from argus import ArgusScanner, IntelligenceEngine
    
    scanner = ArgusScanner(targets, ports)
    results = scanner.scan()

Author: Security Team
License: MIT
"""

__version__ = "0.2.1"
__author__ = "Fevra"
__email__ = "fev.dev@proton.me"

# Core imports
from .scanner import ArgusScanner
from .models import (
    Service,
    Credential,
    OpenPort,
    HostInfo,
    CredentialResult,
    Finding,
    ScanResult,
    Severity
)

# Network scanning
from .network import parse_targets, scan_host, scan_port, grab_banner

# Intelligence layer
try:
    from .intel import (
        IntelligenceEngine,
        IntelligenceData,
        VersionParser,
        ServiceVersion,
        CVEMapper,
        CVEInfo,
        ExploitChecker,
        ExploitInfo
    )
    HAS_INTEL = True
except ImportError:
    HAS_INTEL = False

# Reporting
try:
    from .reporting import ReportGenerator
    HAS_REPORTING = True
except ImportError:
    HAS_REPORTING = False

# Enterprise integrations
try:
    from .integrations import (
        NotificationManager,
        NotificationConfig,
        ScanScheduler,
        ScheduledScan,
        SIEMIntegration,
        SIEMConfig
    )
    HAS_ENTERPRISE = True
except ImportError:
    HAS_ENTERPRISE = False

__all__ = [
    # Core
    '__version__',
    'ArgusScanner',
    'Service',
    'Credential',
    'OpenPort',
    'HostInfo',
    'CredentialResult',
    'Finding',
    'ScanResult',
    'Severity',
    
    # Network
    'parse_targets',
    'scan_host',
    'scan_port',
    'grab_banner',
]

# Conditionally add to __all__
if HAS_INTEL:
    __all__.extend([
        'IntelligenceEngine',
        'IntelligenceData',
        'VersionParser',
        'ServiceVersion',
        'CVEMapper',
        'CVEInfo',
        'ExploitChecker',
        'ExploitInfo'
    ])

if HAS_REPORTING:
    __all__.append('ReportGenerator')

if HAS_ENTERPRISE:
    __all__.extend([
        'NotificationManager',
        'NotificationConfig',
        'ScanScheduler',
        'ScheduledScan',
        'SIEMIntegration',
        'SIEMConfig'
    ])
