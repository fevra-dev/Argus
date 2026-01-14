"""
Network discovery and scanning module.

Provides both synchronous and asynchronous network scanning
capabilities for port discovery, banner grabbing, and
intelligent lockout protection.
"""

from .discovery import parse_targets, scan_host, scan_port, grab_banner
from .async_scanner import AsyncScanner, AsyncCredentialTester, ScanMetrics
from .lockout_protection import (
    LockoutProtection,
    LockoutPolicy,
    AttemptTracker,
    create_safe_scanner_policy
)

__all__ = [
    # Discovery
    'parse_targets',
    'scan_host',
    'scan_port',
    'grab_banner',
    
    # Async scanning
    'AsyncScanner',
    'AsyncCredentialTester',
    'ScanMetrics',
    
    # Lockout protection
    'LockoutProtection',
    'LockoutPolicy',
    'AttemptTracker',
    'create_safe_scanner_policy',
]

