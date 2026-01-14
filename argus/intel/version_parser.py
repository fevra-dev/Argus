"""
Service version detection from banners and responses.

Extracts product names, versions, and metadata for CVE matching.
This module provides high-accuracy version parsing for network services.
"""

import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ServiceVersion:
    """
    Parsed service version information.
    
    Attributes:
        product: Product name (e.g., "OpenSSH", "Apache httpd")
        version: Version string (e.g., "8.9p1", "2.4.52")
        os: Operating system if detected
        details: Raw banner/response data
        confidence: Detection confidence score (0.0-1.0)
    """
    product: str
    version: str
    os: Optional[str] = None
    details: Optional[str] = None
    confidence: float = 1.0


class VersionParser:
    """
    Extract version information from service banners.
    
    Supports SSH, HTTP, FTP, Telnet, and generic services.
    Uses regex-based pattern matching with service-specific rules.
    """
    
    # Common version patterns for generic parsing
    VERSION_PATTERNS = [
        r'(\d+\.\d+\.?\d*\.?\d*)',           # Standard semver: 1.2.3
        r'(\d+\.\d+[a-z]\d+)',                # With letters: 8.9p1
        r'(\d+\.\d+\.\d+[-.]?[a-zA-Z0-9.]+)', # Build numbers: 1.0.0-beta.1
    ]
    
    # Service-specific version extraction patterns
    SERVICE_PATTERNS = {
        'ssh': [
            r'OpenSSH[_\s]+([\d.]+[a-z]?\d*)',
            r'SSH-[\d.]+-OpenSSH_([\d.]+)',
            r'dropbear[_-]?([\d.]+)',
            r'Cisco-([\d.]+)',
        ],
        'http': [
            r'Apache/([\d.]+)',
            r'nginx/([\d.]+)',
            r'Microsoft-IIS/([\d.]+)',
            r'lighttpd/([\d.]+)',
            r'LiteSpeed/([\d.]+)',
            r'Caddy/([\d.]+)',
        ],
        'https': [
            r'Apache/([\d.]+)',
            r'nginx/([\d.]+)',
            r'Microsoft-IIS/([\d.]+)',
        ],
        'ftp': [
            r'vsftpd ([\d.]+)',
            r'ProFTPD ([\d.]+)',
            r'Pure-FTPd ([\d.]+)',
            r'FileZilla Server ([\d.]+)',
            r'wu-(\d+\.\d+)',
        ],
        'telnet': [
            r'Cisco IOS.*Version ([\d.()]+)',
            r'Linux.*\(([\d.]+)',
        ]
    }
    
    # Product name extraction patterns
    PRODUCT_PATTERNS = {
        'OpenSSH': r'OpenSSH',
        'Dropbear': r'dropbear',
        'Apache httpd': r'Apache(?!/)',
        'nginx': r'nginx',
        'Microsoft-IIS': r'Microsoft-IIS',
        'lighttpd': r'lighttpd',
        'vsftpd': r'vsftpd',
        'ProFTPD': r'ProFTPD',
        'Pure-FTPd': r'Pure-FTPd',
        'Cisco IOS': r'Cisco IOS',
        'MikroTik': r'MikroTik',
    }
    
    # Operating system detection patterns
    OS_PATTERNS = [
        (r'Ubuntu', 'Ubuntu Linux'),
        (r'Debian', 'Debian Linux'),
        (r'CentOS', 'CentOS Linux'),
        (r'Red Hat', 'Red Hat Enterprise Linux'),
        (r'RHEL', 'Red Hat Enterprise Linux'),
        (r'FreeBSD', 'FreeBSD'),
        (r'Windows', 'Microsoft Windows'),
        (r'Darwin', 'macOS'),
        (r'Alpine', 'Alpine Linux'),
        (r'Arch', 'Arch Linux'),
    ]
    
    def parse_banner(
        self, 
        banner: str, 
        service_type: str = None
    ) -> Optional[ServiceVersion]:
        """
        Parse a service banner to extract version information.
        
        Args:
            banner: Service banner string from network probe
            service_type: Type of service (ssh, http, ftp, telnet, etc.)
            
        Returns:
            ServiceVersion object with parsed data, or None if parsing failed
        """
        if not banner or len(banner.strip()) == 0:
            return None
        
        logger.debug(f"Parsing banner: {banner[:100]}...")
        
        # Try service-specific patterns first (higher confidence)
        if service_type and service_type.lower() in self.SERVICE_PATTERNS:
            result = self._parse_service_specific(
                banner, 
                service_type.lower()
            )
            if result:
                return result
        
        # Fall back to generic parsing (lower confidence)
        return self._parse_generic(banner)
    
    def _parse_service_specific(
        self, 
        banner: str, 
        service_type: str
    ) -> Optional[ServiceVersion]:
        """Parse using service-specific patterns for higher accuracy."""
        patterns = self.SERVICE_PATTERNS.get(service_type, [])
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1)
                product = self._extract_product(banner)
                os = self._extract_os(banner)
                
                logger.info(
                    f"Detected: {product} {version}" + 
                    (f" on {os}" if os else "")
                )
                
                return ServiceVersion(
                    product=product or service_type.upper(),
                    version=version,
                    os=os,
                    details=banner[:200],
                    confidence=0.9
                )
        
        return None
    
    def _parse_generic(self, banner: str) -> Optional[ServiceVersion]:
        """Generic banner parsing when service type is unknown."""
        product = self._extract_product(banner)
        version = self._extract_version(banner)
        
        if not version:
            return None
        
        os = self._extract_os(banner)
        
        return ServiceVersion(
            product=product or "Unknown",
            version=version,
            os=os,
            details=banner[:200],
            confidence=0.5  # Lower confidence for generic parsing
        )
    
    def _extract_product(self, banner: str) -> Optional[str]:
        """Extract product name from banner."""
        for product, pattern in self.PRODUCT_PATTERNS.items():
            if re.search(pattern, banner, re.IGNORECASE):
                return product
        
        # Try to extract first word before version number
        match = re.search(r'([A-Za-z][A-Za-z0-9_-]+)\s*[\d.]', banner)
        if match:
            return match.group(1)
        
        return None
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version number from banner."""
        for pattern in self.VERSION_PATTERNS:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return None
    
    def _extract_os(self, banner: str) -> Optional[str]:
        """Extract operating system from banner."""
        for pattern, os_name in self.OS_PATTERNS:
            if re.search(pattern, banner, re.IGNORECASE):
                return os_name
        return None
    
    def parse_http_headers(self, headers: Dict[str, str]) -> List[ServiceVersion]:
        """
        Parse HTTP headers for version information.
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            List of ServiceVersion objects for detected software
        """
        versions = []
        
        # Check Server header
        if 'Server' in headers:
            result = self.parse_banner(headers['Server'], 'http')
            if result:
                versions.append(result)
        
        # Check X-Powered-By for application framework versions
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            match = re.search(r'([A-Za-z]+)/([\d.]+)', powered_by)
            if match:
                versions.append(ServiceVersion(
                    product=match.group(1),
                    version=match.group(2),
                    confidence=0.8
                ))
        
        return versions
    
    def normalize_version(self, version: str) -> str:
        """
        Normalize version string for CVE matching.
        
        Removes OS-specific suffixes and patch identifiers.
        
        Args:
            version: Raw version string
            
        Returns:
            Normalized version string for database queries
        """
        normalized = re.sub(r'[a-z]\d+$', '', version)      # Remove 'p1', 'a2'
        normalized = re.sub(r'-[A-Za-z]+.*$', '', normalized)  # Remove '-Ubuntu'
        normalized = re.sub(r'\+.*$', '', normalized)       # Remove '+deb11u1'
        return normalized.strip()
    
    def compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        
        Args:
            v1: First version string
            v2: Second version string
            
        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        def version_tuple(v):
            parts = re.findall(r'\d+', v)
            return tuple(int(x) for x in parts)
        
        try:
            t1 = version_tuple(v1)
            t2 = version_tuple(v2)
            
            if t1 < t2:
                return -1
            elif t1 > t2:
                return 1
            return 0
        except Exception:
            # Fall back to string comparison
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    parser = VersionParser()
    
    test_banners = [
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "ssh"),
        ("Apache/2.4.52 (Ubuntu)", "http"),
        ("vsftpd 3.0.3", "ftp"),
        ("220 ProFTPD 1.3.5 Server", "ftp"),
        ("nginx/1.24.0", "http"),
    ]
    
    for banner, service in test_banners:
        result = parser.parse_banner(banner, service)
        if result:
            print(f"Banner: {banner}")
            print(f"  Product: {result.product}")
            print(f"  Version: {result.version}")
            print(f"  OS: {result.os}")
            print(f"  Confidence: {result.confidence}")
            print()
