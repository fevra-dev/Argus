"""
CVE database integration using NIST NVD API 2.0.

Enriches security findings with known vulnerabilities from the
National Vulnerability Database. Supports rate limiting, caching,
and API key authentication for improved performance.
"""

import requests
import json
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from functools import lru_cache
from datetime import datetime, timedelta
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """
    CVE vulnerability information from NVD.
    
    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2023-12345")
        description: Vulnerability description
        severity: CRITICAL, HIGH, MEDIUM, or LOW
        cvss_score: CVSS v3.x base score (0.0-10.0)
        cvss_vector: CVSS vector string
        published_date: Publication date in ISO format
        references: List of reference URLs
        cpe_matches: Affected product CPE strings
    """
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published_date: str
    references: List[str]
    cpe_matches: List[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class CVEMapper:
    """
    Map service versions to known CVEs using NIST NVD API 2.0.
    
    Provides real-time vulnerability lookups with intelligent
    rate limiting and caching to optimize API usage.
    
    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    
    Rate Limits:
        - Without API key: 5 requests per 30 seconds
        - With API key: 50 requests per 30 seconds (free)
    
    Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key
    """
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6  # seconds between requests (no API key)
    
    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600):
        """
        Initialize CVE mapper.
        
        Args:
            api_key: NIST NVD API key (optional, increases rate limit 10x)
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self.last_request = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Argus/0.2.1 Security Scanner'
        })
        
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.RATE_LIMIT_DELAY = 0.6  # 50 req/30s with API key
        
        logger.info(
            f"CVE Mapper initialized " +
            f"({'with API key' if api_key else 'no API key - consider getting a free key for faster scans'})"
        )
    
    def _rate_limit(self):
        """Enforce rate limiting to avoid API blocks."""
        elapsed = time.time() - self.last_request
        if elapsed < self.RATE_LIMIT_DELAY:
            sleep_time = self.RATE_LIMIT_DELAY - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self.last_request = time.time()
    
    @lru_cache(maxsize=1000)
    def search_cves(
        self, 
        product: str, 
        version: str,
        max_results: int = 10
    ) -> List[CVEInfo]:
        """
        Search for CVEs affecting a product/version.
        
        Uses keyword-based search to find relevant vulnerabilities.
        Results are cached to minimize API calls.
        
        Args:
            product: Product name (e.g., "openssh", "apache")
            version: Product version (e.g., "8.9", "2.4.52")
            max_results: Maximum number of CVEs to return
            
        Returns:
            List of CVEInfo objects sorted by severity
        """
        self._rate_limit()
        
        # Construct search query
        keyword_query = f"{product} {version}"
        
        params = {
            'keywordSearch': keyword_query,
            'resultsPerPage': max_results,
        }
        
        try:
            logger.debug(f"Searching CVEs for: {keyword_query}")
            response = self.session.get(
                self.NVD_API_BASE,
                params=params,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data)
                logger.info(f"Found {len(cves)} CVEs for {product} {version}")
                return cves
            elif response.status_code == 403:
                logger.error(
                    "NVD API rate limit exceeded. "
                    "Get a free API key: https://nvd.nist.gov/developers/request-an-api-key"
                )
                return []
            elif response.status_code == 404:
                logger.debug(f"No CVEs found for {keyword_query}")
                return []
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            logger.error("NVD API request timed out")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to query NVD API: {e}")
            return []
    
    def _parse_nvd_response(self, data: dict) -> List[CVEInfo]:
        """Parse NVD API response into CVEInfo objects."""
        cves = []
        
        for vuln in data.get('vulnerabilities', []):
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', 'UNKNOWN')
                
                # Extract English description
                descriptions = cve_data.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')[:500]
                        break
                
                # Get CVSS metrics (prefer v3.1 > v3.0 > v2.0)
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                cvss_vector = ""
                severity = "UNKNOWN"
                
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    metric = metrics['cvssMetricV31'][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_vector = cvss_data.get('vectorString', '')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    metric = metrics['cvssMetricV30'][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_vector = cvss_data.get('vectorString', '')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    metric = metrics['cvssMetricV2'][0]
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_vector = cvss_data.get('vectorString', '')
                    # v2 doesn't have baseSeverity in cvssData
                    severity = metric.get('baseSeverity', 'UNKNOWN')
                
                # Extract references (first 5)
                references = []
                for ref in cve_data.get('references', [])[:5]:
                    url = ref.get('url', '')
                    if url:
                        references.append(url)
                
                # Get published date
                published = cve_data.get('published', '')
                
                cves.append(CVEInfo(
                    cve_id=cve_id,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    published_date=published,
                    references=references
                ))
                
            except Exception as e:
                logger.error(f"Error parsing CVE data: {e}")
                continue
        
        # Sort by CVSS score (highest first)
        cves.sort(key=lambda x: x.cvss_score, reverse=True)
        
        return cves
    
    def enrich_finding(
        self, 
        finding, 
        service_version
    ) -> Dict:
        """
        Enrich a finding with CVE information.
        
        Args:
            finding: Finding object from scanner
            service_version: ServiceVersion object from version parser
            
        Returns:
            Dictionary with enriched finding data including CVEs
        """
        if not service_version:
            return {
                'finding': finding,
                'cves': [],
                'has_cves': False,
                'max_severity': 'NONE'
            }
        
        # Search for CVEs
        cves = self.search_cves(
            service_version.product.lower(),
            service_version.version
        )
        
        # Determine maximum severity
        max_severity = 'NONE'
        if cves:
            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            for sev in severities:
                if any(cve.severity == sev for cve in cves):
                    max_severity = sev
                    break
        
        return {
            'finding': finding,
            'service_version': service_version,
            'cves': cves,
            'has_cves': len(cves) > 0,
            'max_severity': max_severity,
            'cve_count': len(cves)
        }
    
    def get_cve_summary(self, cves: List[CVEInfo]) -> Dict:
        """
        Generate summary statistics for a list of CVEs.
        
        Args:
            cves: List of CVEInfo objects
            
        Returns:
            Dictionary with severity counts and score statistics
        """
        if not cves:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'max_cvss': 0.0,
                'avg_cvss': 0.0
            }
        
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_score = 0.0
        max_score = 0.0
        
        for cve in cves:
            if cve.severity in severity_count:
                severity_count[cve.severity] += 1
            total_score += cve.cvss_score
            max_score = max(max_score, cve.cvss_score)
        
        return {
            'total': len(cves),
            'critical': severity_count['CRITICAL'],
            'high': severity_count['HIGH'],
            'medium': severity_count['MEDIUM'],
            'low': severity_count['LOW'],
            'max_cvss': max_score,
            'avg_cvss': round(total_score / len(cves), 1) if cves else 0.0
        }
    
    def format_cve_list(self, cves: List[CVEInfo]) -> str:
        """
        Format CVE list for console output.
        
        Args:
            cves: List of CVEInfo objects
            
        Returns:
            Formatted multi-line string
        """
        if not cves:
            return "No CVEs found"
        
        lines = []
        for cve in cves[:5]:  # Show top 5
            lines.append(
                f"  • {cve.cve_id} - {cve.severity} "
                f"(CVSS {cve.cvss_score})"
            )
            lines.append(f"    {cve.description[:100]}...")
        
        if len(cves) > 5:
            lines.append(f"  ... and {len(cves) - 5} more")
        
        return "\n".join(lines)


class CVECache:
    """
    File-based cache for CVE data to reduce API calls.
    
    Stores query results in JSON format for offline access
    and faster subsequent lookups.
    """
    
    def __init__(self, cache_file: str = ".cve_cache.json"):
        """
        Initialize cache.
        
        Args:
            cache_file: Path to cache file
        """
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()
    
    def _load_cache(self) -> dict:
        """Load cache from file."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not load CVE cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save cache to file."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save CVE cache: {e}")
    
    def get(self, key: str, ttl: int = 3600) -> Optional[List[dict]]:
        """
        Get cached CVE data if still valid.
        
        Args:
            key: Cache key (usually "product:version")
            ttl: Time-to-live in seconds
            
        Returns:
            Cached data or None if expired/missing
        """
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        timestamp = entry.get('timestamp', 0)
        
        if time.time() - timestamp > ttl:
            return None
        
        return entry.get('data')
    
    def set(self, key: str, data: List[dict]):
        """
        Cache CVE data.
        
        Args:
            key: Cache key
            data: Data to cache
        """
        self.cache[key] = {
            'timestamp': time.time(),
            'data': data
        }
        self._save_cache()


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    mapper = CVEMapper()
    
    print("Testing CVE lookup for OpenSSH 8.9...")
    cves = mapper.search_cves("openssh", "8.9")
    
    print(f"\nFound {len(cves)} CVEs:")
    print(mapper.format_cve_list(cves))
    
    summary = mapper.get_cve_summary(cves)
    print(f"\nSummary: {summary}")
