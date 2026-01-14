"""
Intelligence integration engine for Argus.

Orchestrates CVE lookup, exploit detection, and risk scoring
to provide comprehensive vulnerability intelligence for findings.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

from .version_parser import VersionParser, ServiceVersion
from .cve_mapper import CVEMapper, CVEInfo
from .exploit_checker import ExploitChecker, ExploitInfo

logger = logging.getLogger(__name__)


@dataclass
class IntelligenceData:
    """
    Complete intelligence data for a security finding.
    
    Aggregates version detection, CVE information, exploit
    availability, and calculated risk scores.
    
    Attributes:
        service_version: Detected service version info
        cves: List of related CVEs
        exploit_checks: Exploit availability per CVE
        risk_score: Calculated risk score (0-10)
        risk_level: Risk category (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        recommendations: Actionable security recommendations
    """
    service_version: Optional[ServiceVersion] = None
    cves: List[CVEInfo] = None
    exploit_checks: Dict[str, ExploitInfo] = None
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    recommendations: List[str] = None
    
    def __post_init__(self):
        """Initialize empty collections if None."""
        if self.cves is None:
            self.cves = []
        if self.exploit_checks is None:
            self.exploit_checks = {}
        if self.recommendations is None:
            self.recommendations = []
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'service_version': asdict(self.service_version) if self.service_version else None,
            'cves': [cve.to_dict() for cve in (self.cves or [])],
            'exploit_checks': {
                cve_id: asdict(info) 
                for cve_id, info in (self.exploit_checks or {}).items()
            },
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'recommendations': self.recommendations or []
        }


class IntelligenceEngine:
    """
    Main intelligence engine coordinating all analysis components.
    
    Provides comprehensive vulnerability intelligence by:
    1. Parsing service versions from banners
    2. Looking up related CVEs from NVD
    3. Checking exploit availability (CISA KEV, etc.)
    4. Calculating composite risk scores
    5. Generating actionable recommendations
    
    Usage:
        engine = IntelligenceEngine(nvd_api_key="your-key")
        intel = engine.analyze_finding(finding, banner)
        print(f"Risk: {intel.risk_score}/10 - {intel.risk_level}")
    """
    
    def __init__(
        self, 
        nvd_api_key: Optional[str] = None,
        enable_exploit_check: bool = True,
        enable_epss: bool = False
    ):
        """
        Initialize intelligence engine with configured components.
        
        Args:
            nvd_api_key: NIST NVD API key for faster CVE lookups
            enable_exploit_check: Enable CISA KEV and exploit checking
            enable_epss: Enable EPSS probability scores (slower)
        """
        self.version_parser = VersionParser()
        self.cve_mapper = CVEMapper(api_key=nvd_api_key)
        
        self.exploit_checker = None
        if enable_exploit_check:
            self.exploit_checker = ExploitChecker()
        
        self.enable_epss = enable_epss
        
        logger.info(
            f"Intelligence Engine initialized - "
            f"CVE: ✓, Exploits: {'✓' if enable_exploit_check else '✗'}, "
            f"EPSS: {'✓' if enable_epss else '✗'}"
        )
    
    def analyze_finding(
        self, 
        finding, 
        banner: str = None
    ) -> IntelligenceData:
        """
        Perform comprehensive intelligence analysis on a finding.
        
        Processes banner to extract version, queries NVD for CVEs,
        checks exploit databases, and generates risk assessment.
        
        Args:
            finding: Finding object from scanner
            banner: Service banner string for version detection
            
        Returns:
            IntelligenceData with complete analysis
        """
        logger.info(
            f"Analyzing {finding.host}:{finding.port} "
            f"({finding.service.value})"
        )
        
        # Step 1: Parse service version from banner
        service_version = None
        if banner:
            service_version = self.version_parser.parse_banner(
                banner,
                finding.service.value
            )
        
        if not service_version:
            logger.debug("No version detected, limited intelligence available")
            return IntelligenceData(
                risk_score=self._base_risk_score(finding),
                risk_level=self._risk_level_from_finding(finding),
                recommendations=self._basic_recommendations(finding)
            )
        
        logger.info(
            f"Detected: {service_version.product} {service_version.version}"
        )
        
        # Step 2: Search for CVEs
        cves = self.cve_mapper.search_cves(
            service_version.product.lower(),
            service_version.version,
            max_results=20
        )
        
        if not cves:
            logger.info("No CVEs found for this version")
            return IntelligenceData(
                service_version=service_version,
                cves=[],
                risk_score=self._base_risk_score(finding),
                risk_level=self._risk_level_from_finding(finding),
                recommendations=self._basic_recommendations(finding)
            )
        
        logger.info(f"Found {len(cves)} CVEs")
        
        # Step 3: Check for exploits
        exploit_checks = {}
        if self.exploit_checker:
            for cve in cves:
                exploit_info = self.exploit_checker.check_cve(
                    cve.cve_id,
                    cve.references
                )
                exploit_checks[cve.cve_id] = exploit_info
        
        # Step 4: Calculate composite risk score
        risk_score = self._calculate_risk_score(
            finding,
            cves,
            exploit_checks
        )
        
        risk_level = self._determine_risk_level(risk_score)
        
        # Step 5: Generate recommendations
        recommendations = self._generate_recommendations(
            finding,
            service_version,
            cves,
            exploit_checks
        )
        
        exploitable_count = sum(1 for e in exploit_checks.values() if e.has_exploit)
        kev_count = sum(1 for e in exploit_checks.values() if e.exploit_maturity == 'high')
        
        logger.info(
            f"Analysis complete: Risk={risk_level} ({risk_score}/10), "
            f"CVEs={len(cves)}, Exploitable={exploitable_count}, KEV={kev_count}"
        )
        
        return IntelligenceData(
            service_version=service_version,
            cves=cves,
            exploit_checks=exploit_checks,
            risk_score=risk_score,
            risk_level=risk_level,
            recommendations=recommendations
        )
    
    def _base_risk_score(self, finding) -> float:
        """Calculate base risk score from finding severity."""
        severity_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MEDIUM': 5.0,
            'LOW': 3.0
        }
        return severity_scores.get(finding.severity.value, 5.0)
    
    def _risk_level_from_finding(self, finding) -> str:
        """Determine risk level from finding severity."""
        return finding.severity.value
    
    def _basic_recommendations(self, finding) -> List[str]:
        """Generate basic recommendations without CVE data."""
        return [
            f"IMMEDIATE: Change default credentials on "
            f"{finding.host}:{finding.port} ({finding.service.value})",
            "Implement strong password policies (12+ chars, mixed case, numbers, symbols)",
            "Enable logging and monitoring for authentication attempts"
        ]
    
    def _calculate_risk_score(
        self,
        finding,
        cves: List[CVEInfo],
        exploit_checks: Dict[str, ExploitInfo]
    ) -> float:
        """
        Calculate comprehensive risk score (0-10).
        
        Factors considered:
        - Default credential severity
        - Maximum CVE severity 
        - Exploit availability and maturity
        - Access level gained
        """
        # Factor 1: Base score from credential finding
        if finding.severity.value == "CRITICAL":
            base_score = 9.0
        elif finding.severity.value == "HIGH":
            base_score = 7.0
        elif finding.severity.value == "MEDIUM":
            base_score = 5.0
        else:
            base_score = 3.0
        
        # Factor 2: CVE severity boost (up to +2.0)
        cve_boost = 0.0
        if cves:
            max_cvss = max(cve.cvss_score for cve in cves)
            critical_cves = sum(1 for cve in cves if cve.severity == "CRITICAL")
            high_cves = sum(1 for cve in cves if cve.severity == "HIGH")
            
            cve_boost = min((max_cvss / 10) * 1.5, 1.5)
            if critical_cves > 0:
                cve_boost += 0.5
            elif high_cves > 0:
                cve_boost += 0.25
        
        base_score += cve_boost
        
        # Factor 3: Exploit availability multiplier (1.0-1.5x)
        exploit_multiplier = 1.0
        if exploit_checks:
            has_kev = any(
                e.exploit_maturity == 'high' 
                for e in exploit_checks.values()
            )
            has_functional = any(
                e.exploit_maturity == 'functional'
                for e in exploit_checks.values()
            )
            has_poc = any(
                e.has_exploit 
                for e in exploit_checks.values()
            )
            
            if has_kev:
                exploit_multiplier = 1.5  # CISA KEV = actively exploited!
            elif has_functional:
                exploit_multiplier = 1.3
            elif has_poc:
                exploit_multiplier = 1.15
        
        base_score *= exploit_multiplier
        
        # Factor 4: Access level adjustment
        if finding.access_level == "admin":
            base_score += 0.5
        
        # Cap at 10.0
        return round(min(base_score, 10.0), 1)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level category from score."""
        if risk_score >= 9.0:
            return "CRITICAL"
        elif risk_score >= 7.0:
            return "HIGH"
        elif risk_score >= 5.0:
            return "MEDIUM"
        elif risk_score >= 3.0:
            return "LOW"
        else:
            return "INFO"
    
    def _generate_recommendations(
        self,
        finding,
        service_version: ServiceVersion,
        cves: List[CVEInfo],
        exploit_checks: Dict[str, ExploitInfo]
    ) -> List[str]:
        """Generate prioritized, actionable security recommendations."""
        recommendations = []
        
        # Always recommend changing default credentials
        recommendations.append(
            f"🔴 IMMEDIATE: Change default credentials on "
            f"{finding.host}:{finding.port} ({finding.service.value})"
        )
        
        # Check for actively exploited CVEs (highest priority)
        kev_cves = [
            cve_id for cve_id, info in exploit_checks.items()
            if info.exploit_maturity == 'high'
        ]
        
        if kev_cves:
            recommendations.append(
                f"🔴 CRITICAL: {len(kev_cves)} actively exploited CVEs detected "
                f"(CISA KEV). Patch or isolate system immediately!"
            )
            for cve_id in kev_cves[:3]:  # Show top 3
                recommendations.append(f"   • Patch: {cve_id}")
        
        # Version-specific update recommendations
        if cves:
            critical_cves = [cve for cve in cves if cve.severity == "CRITICAL"]
            if critical_cves:
                recommendations.append(
                    f"🟠 HIGH: Update {service_version.product} from version "
                    f"{service_version.version} - {len(critical_cves)} critical CVEs found"
                )
        
        # Access level specific recommendations
        if finding.access_level == "admin":
            recommendations.append(
                "🟠 HIGH: Administrative access obtained. Conduct full "
                "security audit and review system logs for unauthorized changes"
            )
        
        # Service-specific hardening
        service = finding.service.value.lower()
        if service == "ssh":
            recommendations.extend([
                "Enable SSH key-based authentication instead of passwords",
                "Disable root login and use sudo for privilege escalation",
                "Configure fail2ban or similar brute-force protection"
            ])
        elif service in ["http", "https"]:
            recommendations.extend([
                "Implement HTTPS with strong TLS configuration",
                "Enable HTTP security headers (HSTS, CSP, X-Frame-Options)"
            ])
        elif service == "ftp":
            recommendations.extend([
                "Consider replacing FTP with SFTP for encrypted transfers",
                "Restrict FTP access to specific IP ranges"
            ])
        elif service == "telnet":
            recommendations.append(
                "🔴 Replace Telnet with SSH - Telnet sends credentials in plaintext"
            )
        
        # General network security
        recommendations.append(
            f"Restrict {service.upper()} access using firewall rules"
        )
        recommendations.append(
            "Enable comprehensive logging and SIEM integration"
        )
        
        return recommendations
    
    def generate_intelligence_report(
        self,
        enriched_findings: List[Dict]
    ) -> Dict:
        """
        Generate comprehensive intelligence report for all findings.
        
        Aggregates statistics across all analyzed findings to provide
        executive-level summary and risk assessment.
        
        Args:
            enriched_findings: List of findings with intelligence data
            
        Returns:
            Report dictionary with statistics and risk assessment
        """
        total_findings = len(enriched_findings)
        
        # CVE statistics
        total_cves = 0
        critical_cves = 0
        high_cves = 0
        exploitable_cves = 0
        kev_cves = 0
        
        # Risk statistics
        critical_risk = 0
        high_risk = 0
        
        for finding_data in enriched_findings:
            intel = finding_data.get('intelligence')
            if not intel:
                continue
            
            # Count CVEs
            cves = intel.get('cves', [])
            total_cves += len(cves)
            
            for cve in cves:
                severity = cve.get('severity') if isinstance(cve, dict) else getattr(cve, 'severity', None)
                if severity == 'CRITICAL':
                    critical_cves += 1
                elif severity == 'HIGH':
                    high_cves += 1
            
            # Count exploits
            exploit_checks = intel.get('exploit_checks', {})
            for exploit_info in exploit_checks.values():
                if isinstance(exploit_info, dict):
                    if exploit_info.get('has_exploit'):
                        exploitable_cves += 1
                    if exploit_info.get('exploit_maturity') == 'high':
                        kev_cves += 1
                else:
                    if exploit_info.has_exploit:
                        exploitable_cves += 1
                    if exploit_info.exploit_maturity == 'high':
                        kev_cves += 1
            
            # Risk levels
            risk_level = intel.get('risk_level')
            if risk_level == 'CRITICAL':
                critical_risk += 1
            elif risk_level == 'HIGH':
                high_risk += 1
        
        return {
            'summary': {
                'total_findings': total_findings,
                'critical_risk_findings': critical_risk,
                'high_risk_findings': high_risk,
            },
            'vulnerabilities': {
                'total_cves': total_cves,
                'critical_cves': critical_cves,
                'high_cves': high_cves,
                'exploitable_cves': exploitable_cves,
                'actively_exploited_cves': kev_cves,
            },
            'risk_assessment': {
                'overall_risk': 'CRITICAL' if (critical_risk > 0 or kev_cves > 0) 
                               else 'HIGH' if high_risk > 0 
                               else 'MEDIUM',
                'requires_immediate_action': critical_risk > 0 or kev_cves > 0,
                'key_concerns': self._generate_key_concerns(
                    critical_risk, 
                    kev_cves,
                    exploitable_cves
                )
            }
        }
    
    def _generate_key_concerns(
        self,
        critical_risk: int,
        kev_cves: int,
        exploitable_cves: int
    ) -> List[str]:
        """Generate prioritized list of key security concerns."""
        concerns = []
        
        if kev_cves > 0:
            concerns.append(
                f"⚠️ {kev_cves} actively exploited vulnerabilities (CISA KEV) - "
                "IMMEDIATE ACTION REQUIRED"
            )
        
        if critical_risk > 0:
            concerns.append(
                f"🔴 {critical_risk} systems with critical risk level - "
                "immediate remediation required"
            )
        
        if exploitable_cves > 0:
            concerns.append(
                f"🟠 {exploitable_cves} CVEs with public exploits available"
            )
        
        concerns.append(
            "Default credentials provide unauthorized access - change immediately"
        )
        
        return concerns


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    from dataclasses import dataclass
    from enum import Enum
    
    class Service(Enum):
        SSH = "ssh"
    
    class Severity(Enum):
        CRITICAL = "CRITICAL"
    
    @dataclass
    class MockFinding:
        host: str = "192.168.1.1"
        port: int = 22
        service: Service = Service.SSH
        username: str = "admin"
        password: str = "admin"
        severity: Severity = Severity.CRITICAL
        access_level: str = "admin"
    
    print("Testing Intelligence Engine...\n")
    
    engine = IntelligenceEngine()
    finding = MockFinding()
    banner = "SSH-2.0-OpenSSH_7.4"
    
    intelligence = engine.analyze_finding(finding, banner)
    
    print(f"\n{'='*50}")
    print("Intelligence Analysis Results")
    print(f"{'='*50}")
    print(f"Service: {intelligence.service_version.product if intelligence.service_version else 'Unknown'}")
    print(f"Version: {intelligence.service_version.version if intelligence.service_version else 'Unknown'}")
    print(f"CVEs Found: {len(intelligence.cves)}")
    print(f"Risk Score: {intelligence.risk_score}/10")
    print(f"Risk Level: {intelligence.risk_level}")
    
    if intelligence.recommendations:
        print(f"\nRecommendations:")
        for i, rec in enumerate(intelligence.recommendations[:5], 1):
            print(f"  {i}. {rec}")
