"""
Auto-remediation guide generator for Argus.

Generates actionable, service-specific remediation
recommendations based on discovered vulnerabilities.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class RemediationStep:
    """Single remediation step with priority."""
    priority: int  # 1 = Critical, 5 = Low
    action: str
    command: Optional[str] = None
    reference: Optional[str] = None


@dataclass
class RemediationGuide:
    """Complete remediation guide for a finding."""
    service: str
    severity: str
    summary: str
    immediate_actions: List[str]
    steps: List[RemediationStep]
    compliance_refs: List[str]
    estimated_effort: str


class RemediationGenerator:
    """
    Generate remediation guides for discovered findings.
    
    Provides:
    - Service-specific hardening recommendations
    - Command examples where applicable
    - Compliance framework references
    - Prioritized action steps
    
    Following Dieter Rams' principle of usefulness:
    Every recommendation must be actionable and practical.
    """
    
    # Service-specific remediation templates
    REMEDIATION_DB = {
        "ssh": {
            "summary": "SSH default credentials detected - immediate password change required",
            "immediate_actions": [
                "Change the password immediately",
                "Review SSH access logs for unauthorized access",
                "Rotate any keys that may have been exposed"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Disable password authentication, use key-based auth only",
                    command="echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && systemctl restart sshd",
                    reference="CIS Benchmark SSH 5.2.6"
                ),
                RemediationStep(
                    priority=1,
                    action="Disable root login via SSH",
                    command="sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                    reference="CIS Benchmark SSH 5.2.10"
                ),
                RemediationStep(
                    priority=2,
                    action="Implement SSH key rotation policy",
                    command=None,
                    reference="NIST SP 800-53 IA-5"
                ),
                RemediationStep(
                    priority=2,
                    action="Configure fail2ban or similar for brute-force protection",
                    command="apt install fail2ban && systemctl enable fail2ban",
                    reference="CIS Benchmark 5.2.20"
                ),
                RemediationStep(
                    priority=3,
                    action="Enable SSH logging and monitoring",
                    command="echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config",
                    reference="PCI DSS 10.2"
                )
            ],
            "compliance_refs": [
                "PCI DSS 8.2.3 - Strong Cryptography",
                "NIST 800-53 IA-5 - Authenticator Management",
                "CIS Controls 5.2 - Secure Access"
            ],
            "estimated_effort": "30 minutes"
        },
        
        "http": {
            "summary": "HTTP/HTTPS default credentials on web service",
            "immediate_actions": [
                "Change default admin password immediately",
                "Check for unauthorized configuration changes",
                "Review access logs for suspicious activity"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Change all default credentials to strong passwords (16+ chars)",
                    command=None,
                    reference="OWASP Authentication Cheat Sheet"
                ),
                RemediationStep(
                    priority=1,
                    action="Enable multi-factor authentication (MFA)",
                    command=None,
                    reference="NIST SP 800-63B"
                ),
                RemediationStep(
                    priority=2,
                    action="Implement account lockout after 5 failed attempts",
                    command=None,
                    reference="CIS Controls 16.9"
                ),
                RemediationStep(
                    priority=2,
                    action="Restrict admin interface to internal network only",
                    command=None,
                    reference="OWASP ASVS 4.0"
                ),
                RemediationStep(
                    priority=3,
                    action="Implement rate limiting on authentication endpoints",
                    command=None,
                    reference="OWASP API Security"
                )
            ],
            "compliance_refs": [
                "OWASP Top 10 A07:2021 - Identification Failures",
                "PCI DSS 8.3 - Strong Authentication",
                "NIST 800-53 AC-7 - Unsuccessful Login Attempts"
            ],
            "estimated_effort": "1-2 hours"
        },
        
        "redis": {
            "summary": "Redis accessible without authentication - database exposed",
            "immediate_actions": [
                "Enable Redis authentication immediately",
                "Check for data exfiltration",
                "Review Redis command history"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Set a strong password in redis.conf",
                    command="echo 'requirepass YOUR_STRONG_PASSWORD' >> /etc/redis/redis.conf && systemctl restart redis",
                    reference="Redis Security Documentation"
                ),
                RemediationStep(
                    priority=1,
                    action="Bind Redis to localhost only",
                    command="sed -i 's/bind 0.0.0.0/bind 127.0.0.1/' /etc/redis/redis.conf",
                    reference="CIS Benchmark Redis"
                ),
                RemediationStep(
                    priority=2,
                    action="Disable dangerous commands (FLUSHALL, CONFIG, etc.)",
                    command="echo 'rename-command FLUSHALL \"\"' >> /etc/redis/redis.conf",
                    reference="Redis Security Best Practices"
                ),
                RemediationStep(
                    priority=2,
                    action="Enable TLS encryption for Redis connections",
                    command=None,
                    reference="Redis TLS Documentation"
                ),
                RemediationStep(
                    priority=3,
                    action="Implement network segmentation for Redis",
                    command=None,
                    reference="NIST 800-53 SC-7"
                )
            ],
            "compliance_refs": [
                "CIS Controls 3.3 - Secure Data at Rest",
                "PCI DSS 1.3.7 - Network Segmentation",
                "NIST 800-53 AC-3 - Access Enforcement"
            ],
            "estimated_effort": "45 minutes"
        },
        
        "mysql": {
            "summary": "MySQL default credentials - database access compromised",
            "immediate_actions": [
                "Change root password immediately",
                "Run mysql_secure_installation",
                "Audit database users and permissions"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Set strong root password",
                    command="mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY 'NEW_STRONG_PASSWORD';\"",
                    reference="MySQL Security Guide"
                ),
                RemediationStep(
                    priority=1,
                    action="Run MySQL secure installation script",
                    command="mysql_secure_installation",
                    reference="CIS Benchmark MySQL 5.7"
                ),
                RemediationStep(
                    priority=2,
                    action="Remove anonymous users and test databases",
                    command="mysql -e \"DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test;\"",
                    reference="CIS Benchmark 4.2"
                ),
                RemediationStep(
                    priority=2,
                    action="Disable remote root login",
                    command="mysql -e \"DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');\"",
                    reference="CIS Benchmark 4.5"
                ),
                RemediationStep(
                    priority=3,
                    action="Enable query logging for audit",
                    command="echo 'general_log = 1' >> /etc/mysql/mysql.conf.d/mysqld.cnf",
                    reference="PCI DSS 10.2"
                )
            ],
            "compliance_refs": [
                "CIS MySQL Benchmark 5.7",
                "PCI DSS 2.1 - Default Passwords",
                "NIST 800-53 IA-5"
            ],
            "estimated_effort": "1 hour"
        },
        
        "snmp": {
            "summary": "SNMP default community string - network device exposed",
            "immediate_actions": [
                "Change community strings immediately",
                "Upgrade to SNMPv3 if possible",
                "Review device configurations for tampering"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Change default community strings to strong random values",
                    command=None,
                    reference="CIS Network Device Benchmark"
                ),
                RemediationStep(
                    priority=1,
                    action="Upgrade to SNMPv3 with authentication and encryption",
                    command=None,
                    reference="NIST SP 800-53 SC-8"
                ),
                RemediationStep(
                    priority=2,
                    action="Restrict SNMP access to management network only",
                    command=None,
                    reference="CIS Controls 12.1"
                ),
                RemediationStep(
                    priority=2,
                    action="Disable SNMP if not required",
                    command=None,
                    reference="CIS Controls 4.8"
                ),
                RemediationStep(
                    priority=3,
                    action="Implement SNMP trap monitoring",
                    command=None,
                    reference="NIST 800-53 SI-4"
                )
            ],
            "compliance_refs": [
                "CIS Controls 4.8 - Disable Unnecessary Services",
                "PCI DSS 2.2.2 - Enable Only Necessary Services",
                "NIST 800-53 CM-7"
            ],
            "estimated_effort": "1-2 hours"
        },
        
        "mongodb": {
            "summary": "MongoDB accessible without authentication",
            "immediate_actions": [
                "Enable MongoDB authentication immediately",
                "Check for data exfiltration",
                "Backup and audit database contents"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Enable authentication in mongod.conf",
                    command="echo 'security.authorization: enabled' >> /etc/mongod.conf && systemctl restart mongod",
                    reference="MongoDB Security Checklist"
                ),
                RemediationStep(
                    priority=1,
                    action="Create admin user with strong password",
                    command="mongosh --eval \"db.createUser({user:'admin',pwd:'STRONG_PWD',roles:['userAdminAnyDatabase']})\"",
                    reference="MongoDB Authorization"
                ),
                RemediationStep(
                    priority=2,
                    action="Bind to localhost only",
                    command="sed -i 's/bindIp: 0.0.0.0/bindIp: 127.0.0.1/' /etc/mongod.conf",
                    reference="MongoDB Network Hardening"
                ),
                RemediationStep(
                    priority=2,
                    action="Enable TLS/SSL for connections",
                    command=None,
                    reference="MongoDB TLS Configuration"
                ),
                RemediationStep(
                    priority=3,
                    action="Enable audit logging",
                    command=None,
                    reference="MongoDB Auditing"
                )
            ],
            "compliance_refs": [
                "CIS MongoDB Benchmark",
                "OWASP Database Security",
                "PCI DSS 8.2 - Unique IDs"
            ],
            "estimated_effort": "1 hour"
        },
        
        "ftp": {
            "summary": "FTP default credentials - file server exposed",
            "immediate_actions": [
                "Change FTP credentials immediately",
                "Audit uploaded/downloaded files",
                "Consider replacing FTP with SFTP"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Change all FTP passwords to strong values",
                    command=None,
                    reference="CIS FTP Benchmark"
                ),
                RemediationStep(
                    priority=1,
                    action="Disable anonymous FTP access",
                    command="echo 'anonymous_enable=NO' >> /etc/vsftpd.conf",
                    reference="CIS Benchmark vsftpd 3.0"
                ),
                RemediationStep(
                    priority=2,
                    action="Migrate to SFTP/SCP for encrypted transfers",
                    command=None,
                    reference="NIST 800-53 SC-8"
                ),
                RemediationStep(
                    priority=2,
                    action="Implement chroot jails for FTP users",
                    command="echo 'chroot_local_user=YES' >> /etc/vsftpd.conf",
                    reference="CIS Benchmark 3.2"
                ),
                RemediationStep(
                    priority=3,
                    action="Enable FTP logging",
                    command="echo 'xferlog_enable=YES' >> /etc/vsftpd.conf",
                    reference="PCI DSS 10.2"
                )
            ],
            "compliance_refs": [
                "PCI DSS 4.1 - Encrypt Transmission",
                "NIST 800-53 SC-8",
                "CIS Controls 13.1"
            ],
            "estimated_effort": "45 minutes"
        },
        
        "telnet": {
            "summary": "Telnet with default credentials - critical exposure",
            "immediate_actions": [
                "Disable Telnet immediately",
                "Replace with SSH",
                "Audit device configurations"
            ],
            "steps": [
                RemediationStep(
                    priority=1,
                    action="Disable Telnet service completely",
                    command="systemctl stop telnetd && systemctl disable telnetd",
                    reference="CIS Benchmark 2.1.1"
                ),
                RemediationStep(
                    priority=1,
                    action="Replace with SSH for remote access",
                    command="apt install openssh-server && systemctl enable ssh",
                    reference="NIST 800-53 SC-8"
                ),
                RemediationStep(
                    priority=2,
                    action="Block Telnet port (23) at firewall",
                    command="ufw deny 23/tcp",
                    reference="CIS Controls 9.4"
                ),
                RemediationStep(
                    priority=3,
                    action="Audit for any remaining Telnet access",
                    command="netstat -tlnp | grep :23",
                    reference="CIS Controls 1.4"
                )
            ],
            "compliance_refs": [
                "PCI DSS 4.1 - Never Use Unencrypted Protocols",
                "CIS Controls 4.8 - Disable Unnecessary Services",
                "NIST 800-53 SC-8"
            ],
            "estimated_effort": "30 minutes"
        }
    }
    
    def __init__(self):
        """Initialize remediation generator."""
        pass
    
    def generate(
        self,
        service: str,
        host: str,
        port: int,
        username: str = "",
        severity: str = "HIGH"
    ) -> RemediationGuide:
        """
        Generate remediation guide for a finding.
        
        Args:
            service: Service type (ssh, http, redis, etc.)
            host: Target host
            port: Target port
            username: Username that worked
            severity: Finding severity
            
        Returns:
            Complete RemediationGuide
        """
        service_lower = service.lower()
        
        if service_lower in self.REMEDIATION_DB:
            template = self.REMEDIATION_DB[service_lower]
            
            return RemediationGuide(
                service=service,
                severity=severity,
                summary=template["summary"],
                immediate_actions=template["immediate_actions"],
                steps=template["steps"],
                compliance_refs=template["compliance_refs"],
                estimated_effort=template["estimated_effort"]
            )
        
        # Generic fallback
        return RemediationGuide(
            service=service,
            severity=severity,
            summary=f"Default credentials found on {service} service",
            immediate_actions=[
                "Change credentials immediately",
                "Review access logs",
                "Audit service configuration"
            ],
            steps=[
                RemediationStep(
                    priority=1,
                    action="Change all default passwords to strong, unique values",
                    reference="NIST 800-63B"
                ),
                RemediationStep(
                    priority=2,
                    action="Implement network segmentation",
                    reference="CIS Controls 12"
                ),
                RemediationStep(
                    priority=3,
                    action="Enable logging and monitoring",
                    reference="PCI DSS 10"
                )
            ],
            compliance_refs=[
                "NIST 800-53 IA-5",
                "PCI DSS 2.1",
                "CIS Controls 4.3"
            ],
            estimated_effort="1 hour"
        )
    
    def to_markdown(self, guide: RemediationGuide) -> str:
        """Convert remediation guide to markdown format."""
        md = []
        md.append(f"# Remediation Guide: {guide.service.upper()}")
        md.append(f"\n**Severity:** {guide.severity}")
        md.append(f"\n**Estimated Effort:** {guide.estimated_effort}")
        md.append(f"\n## Summary\n{guide.summary}")
        
        md.append("\n## Immediate Actions (Do Now)")
        for i, action in enumerate(guide.immediate_actions, 1):
            md.append(f"{i}. ⚠️ {action}")
        
        md.append("\n## Remediation Steps")
        for step in sorted(guide.steps, key=lambda s: s.priority):
            priority_label = ["", "🔴 CRITICAL", "🟠 HIGH", "🟡 MEDIUM", "🔵 LOW", "⚪ INFO"][step.priority]
            md.append(f"\n### {priority_label}: {step.action}")
            if step.command:
                md.append(f"\n```bash\n{step.command}\n```")
            if step.reference:
                md.append(f"\n*Reference: {step.reference}*")
        
        md.append("\n## Compliance References")
        for ref in guide.compliance_refs:
            md.append(f"- {ref}")
        
        return "\n".join(md)


# Module exports
__all__ = ['RemediationGenerator', 'RemediationGuide', 'RemediationStep']
