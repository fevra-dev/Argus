"""
Notification system for Argus.

Supports multi-channel alerting: Slack, Discord, Microsoft Teams, Email.
Enables real-time alerts for critical findings.
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
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
class NotificationConfig:
    """
    Notification channel configuration.
    
    Attributes:
        slack_webhook: Slack incoming webhook URL
        discord_webhook: Discord webhook URL
        teams_webhook: Microsoft Teams webhook URL
        email_smtp_host: SMTP server host
        email_smtp_port: SMTP server port
        email_username: SMTP authentication username
        email_password: SMTP authentication password
        email_from: Sender email address
        email_to: List of recipient email addresses
        email_use_tls: Use TLS encryption
        min_severity: Minimum severity to trigger notifications
    """
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    
    email_smtp_host: Optional[str] = None
    email_smtp_port: int = 587
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    email_from: Optional[str] = None
    email_to: Optional[List[str]] = None
    email_use_tls: bool = True
    
    min_severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW


class NotificationManager:
    """
    Multi-channel notification manager.
    
    Sends scan alerts to configured channels with
    severity filtering and formatted messages.
    
    Usage:
        config = NotificationConfig(
            slack_webhook="https://hooks.slack.com/...",
            min_severity="HIGH"
        )
        notifier = NotificationManager(config)
        notifier.send_scan_alert(scan_result, findings)
    """
    
    SEVERITY_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    
    def __init__(self, config: NotificationConfig):
        """
        Initialize notification manager.
        
        Args:
            config: NotificationConfig with channel details
        """
        self.config = config
        self.min_severity_level = self.SEVERITY_LEVELS.get(config.min_severity, 3)
        
        if HAS_HTTPX:
            self.http_client = httpx.Client(timeout=30.0)
        else:
            self.http_client = None
        
        logger.info("NotificationManager initialized")
    
    def should_notify(self, severity: str) -> bool:
        """Check if severity level warrants notification."""
        level = self.SEVERITY_LEVELS.get(severity.upper(), 0)
        return level >= self.min_severity_level
    
    def send_scan_alert(
        self,
        scan_id: str,
        findings: List[Dict],
        metadata: Dict = None
    ) -> Dict[str, bool]:
        """
        Send scan alerts to all configured channels.
        
        Args:
            scan_id: Unique scan identifier
            findings: List of finding dictionaries
            metadata: Optional scan metadata
            
        Returns:
            Dict with channel names and success status
        """
        # Filter findings by severity
        filtered = [
            f for f in findings
            if self.should_notify(f.get('severity', 'LOW'))
        ]
        
        if not filtered:
            logger.info("No findings meet notification threshold")
            return {"skipped": True}
        
        results = {}
        
        # Send to each configured channel
        if self.config.slack_webhook:
            results['slack'] = self._send_slack(scan_id, filtered, metadata)
        
        if self.config.discord_webhook:
            results['discord'] = self._send_discord(scan_id, filtered, metadata)
        
        if self.config.teams_webhook:
            results['teams'] = self._send_teams(scan_id, filtered, metadata)
        
        if self.config.email_smtp_host and self.config.email_to:
            results['email'] = self._send_email(scan_id, filtered, metadata)
        
        return results
    
    def _send_slack(
        self,
        scan_id: str,
        findings: List[Dict],
        metadata: Dict = None
    ) -> bool:
        """Send Slack notification with rich formatting."""
        try:
            # Count severities
            critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
            high = sum(1 for f in findings if f.get('severity') == 'HIGH')
            
            # Build blocks
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "👁️ Argus Security Alert",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id[:8]}`"},
                        {"type": "mrkdwn", "text": f"*Findings:*\n{len(findings)}"},
                        {"type": "mrkdwn", "text": f"*Critical:*\n{critical}"},
                        {"type": "mrkdwn", "text": f"*High:*\n{high}"}
                    ]
                },
                {"type": "divider"}
            ]
            
            # Add top findings (max 5)
            for finding in findings[:5]:
                severity_emoji = "🔴" if finding.get('severity') == 'CRITICAL' else "🟠"
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{severity_emoji} *{finding.get('host')}:{finding.get('port')}*\n"
                            f"Service: `{finding.get('service')}` | "
                            f"User: `{finding.get('username')}`"
                        )
                    }
                })
            
            payload = {"blocks": blocks}
            
            if HAS_HTTPX:
                response = self.http_client.post(
                    self.config.slack_webhook,
                    json=payload
                )
            else:
                response = requests.post(
                    self.config.slack_webhook,
                    json=payload,
                    timeout=30
                )
            
            success = response.status_code == 200
            logger.info(f"Slack notification: {'sent' if success else 'failed'}")
            return success
            
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False
    
    def _send_discord(
        self,
        scan_id: str,
        findings: List[Dict],
        metadata: Dict = None
    ) -> bool:
        """Send Discord notification with embeds."""
        try:
            critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
            high = sum(1 for f in findings if f.get('severity') == 'HIGH')
            
            # Build embed
            embed = {
                "title": "👁️ Argus Security Alert",
                "color": 0xFF0000 if critical > 0 else 0xFF8C00,
                "timestamp": datetime.utcnow().isoformat(),
                "fields": [
                    {"name": "Scan ID", "value": f"`{scan_id[:8]}`", "inline": True},
                    {"name": "Findings", "value": str(len(findings)), "inline": True},
                    {"name": "Critical", "value": str(critical), "inline": True},
                    {"name": "High", "value": str(high), "inline": True}
                ],
                "footer": {"text": "Argus 2.0 | The All-Seeing Eye"}
            }
            
            # Add top findings to description
            description_lines = []
            for finding in findings[:5]:
                emoji = "🔴" if finding.get('severity') == 'CRITICAL' else "🟠"
                description_lines.append(
                    f"{emoji} **{finding.get('host')}:{finding.get('port')}** - "
                    f"`{finding.get('service')}` ({finding.get('username')})"
                )
            
            embed["description"] = "\n".join(description_lines)
            
            payload = {"embeds": [embed]}
            
            if HAS_HTTPX:
                response = self.http_client.post(
                    self.config.discord_webhook,
                    json=payload
                )
            else:
                response = requests.post(
                    self.config.discord_webhook,
                    json=payload,
                    timeout=30
                )
            
            success = response.status_code in [200, 204]
            logger.info(f"Discord notification: {'sent' if success else 'failed'}")
            return success
            
        except Exception as e:
            logger.error(f"Discord notification failed: {e}")
            return False
    
    def _send_teams(
        self,
        scan_id: str,
        findings: List[Dict],
        metadata: Dict = None
    ) -> bool:
        """Send Microsoft Teams notification with adaptive card."""
        try:
            critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
            high = sum(1 for f in findings if f.get('severity') == 'HIGH')
            
            # Build adaptive card
            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "FF0000" if critical > 0 else "FF8C00",
                "summary": f"Argus Alert: {len(findings)} findings",
                "sections": [{
                    "activityTitle": "👁️ Argus Security Alert",
                    "facts": [
                        {"name": "Scan ID", "value": scan_id[:8]},
                        {"name": "Total Findings", "value": str(len(findings))},
                        {"name": "Critical", "value": str(critical)},
                        {"name": "High", "value": str(high)},
                        {"name": "Time", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    ],
                    "markdown": True
                }]
            }
            
            # Add findings section
            findings_text = "\n".join(
                f"• **{f.get('host')}:{f.get('port')}** - {f.get('service')} ({f.get('severity')})"
                for f in findings[:5]
            )
            
            card["sections"].append({
                "title": "Top Findings",
                "text": findings_text
            })
            
            if HAS_HTTPX:
                response = self.http_client.post(
                    self.config.teams_webhook,
                    json=card
                )
            else:
                response = requests.post(
                    self.config.teams_webhook,
                    json=card,
                    timeout=30
                )
            
            success = response.status_code == 200
            logger.info(f"Teams notification: {'sent' if success else 'failed'}")
            return success
            
        except Exception as e:
            logger.error(f"Teams notification failed: {e}")
            return False
    
    def _send_email(
        self,
        scan_id: str,
        findings: List[Dict],
        metadata: Dict = None
    ) -> bool:
        """Send email notification with HTML formatting."""
        try:
            config = self.config
            critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
            
            # Build HTML email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"👁️ Argus Alert: {len(findings)} Findings ({critical} Critical)"
            msg['From'] = config.email_from
            msg['To'] = ", ".join(config.email_to)
            
            # HTML body
            html = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: 'DM Sans', Arial, sans-serif; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #0a0a0b; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                    .content {{ background: #f5f5f5; padding: 20px; }}
                    .finding {{ background: white; padding: 12px; margin: 8px 0; border-radius: 4px; border-left: 4px solid #ef4444; }}
                    .stats {{ display: flex; gap: 16px; margin: 16px 0; }}
                    .stat {{ background: white; padding: 12px; border-radius: 4px; text-align: center; }}
                    .critical {{ color: #ef4444; font-size: 24px; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>👁️ Argus Security Alert</h1>
                        <p>Scan ID: {scan_id[:8]}</p>
                    </div>
                    <div class="content">
                        <div class="stats">
                            <div class="stat">
                                <div class="critical">{len(findings)}</div>
                                <div>Findings</div>
                            </div>
                            <div class="stat">
                                <div class="critical">{critical}</div>
                                <div>Critical</div>
                            </div>
                        </div>
                        <h3>Top Findings:</h3>
            """
            
            for finding in findings[:10]:
                html += f"""
                        <div class="finding">
                            <strong>{finding.get('host')}:{finding.get('port')}</strong><br>
                            Service: {finding.get('service')} | User: {finding.get('username')}<br>
                            Severity: {finding.get('severity')}
                        </div>
                """
            
            html += """
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            server = smtplib.SMTP(config.email_smtp_host, config.email_smtp_port)
            if config.email_use_tls:
                server.starttls()
            if config.email_username and config.email_password:
                server.login(config.email_username, config.email_password)
            
            server.sendmail(config.email_from, config.email_to, msg.as_string())
            server.quit()
            
            logger.info("Email notification sent")
            return True
            
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return False


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("NotificationManager module loaded")
    print("Supported channels: Slack, Discord, Microsoft Teams, Email")
