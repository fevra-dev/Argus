"""Console output reporter."""

import click
from ..models import ScanResult, Severity


class ConsoleReporter:
    def __init__(self, quiet: bool = False, verbose: bool = False):
        self.quiet = quiet
        self.verbose = verbose
    
    def generate(self, result: ScanResult) -> str:
        lines = []
        
        if not self.quiet:
            lines.append("")
            lines.append("╔══════════════════════════════════════════════════════════════╗")
            lines.append("║  Argus - Default Credential Scanner                       ║")
            lines.append("╚══════════════════════════════════════════════════════════════╝")
            lines.append("")
            lines.append(f"Hosts scanned: {result.hosts_scanned}")
            lines.append(f"Duration: {result.scan_duration_ms / 1000:.2f}s")
            lines.append("")
        
        if result.findings:
            lines.append(click.style(
                f"⚠️  {len(result.findings)} CREDENTIALS FOUND:",
                fg="red", bold=True
            ))
            lines.append("")
            
            for finding in result.findings:
                severity_color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green"
                }.get(finding.severity, "white")
                
                sev = click.style(f"[{finding.severity.value}]", fg=severity_color, bold=True)
                
                lines.append(f"  {sev} {finding.host}:{finding.port} ({finding.service.value})")
                lines.append(f"      Username: {finding.username}")
                lines.append(f"      Password: {finding.password}")
                lines.append(f"      Access:   {finding.access_level}")
                if finding.banner:
                    lines.append(f"      Banner:   {finding.banner[:50]}")
                lines.append("")
        else:
            lines.append(click.style("✓ No default credentials found", fg="green"))
        
        return "\n".join(lines)

