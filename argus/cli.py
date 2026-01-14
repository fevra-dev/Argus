"""
Argus 0.2.0 - Enhanced CLI with Rich Terminal UI.

Professional command-line interface with:
- Beautiful Rich terminal output
- Live progress bars and spinners
- Colored tables and formatted results
- CVE intelligence integration
- HTML report generation
"""

import sys
import click
import logging
from typing import Optional, List
from datetime import datetime
from pathlib import Path

# Rich UI imports
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich import box

from . import __version__
from .scanner import ArgusScanner
from .models import ScanResult, Severity
from .reporters import ConsoleReporter, JSONReporter, CSVReporter

# Initialize Rich console
console = Console()

# Configure logging
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool, quiet: bool):
    """Configure logging based on verbosity settings."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def show_banner():
    """Display the Argus banner with Rich formatting."""
    banner_text = """
    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
   ███████║██████╔╝██║  ███╗██║   ██║███████╗
   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
    """
    
    version_text = f"v{__version__} • Intelligence-Driven Security Scanner"
    tagline = "The All-Seeing Eye • MITRE ATT&CK: T1078.001"
    
    console.print(Panel(
        Text.from_markup(
            f"[cyan]{banner_text}[/cyan]\n"
            f"[dim]{version_text}[/dim]\n"
            f"[dim]{tagline}[/dim]"
        ),
        border_style="cyan",
        box=box.DOUBLE_EDGE
    ))


def create_results_table(result: ScanResult, show_creds: bool = True) -> Table:
    """Create a Rich table for displaying scan results."""
    table = Table(
        title="🔍 Scan Findings",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim"
    )
    
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right", style="green")
    table.add_column("Service", style="blue")
    if show_creds:
        table.add_column("Username", style="yellow")
        table.add_column("Password", style="yellow")
    table.add_column("Severity", justify="center")
    table.add_column("Access", style="dim")
    
    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "yellow",
        "LOW": "green"
    }
    
    for finding in result.findings:
        severity = finding.severity.value
        sev_style = severity_styles.get(severity, "white")
        
        row = [
            finding.host,
            str(finding.port),
            finding.service.value.upper(),
        ]
        
        if show_creds:
            row.extend([finding.username, finding.password])
        
        row.extend([
            Text(severity, style=sev_style),
            finding.access_level
        ])
        
        table.add_row(*row)
    
    return table


def create_stats_panel(result: ScanResult) -> Panel:
    """Create a statistics panel for the scan results."""
    stats = Text()
    stats.append("Hosts Scanned: ", style="dim")
    stats.append(f"{result.hosts_scanned}\n", style="cyan bold")
    stats.append("Vulnerable Hosts: ", style="dim")
    stats.append(f"{result.hosts_with_findings}\n", style="yellow bold" if result.hosts_with_findings else "green bold")
    stats.append("Total Findings: ", style="dim")
    stats.append(f"{result.total_findings}\n", style="red bold" if result.total_findings else "green bold")
    stats.append("Critical: ", style="dim")
    stats.append(f"{result.critical_count} ", style="red bold")
    stats.append("High: ", style="dim")
    stats.append(f"{result.high_count}\n", style="orange1 bold")
    stats.append("Duration: ", style="dim")
    stats.append(f"{result.scan_duration_ms / 1000:.2f}s", style="cyan")
    
    return Panel(
        stats,
        title="📊 Scan Statistics",
        border_style="cyan",
        box=box.ROUNDED
    )


def enrich_with_intelligence(
    result: ScanResult,
    nvd_api_key: Optional[str],
    check_exploits: bool
) -> tuple:
    """Enrich findings with CVE intelligence."""
    try:
        from .intel.intelligence_engine import IntelligenceEngine
        
        console.print("\n[cyan]🧠 Enriching findings with CVE intelligence...[/cyan]")
        
        engine = IntelligenceEngine(
            nvd_api_key=nvd_api_key,
            enable_exploit_check=check_exploits
        )
        
        enriched_findings = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                "Analyzing vulnerabilities...",
                total=len(result.findings)
            )
            
            for finding in result.findings:
                banner = getattr(finding, 'banner', '')
                intelligence = engine.analyze_finding(finding, banner)
                
                enriched_findings.append({
                    'finding': finding,
                    'intelligence': intelligence.to_dict() if hasattr(intelligence, 'to_dict') else intelligence
                })
                
                progress.advance(task)
        
        # Generate intelligence report
        intel_report = engine.generate_intelligence_report(enriched_findings)
        
        # Display intelligence summary
        vulns = intel_report.get('vulnerabilities', {})
        console.print(Panel(
            Text.from_markup(
                f"[bold]CVE Analysis Complete[/bold]\n\n"
                f"Total CVEs Found: [cyan]{vulns.get('total_cves', 0)}[/cyan]\n"
                f"Critical CVEs: [red]{vulns.get('critical_cves', 0)}[/red]\n"
                f"Exploitable: [orange1]{vulns.get('exploitable_cves', 0)}[/orange1]\n"
                f"CISA KEV: [red bold]{vulns.get('actively_exploited_cves', 0)}[/red bold]"
                + (" ⚠️" if vulns.get('actively_exploited_cves', 0) > 0 else "")
            ),
            title="🧠 Intelligence Summary",
            border_style="magenta"
        ))
        
        return enriched_findings, intel_report
        
    except ImportError as e:
        console.print(f"[yellow]Warning: Intelligence module not available: {e}[/yellow]")
        return None, None
    except Exception as e:
        console.print(f"[red]Error during intelligence enrichment: {e}[/red]")
        return None, None


def generate_html_report(
    result: ScanResult,
    output_file: str,
    enriched_findings: List = None,
    intel_report: dict = None
):
    """Generate HTML report with optional intelligence data."""
    try:
        from .reporting.report_generator import ReportGenerator
        
        generator = ReportGenerator()
        generator.generate_html_report(
            result,
            output_file,
            enriched_findings=enriched_findings,
            intelligence_report=intel_report
        )
        
        console.print(f"\n[green]✓[/green] HTML report saved: [cyan]{output_file}[/cyan]")
        
    except ImportError as e:
        console.print(f"[red]Error: Report generator not available: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error generating HTML report: {e}[/red]")


@click.command()
@click.argument('targets', nargs=-1)
@click.option('-f', '--file', 'target_file', type=click.Path(exists=True),
              help='File with targets (one per line)')
@click.option('-p', '--ports', default="22,23,21,80,443,8080",
              help='Ports to scan (comma-separated)')
@click.option('-t', '--threads', default=10, type=int,
              help='Concurrent threads (default: 10)')
@click.option('--timeout', default=5, type=int,
              help='Connection timeout in seconds (default: 5)')
@click.option('-o', '--output', 'output_format',
              type=click.Choice(['console', 'json', 'csv', 'html']),
              default='console', help='Output format')
@click.option('--out-file', type=click.Path(),
              help='Output file path')
@click.option('--creds-file', type=click.Path(exists=True),
              help='Custom credentials file (JSON)')
@click.option('--async-scan', is_flag=True,
              help='Use async scanning (3-5x faster)')
@click.option('--enrich-cves', is_flag=True,
              help='Enable CVE enrichment from NVD')
@click.option('--nvd-api-key', envvar='NVD_API_KEY',
              help='NVD API key for faster CVE lookups')
@click.option('--check-exploits', is_flag=True,
              help='Check CISA KEV for known exploits')
@click.option('--stop-on-success/--no-stop-on-success', default=True,
              help='Stop after first success per host')
@click.option('--no-banner', is_flag=True,
              help='Skip banner grabbing')
@click.option('--no-ui', is_flag=True,
              help='Disable Rich UI (plain output)')
@click.option('-q', '--quiet', is_flag=True,
              help='Only show findings')
@click.option('-v', '--verbose', is_flag=True,
              help='Verbose logging')
@click.option('--version', is_flag=True,
              help='Show version and exit')
def main(
    targets,
    target_file,
    ports,
    threads,
    timeout,
    output_format,
    out_file,
    creds_file,
    async_scan,
    enrich_cves,
    nvd_api_key,
    check_exploits,
    stop_on_success,
    no_banner,
    no_ui,
    quiet,
    verbose,
    version
):
    """
    Argus - Intelligence-Driven Security Scanner.
    
    Named after the all-seeing giant from Greek mythology, Argus scans
    network devices for default and weak credentials, enriched with
    real-time vulnerability intelligence from NIST NVD.
    
    Examples:
    
        argus 192.168.1.0/24
        
        argus 192.168.1.1 --enrich-cves --check-exploits
        
        argus 192.168.1.0/24 -o html --out-file report.html
    """
    
    # Handle version flag
    if version:
        click.echo(f"Argus v{__version__}")
        sys.exit(0)
    
    # Setup logging
    setup_logging(verbose, quiet)
    
    # Show banner unless quiet or no-ui
    if not quiet and not no_ui:
        show_banner()
    
    # Collect targets
    target_list = list(targets)
    if target_file:
        with open(target_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    target_list.append(line)
    
    if not target_list:
        console.print("[red]Error: No targets specified[/red]")
        console.print("Usage: argus [OPTIONS] [TARGETS]...")
        console.print("Try 'argus --help' for help.")
        sys.exit(2)
    
    # Parse ports
    port_list = [int(p.strip()) for p in ports.split(',')]
    
    # Display scan configuration
    if not quiet and not no_ui:
        console.print(Panel(
            f"[bold]Targets:[/bold] {len(target_list)} host(s)\n"
            f"[bold]Ports:[/bold] {ports}\n"
            f"[bold]Threads:[/bold] {threads}\n"
            f"[bold]CVE Enrichment:[/bold] {'Enabled' if enrich_cves else 'Disabled'}\n"
            f"[bold]Exploit Check:[/bold] {'Enabled' if check_exploits else 'Disabled'}",
            title="⚙️ Scan Configuration",
            border_style="dim"
        ))
    
    # Create scanner
    scanner = ArgusScanner(
        threads=threads,
        timeout=timeout,
        creds_file=creds_file,
        stop_on_success=stop_on_success,
        grab_banners=not no_banner
    )
    
    # Run scan with progress
    try:
        if not quiet and not no_ui:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Scanning network...", total=100)
                
                # Simulate progress during scan
                progress.update(task, completed=10)
                result = scanner.scan(target_list, port_list)
                progress.update(task, completed=100)
        else:
            result = scanner.scan(target_list, port_list)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(2)
    
    # Enrich with CVE intelligence if requested
    enriched_findings = None
    intel_report = None
    
    if enrich_cves and result.findings:
        enriched_findings, intel_report = enrich_with_intelligence(
            result,
            nvd_api_key,
            check_exploits
        )
    
    # Generate output
    if output_format == 'html':
        if not out_file:
            out_file = f"argus_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        generate_html_report(result, out_file, enriched_findings, intel_report)
        
    elif output_format == 'json':
        reporter = JSONReporter()
        output_str = reporter.generate(result)
        if out_file:
            with open(out_file, 'w') as f:
                f.write(output_str)
            console.print(f"\n[green]✓[/green] JSON saved: [cyan]{out_file}[/cyan]")
        else:
            click.echo(output_str)
            
    elif output_format == 'csv':
        reporter = CSVReporter()
        output_str = reporter.generate(result)
        if out_file:
            with open(out_file, 'w') as f:
                f.write(output_str)
            console.print(f"\n[green]✓[/green] CSV saved: [cyan]{out_file}[/cyan]")
        else:
            click.echo(output_str)
            
    else:  # console output
        if not quiet and not no_ui:
            # Display results with Rich
            console.print()
            console.print(create_stats_panel(result))
            
            if result.findings:
                console.print()
                console.print(create_results_table(result))
                
                # Show warning for critical findings
                if result.critical_count > 0:
                    console.print(Panel(
                        f"[red bold]⚠️ {result.critical_count} CRITICAL[/red bold] findings "
                        "require immediate attention!\nChange default credentials now.",
                        border_style="red"
                    ))
            else:
                console.print("\n[green]✓ No default credentials found[/green]")
        else:
            # Plain output for CI/CD
            reporter = ConsoleReporter(quiet=quiet, verbose=verbose)
            click.echo(reporter.generate(result))
    
    # Save to file if specified (for non-file formats)
    if out_file and output_format == 'console':
        reporter = ConsoleReporter(quiet=False, verbose=verbose)
        with open(out_file, 'w') as f:
            f.write(reporter.generate(result))
        console.print(f"\n[green]✓[/green] Results saved: [cyan]{out_file}[/cyan]")
    
    # Exit with appropriate code
    if result.total_findings > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
