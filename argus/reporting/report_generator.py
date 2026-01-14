"""
Professional HTML report generator with interactive charts.

Generates executive-ready security reports with Chart.js
visualizations, severity breakdowns, and remediation guidance.
"""

from datetime import datetime
from typing import List, Dict, Optional
from jinja2 import Template
import json
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate professional security reports in multiple formats.
    
    Produces visually appealing HTML reports with:
    - Interactive Chart.js visualizations
    - Severity distribution doughnut charts
    - Service breakdown bar charts
    - Detailed findings tables
    - Remediation recommendations
    - MITRE ATT&CK mapping
    """
    
    # Modern, professional HTML template
    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Lora:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0b;
            --bg-secondary: #111113;
            --bg-card: #18181b;
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --accent: #22d3ee;
            --accent-dim: rgba(34, 211, 238, 0.1);
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --border: #27272a;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 24px;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-secondary) 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 48px;
            margin-bottom: 32px;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent), var(--critical), var(--accent));
        }
        
        .header h1 {
            font-family: 'Lora', serif;
            font-size: 2.5rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .header .subtitle {
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 400;
        }
        
        .header .meta {
            display: flex;
            gap: 24px;
            margin-top: 16px;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        /* Alert Banner */
        .alert {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-left: 4px solid var(--critical);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 32px;
        }
        
        .alert-title {
            color: var(--critical);
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .alert p {
            color: var(--text-secondary);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            transition: transform 0.2s, border-color 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent);
        }
        
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 4px;
            font-family: 'Lora', serif;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-card.critical .value { color: var(--critical); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.success .value { color: var(--low); }
        .stat-card.info .value { color: var(--accent); }
        
        /* Content Sections */
        .content-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 32px;
        }
        
        .section-title {
            font-family: 'Lora', serif;
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        /* Charts */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 32px;
            margin-bottom: 24px;
        }
        
        .chart-container {
            position: relative;
            height: 320px;
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: var(--bg-secondary);
        }
        
        th {
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border);
        }
        
        td {
            padding: 16px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }
        
        tbody tr:hover {
            background: var(--bg-secondary);
        }
        
        /* Badges */
        .severity-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-critical {
            background: rgba(239, 68, 68, 0.15);
            color: var(--critical);
        }
        
        .severity-high {
            background: rgba(249, 115, 22, 0.15);
            color: var(--high);
        }
        
        .severity-medium {
            background: rgba(234, 179, 8, 0.15);
            color: var(--medium);
        }
        
        .severity-low {
            background: rgba(34, 197, 94, 0.15);
            color: var(--low);
        }
        
        .credential {
            font-family: 'SF Mono', 'Fira Code', monospace;
            background: var(--bg-secondary);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            color: var(--accent);
        }
        
        /* Recommendations */
        .recommendations {
            background: rgba(34, 211, 238, 0.05);
            border: 1px solid rgba(34, 211, 238, 0.2);
            border-radius: 12px;
            padding: 24px;
            margin-top: 32px;
        }
        
        .recommendations h3 {
            color: var(--accent);
            font-size: 1.1rem;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .recommendations ul {
            list-style: none;
            padding: 0;
        }
        
        .recommendations li {
            padding: 8px 0;
            padding-left: 24px;
            position: relative;
            color: var(--text-secondary);
        }
        
        .recommendations li::before {
            content: '→';
            position: absolute;
            left: 0;
            color: var(--accent);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            color: var(--text-secondary);
            padding: 32px;
            font-size: 0.875rem;
        }
        
        .footer .mitre {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-card);
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-top: 16px;
        }
        
        /* Intelligence Section */
        .intel-card {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(249, 115, 22, 0.05));
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }
        
        .intel-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
        }
        
        .intel-item {
            text-align: center;
        }
        
        .intel-item .value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .intel-item .label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }
        
        .kev-warning {
            background: rgba(239, 68, 68, 0.15);
            color: var(--critical);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👁️ Argus Security Report</h1>
            <p class="subtitle">Default Credential Assessment & Vulnerability Intelligence</p>
            <div class="meta">
                <span>📅 {{ scan_date }}</span>
                <span>⏱️ Duration: {{ duration }}s</span>
                <span>🎯 {{ total_hosts }} hosts scanned</span>
            </div>
        </div>
        
        {% if critical_count > 0 or (intel_report and intel_report.vulnerabilities.actively_exploited_cves > 0) %}
        <div class="alert">
            <div class="alert-title">⚠️ Critical Security Issues Detected</div>
            <p>
                {% if intel_report and intel_report.vulnerabilities.actively_exploited_cves > 0 %}
                {{ intel_report.vulnerabilities.actively_exploited_cves }} actively exploited vulnerabilities (CISA KEV) and
                {% endif %}
                {{ critical_count }} critical findings require immediate attention. Default credentials provide unauthorized access to systems.
            </p>
        </div>
        {% endif %}
        
        <div class="stats-grid">
            <div class="stat-card info">
                <div class="value">{{ total_hosts }}</div>
                <div class="label">Hosts Scanned</div>
            </div>
            <div class="stat-card {% if vulnerable_hosts > 0 %}high{% else %}success{% endif %}">
                <div class="value">{{ vulnerable_hosts }}</div>
                <div class="label">Vulnerable Hosts</div>
            </div>
            <div class="stat-card {% if critical_count > 0 %}critical{% else %}success{% endif %}">
                <div class="value">{{ critical_count }}</div>
                <div class="label">Critical Findings</div>
            </div>
            <div class="stat-card {% if high_count > 0 %}high{% else %}success{% endif %}">
                <div class="value">{{ high_count }}</div>
                <div class="label">High Findings</div>
            </div>
        </div>
        
        {% if intel_report %}
        <div class="content-section">
            <h2 class="section-title">🧠 Intelligence Assessment</h2>
            <div class="intel-card">
                <div class="intel-grid">
                    <div class="intel-item">
                        <div class="value">{{ intel_report.vulnerabilities.total_cves }}</div>
                        <div class="label">Total CVEs</div>
                    </div>
                    <div class="intel-item">
                        <div class="value" style="color: var(--critical)">{{ intel_report.vulnerabilities.critical_cves }}</div>
                        <div class="label">Critical CVEs</div>
                    </div>
                    <div class="intel-item">
                        <div class="value" style="color: var(--high)">{{ intel_report.vulnerabilities.exploitable_cves }}</div>
                        <div class="label">Exploitable</div>
                    </div>
                    <div class="intel-item">
                        <div class="value" style="color: var(--critical)">{{ intel_report.vulnerabilities.actively_exploited_cves }}</div>
                        <div class="label">CISA KEV ⚠️</div>
                    </div>
                </div>
            </div>
            {% if intel_report.risk_assessment.requires_immediate_action %}
            <p style="color: var(--critical); font-weight: 600;">
                ⚡ IMMEDIATE ACTION REQUIRED: Actively exploited vulnerabilities detected
            </p>
            {% endif %}
        </div>
        {% endif %}
        
        <div class="content-section">
            <h2 class="section-title">📊 Vulnerability Distribution</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-container">
                    <canvas id="servicesChart"></canvas>
                </div>
            </div>
        </div>
        
        {% if findings %}
        <div class="content-section">
            <h2 class="section-title">🔍 Detailed Findings ({{ findings|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Credentials</th>
                        <th>Severity</th>
                        <th>Access</th>
                        {% if intel_report %}<th>Risk</th>{% endif %}
                    </tr>
                </thead>
                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td>{{ finding.host }}</td>
                        <td>{{ finding.port }}</td>
                        <td>{{ finding.service }}</td>
                        <td>
                            <span class="credential">{{ finding.username }}</span>
                            <span style="color: var(--text-secondary)">:</span>
                            <span class="credential">{{ finding.password }}</span>
                        </td>
                        <td>
                            <span class="severity-badge severity-{{ finding.severity|lower }}">
                                {{ finding.severity }}
                            </span>
                        </td>
                        <td>{{ finding.access_level }}</td>
                        {% if intel_report and finding.risk_score %}
                        <td>
                            <strong style="color: {% if finding.risk_score >= 9 %}var(--critical){% elif finding.risk_score >= 7 %}var(--high){% else %}var(--medium){% endif %}">
                                {{ finding.risk_score }}/10
                            </strong>
                        </td>
                        {% endif %}
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        <div class="recommendations">
            <h3>🔒 Remediation Recommendations</h3>
            <ul>
                <li><strong>Immediate:</strong> Change all default credentials to strong, unique passwords</li>
                <li><strong>Within 24h:</strong> Implement password complexity (12+ chars, mixed case, numbers, symbols)</li>
                <li><strong>Within 1 week:</strong> Enable multi-factor authentication (MFA) on all critical services</li>
                <li><strong>Ongoing:</strong> Implement automated credential rotation every 90 days</li>
                <li><strong>Monitoring:</strong> Set up alerts for failed authentication attempts</li>
                {% if intel_report and intel_report.vulnerabilities.actively_exploited_cves > 0 %}
                <li><strong style="color: var(--critical)">CRITICAL:</strong> Patch or isolate systems with CISA KEV vulnerabilities immediately</li>
                {% endif %}
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Argus v0.2.1 | The All-Seeing Eye</p>
            <div class="mitre">
                <span>MITRE ATT&CK:</span>
                <strong>T1078.001</strong>
                <span>(Default Accounts)</span>
            </div>
        </div>
    </div>
    
    <script>
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#a1a1aa',
                        padding: 16,
                        font: { size: 12, family: 'DM Sans' }
                    }
                }
            }
        };
        
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [{{ critical_count }}, {{ high_count }}, {{ medium_count }}, {{ low_count }}],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                    borderWidth: 0,
                    cutout: '65%'
                }]
            },
            options: {
                ...chartOptions,
                plugins: {
                    ...chartOptions.plugins,
                    title: {
                        display: true,
                        text: 'Findings by Severity',
                        color: '#fafafa',
                        font: { size: 16, family: 'Lora', weight: 600 }
                    }
                }
            }
        });
        
        // Services Chart
        new Chart(document.getElementById('servicesChart'), {
            type: 'bar',
            data: {
                labels: {{ service_labels | tojson }},
                datasets: [{
                    label: 'Vulnerable Instances',
                    data: {{ service_counts | tojson }},
                    backgroundColor: 'rgba(34, 211, 238, 0.6)',
                    borderColor: '#22d3ee',
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                ...chartOptions,
                plugins: {
                    ...chartOptions.plugins,
                    legend: { display: false },
                    title: {
                        display: true,
                        text: 'Vulnerable Services',
                        color: '#fafafa',
                        font: { size: 16, family: 'Lora', weight: 600 }
                    }
                },
                scales: {
                    x: {
                        grid: { color: '#27272a' },
                        ticks: { color: '#a1a1aa' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: '#27272a' },
                        ticks: { color: '#a1a1aa', stepSize: 1 }
                    }
                }
            }
        });
    </script>
</body>
</html>'''
    
    def generate_html_report(
        self, 
        scan_result, 
        output_file: str,
        enriched_findings: List[Dict] = None,
        intelligence_report: Dict = None
    ):
        """
        Generate professional HTML report with charts.
        
        Args:
            scan_result: ScanResult object from scanner
            output_file: Path to write HTML file
            enriched_findings: Optional list of findings with intelligence data
            intelligence_report: Optional intelligence summary report
        """
        # Build findings list
        findings_list = []
        for i, f in enumerate(scan_result.findings):
            finding_data = {
                'host': f.host,
                'port': f.port,
                'service': f.service.value,
                'username': f.username,
                'password': f.password,
                'severity': f.severity.value,
                'access_level': f.access_level
            }
            
            # Add risk score if available
            if enriched_findings and i < len(enriched_findings):
                intel = enriched_findings[i].get('intelligence', {})
                if isinstance(intel, dict):
                    finding_data['risk_score'] = intel.get('risk_score')
                else:
                    finding_data['risk_score'] = getattr(intel, 'risk_score', None)
            
            findings_list.append(finding_data)
        
        # Count by service
        service_counts = {}
        for f in scan_result.findings:
            svc = f.service.value.upper()
            service_counts[svc] = service_counts.get(svc, 0) + 1
        
        # Template data
        template_data = {
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_end': scan_result.scan_end,
            'duration': f"{scan_result.scan_duration_ms / 1000:.2f}",
            'total_hosts': scan_result.hosts_scanned,
            'vulnerable_hosts': scan_result.hosts_with_findings,
            'total_findings': scan_result.total_findings,
            'critical_count': scan_result.critical_count,
            'high_count': scan_result.high_count,
            'medium_count': sum(1 for f in scan_result.findings if f.severity.value == "MEDIUM"),
            'low_count': sum(1 for f in scan_result.findings if f.severity.value == "LOW"),
            'findings': findings_list,
            'service_labels': list(service_counts.keys()),
            'service_counts': list(service_counts.values()),
            'intel_report': intelligence_report
        }
        
        # Render template
        template = Template(self.HTML_TEMPLATE)
        html = template.render(**template_data)
        
        # Write file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"HTML report generated: {output_file}")
    
    def generate_executive_summary(self, scan_result, intelligence_report: Dict = None) -> str:
        """
        Generate markdown executive summary for stakeholders.
        
        Args:
            scan_result: ScanResult object
            intelligence_report: Optional intelligence data
            
        Returns:
            Markdown-formatted executive summary
        """
        summary = f"""# Executive Summary - Argus Security Assessment

**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Duration**: {scan_result.scan_duration_ms / 1000:.2f} seconds
**Tool**: Argus v0.2.1 - The All-Seeing Eye

## Overview

This assessment identified default credential vulnerabilities across the target network. 
Default credentials represent a critical security risk as they provide unauthorized access 
to systems and are frequently exploited by threat actors.

### Scan Statistics

| Metric | Value |
|--------|-------|
| Hosts Scanned | {scan_result.hosts_scanned} |
| Vulnerable Hosts | {scan_result.hosts_with_findings} |
| Total Findings | {scan_result.total_findings} |
| Critical Findings | {scan_result.critical_count} |
| High Findings | {scan_result.high_count} |

"""
        
        if intelligence_report:
            vulns = intelligence_report.get('vulnerabilities', {})
            summary += f"""
### Intelligence Summary

| Metric | Value |
|--------|-------|
| Total CVEs Found | {vulns.get('total_cves', 0)} |
| Critical CVEs | {vulns.get('critical_cves', 0)} |
| Exploitable CVEs | {vulns.get('exploitable_cves', 0)} |
| CISA KEV (Actively Exploited) | {vulns.get('actively_exploited_cves', 0)} |

"""
            if vulns.get('actively_exploited_cves', 0) > 0:
                summary += """
> ⚠️ **CRITICAL WARNING**: Actively exploited vulnerabilities detected. 
> These vulnerabilities are being exploited in the wild according to CISA's 
> Known Exploited Vulnerabilities catalog. Immediate action required.

"""
        
        summary += """
## Risk Assessment

"""
        
        if scan_result.critical_count > 0:
            summary += f"""### 🔴 CRITICAL RISK
**{scan_result.critical_count} critical vulnerabilities** provide administrative access to systems. 
These must be remediated immediately (within 24 hours).

"""
        
        if scan_result.high_count > 0:
            summary += f"""### 🟠 HIGH RISK
**{scan_result.high_count} high-risk vulnerabilities** provide user-level access. 
These should be remediated within 7 days.

"""
        
        summary += """## Remediation Timeline

### Immediate Actions (0-24 hours)
1. **Change all default credentials** identified in this report
2. **Disable or isolate** critically vulnerable systems until remediated
3. **Review access logs** for signs of unauthorized access

### Short-term Actions (1-7 days)
1. Implement **password complexity requirements**: 12+ characters, mixed case, numbers, symbols
2. Enable **multi-factor authentication (MFA)** on all administrative interfaces
3. Conduct **credential audit** across all network devices

### Long-term Actions (1-3 months)
1. Implement **automated credential rotation** every 90 days
2. Deploy **privileged access management (PAM)** solution
3. Establish **continuous monitoring** for default credentials

## MITRE ATT&CK Mapping

- **T1078.001**: Valid Accounts - Default Accounts
- **T1110**: Brute Force

## Compliance Impact

Default credentials violate multiple compliance frameworks:
- **PCI DSS**: Requirements 2.1, 8.2
- **NIST CSF**: PR.AC-1, PR.AC-7
- **CIS Controls**: Controls 4, 5, 16
- **ISO 27001**: A.9.2.1, A.9.4.3

---

*Report generated by Argus v0.2.1 - For authorized security testing only*
"""
        
        return summary


# Module self-test
if __name__ == "__main__":
    print("ReportGenerator module loaded successfully")
    print("Use generate_html_report() to create reports")
