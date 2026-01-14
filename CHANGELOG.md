# Changelog

All notable changes to Argus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-14

### Added

- **5 New Protocol Plugins** (14 total protocols now supported!)

  - **VNC Plugin** (ports 5900-5903)
    - RFB protocol implementation
    - DES challenge-response authentication
    - Detects no-auth configurations (critical finding)
    - 16 common VNC passwords
    
  - **Elasticsearch Plugin** (ports 9200, 9300)
    - Detects unauthenticated cluster access
    - X-Pack Security credential testing
    - Cluster info and index enumeration
    - 15 default credential pairs
    
  - **RDP Plugin** (port 3389)
    - X.224/RDP negotiation detection
    - NLA (Network Level Authentication) status check
    - Security configuration analysis
    - 18 Windows default credentials
    
  - **WinRM Plugin** (ports 5985, 5986)
    - HTTP Basic authentication testing
    - NTLM/Negotiate detection
    - WS-Management protocol support
    - 17 Windows/automation account defaults
    
  - **Memcached Plugin** (port 11211)
    - No-auth access detection
    - Server statistics retrieval
    - Key enumeration capability
    - DDoS amplification risk detection

### Changed

- Plugin registry now supports 14 protocols across 25+ ports
- Updated port auto-detection for all new services

---

## [0.2.1] - 2026-01-14

### Added

- **PostgreSQL Plugin** - Full PostgreSQL authentication testing with MD5 and cleartext password support
- **GitHub Actions CI/CD** - Automated testing and security scanning workflow

### Changed

- Renamed workflow file from `credscan.yml` to `argus.yml`
- Updated default port list to include PostgreSQL (5432)

---

## [0.2.0] - 2026-01-14

### Added

- **Intelligence Layer**
  - Real-time CVE enrichment via NIST NVD API 2.0
  - Exploit availability checking via CISA KEV catalog
  - Composite risk scoring with actionable recommendations
  - Version parser for banner analysis

- **Protocol Plugins**
  - SSH credential testing (Paramiko)
  - HTTP/HTTPS Basic Auth testing
  - FTP credential testing
  - Telnet credential testing
  - Redis authentication testing
  - MongoDB authentication testing
  - MySQL authentication testing
  - PostgreSQL authentication testing
  - SNMP community string testing

- **Enterprise Features**
  - REST API (FastAPI) with Swagger documentation
  - Web dashboard with real-time statistics
  - Multi-channel notifications (Slack, Discord, Teams, Email)
  - SIEM integration (Splunk, ELK, Syslog/CEF)
  - Scheduled automated scanning (APScheduler)
  - Account lockout protection

- **Reporting**
  - Professional HTML reports with Chart.js
  - JSON export format
  - CSV export format
  - Executive summary generation
  - MITRE ATT&CK mapping

- **CLI Enhancements**
  - Rich terminal UI with progress bars
  - Colored output with severity indicators
  - CVE enrichment flags
  - Multiple output format options

- **Deployment**
  - Docker containerization
  - Docker Compose full-stack deployment
  - Nginx reverse proxy configuration

### Technical

- Async scanning with asyncio/aiohttp
- Concurrent credential testing
- Modular plugin architecture
- Comprehensive logging
- Type hints throughout codebase

## [0.1.0] - Initial Development

### Added

- Basic credential scanning functionality
- SSH, HTTP, FTP, Telnet plugins
- Default credential database
- Console, JSON, CSV reporters
- Network discovery module

---

## Roadmap

### [0.3.0] - Planned

- [ ] LDAP/Active Directory plugin
- [ ] SMB/CIFS plugin
- [ ] Async credential testing improvements
- [ ] Web dashboard enhancements
- [ ] Plugin marketplace concept

### [1.0.0] - Future

- [ ] Stable API
- [ ] Comprehensive documentation
- [ ] PyPI publication
- [ ] Docker Hub images

---

[0.3.0]: https://github.com/fevra-dev/Argus/releases/tag/v0.3.0
[0.2.1]: https://github.com/fevra-dev/Argus/releases/tag/v0.2.1
[0.2.0]: https://github.com/fevra-dev/Argus/releases/tag/v0.2.0
[0.1.0]: https://github.com/fevra-dev/Argus/releases/tag/v0.1.0
