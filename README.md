# 👁️ Argus - The All-Seeing Eye

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.2.1-green.svg)](https://github.com/fevra-dev/Argus/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-tool-orange.svg)](SECURITY.md)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1078.001-red.svg)](https://attack.mitre.org/techniques/T1078/001/)

**Intelligence-Driven Security Scanner** • Named after Argus Panoptes, the all-seeing giant with 100 eyes from Greek mythology.

Argus is an enterprise-grade security scanner that identifies default credentials and vulnerabilities across network infrastructure. It combines high-performance async scanning with real-time threat intelligence from NIST NVD and CISA KEV.

**🔒 For authorized security testing only.**

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🚀 **Async Scanning** | 3-5x faster with concurrent I/O operations |
| 🧠 **CVE Intelligence** | Real-time enrichment via NIST NVD API |
| ⚠️ **Exploit Detection** | CISA KEV integration for actively exploited vulns |
| 📊 **Rich Reports** | Interactive HTML reports with Chart.js |
| 🌐 **REST API** | FastAPI backend with Swagger docs |
| 🔔 **Notifications** | Slack, Discord, Email, Teams integration |
| 📈 **SIEM Ready** | Splunk, ELK, Syslog/CEF export |
| 🐳 **Containerized** | Docker & Kubernetes deployment |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone git@github.com:fevra-dev/Argus.git
cd Argus

# Install in development mode
pip install -e .

# Or with all dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a single host
argus 192.168.1.1

# Scan a CIDR range
argus 192.168.1.0/24

# Scan with CVE enrichment
argus 192.168.1.0/24 --enrich-cves --check-exploits

# Generate HTML report
argus 192.168.1.0/24 -o html --out-file report.html

# Scan specific ports
argus 192.168.1.1 -p 22,80,443,3306,6379
```

### API Server

```bash
# Start the REST API
argus api

# Or with uvicorn directly
uvicorn argus.api.server:app --reload --port 8000

# Access Swagger docs at http://localhost:8000/api/docs
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access dashboard at http://localhost
# API available at http://localhost:8000
```

---

## 📖 Command Reference

```
Usage: argus [OPTIONS] [TARGETS]...

Options:
  -f, --file PATH          File with targets (one per line)
  -p, --ports TEXT         Ports to scan [default: 22,23,21,80,443,8080]
  -t, --threads INT        Concurrent threads [default: 10]
  --timeout INT            Connection timeout in seconds [default: 5]
  -o, --output FORMAT      Output format: console, json, csv, html
  --out-file PATH          Write output to file
  --creds-file PATH        Custom credentials file (JSON)
  --async-scan             Use async scanning (3-5x faster)
  --enrich-cves            Enable CVE enrichment from NVD
  --nvd-api-key TEXT       NVD API key for faster lookups
  --check-exploits         Check CISA KEV for known exploits
  --stop-on-success        Stop testing after first success per host
  --no-banner              Skip banner grabbing
  --no-ui                  Disable Rich UI (for CI/CD)
  -q, --quiet              Only show findings
  -v, --verbose            Verbose logging
  --version                Show version and exit
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No credentials found |
| 1 | Credentials found |
| 2 | Error during execution |

---

## 🔌 Supported Protocols

| Protocol | Port(s) | Library |
|----------|---------|---------|
| SSH | 22 | Paramiko |
| HTTP/HTTPS | 80, 443, 8080, 8443 | Requests/aiohttp |
| FTP | 21 | ftplib |
| Telnet | 23 | telnetlib |
| Redis | 6379 | redis-py |
| MongoDB | 27017 | pymongo |
| MySQL | 3306 | mysql-connector |
| SNMP | 161 | pysnmp |

---

## 🧠 Intelligence Layer

Argus enriches findings with real-time threat intelligence:

### CVE Mapping
- Queries NIST NVD API 2.0 for known vulnerabilities
- Parses service banners to identify product versions
- Provides CVSS scores and severity ratings

### Exploit Detection
- Checks CISA Known Exploited Vulnerabilities (KEV) catalog
- Identifies actively exploited CVEs requiring immediate action
- Calculates composite risk scores

### Example Output

```
┌─────────────────────────────────────────────────┐
│ 🧠 Intelligence Summary                         │
├─────────────────────────────────────────────────┤
│ Total CVEs Found: 12                            │
│ Critical CVEs: 3                                │
│ Exploitable: 5                                  │
│ CISA KEV: 2 ⚠️                                  │
└─────────────────────────────────────────────────┘
```

---

## 🌐 REST API

### Create Scan
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "ports": [22, 80, 443],
    "enrich_cves": true,
    "check_exploits": true
  }'
```

### Check Status
```bash
curl http://localhost:8000/api/scans/{scan_id}
```

### Get Statistics
```bash
curl http://localhost:8000/api/stats
```

---

## ⚠️ Legal and Ethical Notice

**This tool is for AUTHORIZED testing only.**

### Permitted Use (Canada/US)
- ✅ Your own networks and devices
- ✅ Systems with explicit written authorization
- ✅ Dedicated lab/testing environments

### Prohibited Use
- ❌ Networks/systems you don't own
- ❌ Systems without written permission
- ❌ Any unauthorized access attempts

### Legal Context (Canada)
Under Canadian law (Criminal Code Section 342.1):
- Testing **your own equipment** is legal
- Testing **with explicit written permission** is legal
- Testing **without authorization** is illegal

See [LEGAL.md](LEGAL.md) for full legal guidelines.

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                         ARGUS                                 │
│                    The All-Seeing Eye                         │
├───────────────────────────────────────────────────────────────┤
│  ┌────────────┐   ┌────────────┐   ┌──────────────────┐      │
│  │   Target   │──►│    Port    │──►│     Service      │      │
│  │  Parser    │   │  Scanner   │   │  Identification  │      │
│  └────────────┘   └────────────┘   └──────────────────┘      │
│                                    │                          │
│                                    ▼                          │
│                         ┌──────────────────┐                  │
│                         │   Credential     │                  │
│                         │    Tester        │                  │
│                         └──────────────────┘                  │
│                                    │                          │
│         ┌──────────────┬──────────┴──────────┬──────────┐    │
│         ▼              ▼                      ▼          ▼    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │   SSH    │  │   HTTP   │  │  Redis   │  │  MySQL   │     │
│  │  Plugin  │  │  Plugin  │  │  Plugin  │  │  Plugin  │     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Intelligence Engine                         │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │ │
│  │  │ Version │  │   CVE   │  │ Exploit │  │  Risk   │    │ │
│  │  │ Parser  │  │ Mapper  │  │ Checker │  │ Scorer  │    │ │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Enterprise Integrations                     │ │
│  │  REST API │ SIEM │ Notifications │ Scheduler │ Reports  │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

---

## 🔗 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Valid Accounts | T1078.001 | Default Accounts |
| Network Service Scanning | T1046 | Port discovery |
| Brute Force | T1110 | Credential testing |

---

## 🎯 Use Cases

- **IoT Security Assessment** - Identify default credentials on IoT devices
- **Network Auditing** - Comprehensive credential auditing
- **Penetration Testing** - Validated default account identification
- **Compliance** - Verify devices don't use default credentials
- **CI/CD Integration** - Automated security checks in pipelines

---

## 📦 Default Credential Categories

- Generic (admin/admin, root/root)
- Routers (TP-Link, Netgear, D-Link, Cisco)
- Cameras (Hikvision, Dahua, Axis)
- Printers (HP, Brother, Canon)
- IoT Devices (Raspberry Pi, embedded systems)
- Databases (MySQL, PostgreSQL, Redis, MongoDB)
- Web Services (Tomcat, Jenkins, WordPress)

---

## 🛠️ Development

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run linting
flake8 argus/

# Format code
black argus/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🔐 Security

For security issues, please see [SECURITY.md](SECURITY.md) or contact: **fev.dev@proton.me**

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## ⚡ Performance

| Metric | Sync Mode | Async Mode |
|--------|-----------|------------|
| 254 hosts scan | 45s | 12s |
| Ports/second | ~50 | ~200 |
| Memory usage | 150MB | 180MB |

---

## 👤 Author

**Fevra** - [fev.dev@proton.me](mailto:fev.dev@proton.me)

- GitHub: [@fevra-dev](https://github.com/fevra-dev)

---

*Argus v0.2.1 - The All-Seeing Eye • For authorized security testing only*
