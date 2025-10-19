# 🛡️ VOIGHT SecVuln Agent

> **Automated Security Vulnerability Intelligence & Monitoring System**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security](https://img.shields.io/badge/security-encrypted%20credentials-success)](CREDENTIAL_SECURITY.md)

VOIGHT SecVuln Agent is an intelligent, automated vulnerability monitoring system that continuously scans multiple security feeds, correlates CVEs with your infrastructure, and delivers actionable alerts through your preferred channels.

---

## 🌟 Key Features

### 🔍 **Comprehensive Vulnerability Intelligence**
- **Multi-Source Aggregation**: CISA KEV, GitHub Security Advisories, NVD, OpenCVE, RSS feeds
- **Real-Time Monitoring**: Continuous scanning with configurable intervals (1-24 hours)
- **Smart Filtering**: Device-only or all-CVEs mode with customizable CVSS thresholds
- **Exploit Detection**: Automatic detection of public exploits and CISA Known Exploited Vulnerabilities

### 🎯 **Device-Centric Monitoring**
- **Automated Matching**: Correlates CVEs with your infrastructure inventory
- **Vendor/Product/Version Tracking**: Precise vulnerability identification
- **Criticality Scoring**: Priority ranking based on device criticality
- **24/7 Device Monitoring**: Continuous protection for all registered assets

### 🤖 **AI-Powered Analysis** *(Optional)*
- **Multi-Provider Support**: Anthropic Claude, OpenAI GPT-4, Google Gemini, Ollama (local)
- **Risk Assessment**: Intelligent severity analysis and impact evaluation
- **Remediation Guidance**: Automated, context-aware mitigation steps
- **Smart Summarization**: AI-generated executive summaries

### 📢 **Flexible Notification System**
- **Multi-Channel Delivery**: Email, Slack, Microsoft Teams, Telegram, Google Chat
- **Dual Alert Modes**:
  - **Immediate Alerts**: Real-time notifications for critical vulnerabilities
  - **Daily Digest**: Comprehensive daily summaries with detailed reports
- **Rich Formatting**: HTML emails, Adaptive Cards (Teams), interactive messages
- **Rate Limiting**: Configurable thresholds to prevent alert fatigue

### 🔐 **Enterprise-Grade Security**
- **Encrypted Credentials**: Fernet encryption with OS keyring integration
- **Secure Storage**: No plain-text passwords in configuration files
- **Safe Sharing**: Configuration files can be shared without exposing secrets
- **Migration Tools**: Easy credential migration from plain-text to encrypted storage

### 📊 **Reporting & Analytics**
- **CSV Export**: Detailed vulnerability reports for analysis and compliance
- **Device Breakdown**: Per-device vulnerability counts and severity distribution
- **Trend Analysis**: Historical data tracking and reporting
- **Audit Trail**: Complete logging of all scans and alerts

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- **Virtual environment** (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/mohamedalhassan789/secvuln-agent.git
cd secvuln-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run setup wizard
python src/setup_wizard.py
```

### First-Time Setup

The interactive setup wizard will guide you through:

1. **Agent Configuration**: Name, scan interval, alert mode
2. **Alert Thresholds**: CVSS scores, CISA KEV, exploit-based alerts
3. **Data Sources**: Select feeds to monitor (CISA, GitHub, NVD, RSS)
4. **AI Analysis**: Optional AI-powered vulnerability analysis
5. **Notifications**: Configure email, Slack, Teams, Telegram, etc.
6. **Device Inventory**: Add your infrastructure for monitoring

```bash
python src/setup_wizard.py
```

**All credentials are automatically encrypted** during setup. No plain-text passwords in config files!

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [**Setup Guide**](SETUP_GUIDE.md) | Comprehensive installation and configuration |
| [**Credential Security**](CREDENTIAL_SECURITY.md) | Encryption details and migration instructions |
| [**Feature Summary**](SETUP_WIZARD_FEATURES.md) | Alert modes, device monitoring, and features |
| [**Sharing Instructions**](SHARING_INSTRUCTIONS.md) | How to share the tool safely |

---

## 🎯 Usage Examples

### Basic Usage

```bash
# Start the agent (runs continuously)
python src/main.py

# The agent will:
# ✓ Scan vulnerability feeds every X hours
# ✓ Match CVEs to your devices
# ✓ Send immediate alerts for critical issues
# ✓ Generate daily digest reports
# ✓ Export CSV reports to reports/ directory
```

### Configuration Modes

#### Device-Only Mode (Recommended)
```yaml
filters:
  alert_mode: device-only
  min_cvss_devices: 4.0
```
**Result**: Only alerts for CVEs affecting **your** devices (focused, actionable alerts)

#### All-CVEs Mode
```yaml
filters:
  alert_mode: all-cves
  min_cvss_devices: 4.0
  min_cvss_all: 7.0
```
**Result**: Alerts for device CVEs **+** all high-severity CVEs (comprehensive threat awareness)

### Device Inventory Management

Edit `config/devices.csv`:
```csv
device_id,device_type,vendor,product,version,criticality,location,notes
WEB-01,server,Apache,HTTP Server,2.4.54,critical,DMZ,Public web server
DB-01,database,PostgreSQL,PostgreSQL,14.5,critical,Internal,Production database
FW-01,firewall,Palo Alto,PAN-OS,10.2.3,critical,Edge,Perimeter firewall
```

Changes take effect on the next scan!

---

## 🔧 Advanced Configuration

### Immediate Alert Triggers

```yaml
filters:
  immediate_alert_cvss: 9.0      # CVSS threshold for immediate alerts
  alert_on_cisa_kev: true        # Alert on CISA Known Exploited Vulnerabilities
  alert_on_exploit: true         # Alert when public exploits are available
```

### Notification Frequency

```yaml
notifications:
  schedule:
    frequency: both                # Options: both, immediate-only, digest-only
    immediate_alerts: true
    digest_summary: true
    digest_time: '09:00'
  max_immediate_per_hour: 5       # Rate limiting to prevent alert fatigue
```

### AI Analysis Configuration

```yaml
ai:
  enabled: true
  provider: anthropic              # Options: anthropic, openai, google, ollama
  anthropic:
    model: claude-sonnet-4-5
```

---

## 🔐 Security & Privacy

### Encrypted Credential Storage

All sensitive credentials are encrypted:
- ✅ Email passwords
- ✅ Webhook URLs (Slack, Teams, Google Chat)
- ✅ Telegram bot tokens
- ✅ API keys (AI providers)

**Storage Location**: `~/.secvuln-agent/credentials.enc` (encrypted with Fernet)

### Migration for Existing Users

If you have plain-text credentials in `config.yaml`:

```bash
python migrate_credentials.py
```

This will:
1. Encrypt all credentials
2. Remove them from `config.yaml`
3. Store them securely in `~/.secvuln-agent/`
4. Create a backup of your original config

See [CREDENTIAL_SECURITY.md](CREDENTIAL_SECURITY.md) for details.

---

## 📊 Example Output

### Immediate Alert (Email)
```
🚨 CRITICAL Security Alert: CVE-2024-1234 (CVSS 9.8)

CVE ID: CVE-2024-1234
CVSS Score: 9.8 / 10.0
Severity: CRITICAL
Exploit Available: ✅ Yes
CISA KEV: ⚠️ Yes - Active Exploitation

Description: Remote code execution vulnerability in...

Affected Systems:
  • WEB-01 (server) - Apache HTTP Server 2.4.54
  • WEB-02 (server) - Apache HTTP Server 2.4.54

🔧 Remediation Steps:
  1. Apply Apache security patch immediately
  2. Implement WAF rules to block exploitation attempts
  3. Monitor logs for signs of compromise
  ...
```

### Daily Digest (Summary)
```
📊 Daily Security Digest - January 19, 2025

Summary: 47 vulnerabilities | 3 CRITICAL | 12 HIGH | 28 MEDIUM | 4 LOW

📱 Affected Devices:
  • WEB-01: 2 CRITICAL, 5 HIGH, 8 MEDIUM
  • DB-01: 1 CRITICAL, 3 HIGH, 2 MEDIUM
  • FW-01: 0 CRITICAL, 4 HIGH, 6 MEDIUM

🔴 Top CRITICAL Vulnerabilities:
  • CVE-2024-1234 (CVSS 9.8) - Apache HTTP Server RCE
  • CVE-2024-5678 (CVSS 9.1) - PostgreSQL Authentication Bypass
  ...

📊 Full CSV Report: reports/vulns_2025-01-19_090000.csv
```

---

## 🛠️ Development

### Project Structure

```
secvuln-agent/
├── src/
│   ├── main.py                    # Main agent orchestrator
│   ├── setup_wizard.py            # Interactive setup wizard
│   ├── collectors/                # Vulnerability feed collectors
│   │   ├── cisa_kev_collector.py
│   │   ├── github_collector.py
│   │   ├── nvd_collector.py
│   │   └── ...
│   ├── processors/                # CVE processors & matchers
│   │   ├── cve_matcher.py
│   │   └── cve_processor.py
│   ├── notifiers/                 # Notification channels
│   │   ├── email_notifier.py
│   │   ├── teams_notifier.py
│   │   ├── slack_notifier.py
│   │   └── ...
│   └── utils/                     # Utilities
│       ├── secrets_manager.py     # Credential encryption
│       ├── ai_analyzer.py         # AI-powered analysis
│       └── csv_report_generator.py
├── config/
│   ├── config.yaml               # User configuration (no secrets!)
│   └── devices.csv               # Device inventory
├── data/                         # SQLite database
├── reports/                      # CSV vulnerability reports
├── requirements.txt              # Python dependencies
├── reset_config.py              # Reset configuration
├── migrate_credentials.py       # Credential migration tool
└── docs/                        # Documentation
```

### Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run with coverage
pytest --cov=src tests/
```

### Code Style

```bash
# Format code
black src/

# Lint
flake8 src/
pylint src/
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Ways to Contribute
- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Add new data source collectors
- 🔌 Add new notification channels

---

## 📋 Roadmap

- [ ] Web UI dashboard
- [ ] Kubernetes deployment support
- [ ] Docker containerization
- [ ] Webhook-based device inventory sync
- [ ] Custom vulnerability scoring models
- [ ] Integration with SIEM systems
- [ ] Mobile app (iOS/Android)
- [ ] REST API for programmatic access

---

## 🙏 Acknowledgments

### Data Sources
- [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [GitHub Security Advisories](https://github.com/advisories)
- [OpenCVE](https://www.opencve.io/)

### Technologies
- **Python**: Core programming language
- **SQLite**: Local database
- **Cryptography**: Credential encryption (Fernet)
- **Keyring**: OS credential storage
- **Requests**: HTTP client
- **PyYAML**: Configuration management
- **Questionary**: Interactive CLI

### AI Providers
- **Anthropic Claude**: Advanced reasoning and analysis
- **OpenAI GPT-4**: Versatile AI capabilities
- **Google Gemini**: Free tier AI analysis
- **Ollama**: Local AI inference

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/secvuln-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/secvuln-agent/discussions)

---

## ⚠️ Disclaimer

This tool is provided for **defensive security purposes only**. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before scanning or monitoring systems.

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=mohamedalhassan789/secvuln-agent&type=Date)](https://star-history.com/#mohamedalhassan789/secvuln-agent&Date)


