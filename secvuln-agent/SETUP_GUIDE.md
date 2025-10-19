# VOIGHT SecVuln Agent - Setup Guide

## 🚀 Quick Start

Run the interactive setup wizard to configure your agent:

```bash
cd C:\Projects\secvuln-agent
python src/setup.py
```

The wizard will guide you through all configuration options.

---

## 📋 Configuration Options

### 1. Alert Mode

**Choose how you want to be alerted:**

#### Device-Only Mode (Recommended)
- ✅ **Only alerts for CVEs affecting YOUR devices**
- Perfect for focused, actionable alerts
- Reduces noise - you only see what matters to your infrastructure
- **Use case**: "I only want to know about vulnerabilities in MY environment"

```yaml
filters:
  alert_mode: device-only
  min_cvss_devices: 4.0  # Alert for device CVEs with CVSS >= 4.0
```

**Example:**
- You have Apache 2.4.48 in devices.csv
- CVE-2024-1234 affects Apache 2.4.48 (CVSS 7.5)
- ✅ **You get alerted** (affects your device)
- CVE-2024-5678 affects Nginx (CVSS 9.8)
- ❌ **No alert** (you don't use Nginx)

---

#### All CVEs Mode
- ✅ **Alerts for critical CVEs + YOUR device CVEs**
- Stay informed about the broader threat landscape
- Good for security teams monitoring multiple environments
- **Use case**: "I want to know about major threats, even if they don't affect me yet"

```yaml
filters:
  alert_mode: all-cves
  min_cvss_devices: 4.0   # Device CVEs: CVSS >= 4.0
  min_cvss_all: 7.0        # Non-device CVEs: CVSS >= 7.0
```

**Example:**
- Your device CVE (CVSS 5.0): ✅ Alert (>= 4.0 threshold)
- Other CVE (CVSS 8.5): ✅ Alert (>= 7.0 threshold)
- Other CVE (CVSS 6.0): ❌ No alert (< 7.0 threshold)

---

### 2. Device Monitoring (Always Enabled)

**Your devices are monitored 24/7 automatically!**

```yaml
filters:
  min_cvss_devices: 4.0  # Set your comfort level
```

**Device monitoring includes:**
- ✅ Continuous scanning for CVEs affecting your inventory
- ✅ Matching by vendor, product, and version
- ✅ Lower CVSS threshold (catch issues early)
- ✅ Immediate alerts for critical device vulnerabilities
- ✅ Device breakdown in digest emails

**devices.csv Example:**
```csv
device_id,type,vendor,product,version,criticality,location
WEB-01,Server,Apache,HTTP Server,2.4.48,critical,DMZ
DB-01,Database,PostgreSQL,PostgreSQL,13.2,critical,Internal
FW-01,Firewall,Palo Alto,PAN-OS,10.1.3,critical,Edge
```

**When a CVE is found:**
```
🚨 CVE-2024-1234 (CVSS 7.5) - HIGH
Affects: WEB-01, WEB-02 (Apache HTTP Server 2.4.48)
Action Required: Immediate patching recommended
```

---

### 3. Notification Frequency

**Choose how often you want to receive notifications:**

#### Option 1: Immediate Alerts Only
```yaml
notifications:
  schedule:
    frequency: immediate-only
    immediate_alerts: true
    digest_summary: false
```

- Real-time notifications when critical CVEs are found
- No daily digest emails
- **Best for**: Critical systems requiring immediate action

---

#### Option 2: Daily Digest Only
```yaml
notifications:
  schedule:
    frequency: digest-only
    immediate_alerts: false
    digest_summary: true
```

- One comprehensive email/message per day
- All CVEs summarized with statistics
- **Best for**: Regular monitoring without interruptions

---

#### Option 3: Both (Recommended)
```yaml
notifications:
  schedule:
    frequency: both
    immediate_alerts: true
    digest_summary: true
```

- Immediate alerts for critical issues
- Daily digest for comprehensive overview
- **Best for**: Maximum awareness with actionable urgency

---

### 4. Scan Interval

**How often should the agent check for new vulnerabilities?**

```yaml
agent:
  interval_hours: 6  # Options: 1, 2, 6, 12, 24
```

**Recommendations:**
- **Production servers**: 1-2 hours (maximum protection)
- **Standard environments**: 6 hours (balanced)
- **Development/testing**: 12-24 hours (less frequent)

**Note**: Scans are lightweight and won't impact system performance.

---

### 5. Immediate Alert Thresholds

**What triggers an immediate alert?**

```yaml
filters:
  immediate_alert_cvss: 9.0     # CVSS threshold for immediate alerts
  alert_on_cisa_kev: true       # Alert for CISA KEV vulnerabilities
  alert_on_exploit: true        # Alert for CVEs with public exploits
```

**Immediate alerts are triggered when:**
1. **CVSS >= threshold** (e.g., 9.0 for CRITICAL)
2. **In CISA KEV catalog** (actively exploited in the wild)
3. **Has public exploit** AND CVSS >= 7.0

**Example Alert Logic:**
```
CVE-2024-1234: CVSS 9.8              → ✅ Immediate alert (>= 9.0)
CVE-2024-5678: CVSS 7.5, CISA KEV    → ✅ Immediate alert (KEV)
CVE-2024-9012: CVSS 7.8, Exploit     → ✅ Immediate alert (Exploit)
CVE-2024-3456: CVSS 8.0, No exploit  → ❌ Digest only (< 9.0, not KEV)
```

---

## 📊 Configuration Examples

### Example 1: Small Business (Device-Only, Focused)
```yaml
agent:
  interval_hours: 6

filters:
  alert_mode: device-only
  min_cvss_devices: 5.0        # Only medium+ severity for devices
  immediate_alert_cvss: 8.0    # High severity immediate alerts
  alert_on_cisa_kev: true
  alert_on_exploit: true

notifications:
  schedule:
    frequency: both
```

**Result:**
- Checks every 6 hours
- Only alerts for CVEs affecting your devices (CVSS >= 5.0)
- Immediate alerts for CVSS >= 8.0, CISA KEV, or exploits
- Daily digest + immediate critical alerts

---

### Example 2: Enterprise Security Team (All CVEs, Maximum Awareness)
```yaml
agent:
  interval_hours: 1

filters:
  alert_mode: all-cves
  min_cvss_devices: 4.0        # Low threshold for our devices
  min_cvss_all: 7.0            # High threshold for others
  immediate_alert_cvss: 9.0    # Only critical immediate alerts
  alert_on_cisa_kev: true
  alert_on_exploit: false      # Too many false positives

notifications:
  schedule:
    frequency: both
```

**Result:**
- Checks every hour (rapid response)
- Device CVEs >= 4.0, all CVEs >= 7.0
- Immediate alerts for CVSS >= 9.0 or CISA KEV only
- Comprehensive daily digest

---

### Example 3: Development Environment (Digest Only, Less Frequent)
```yaml
agent:
  interval_hours: 24

filters:
  alert_mode: device-only
  min_cvss_devices: 7.0        # Only high severity
  immediate_alert_cvss: 10.0   # Effectively disabled

notifications:
  schedule:
    frequency: digest-only
```

**Result:**
- Checks once daily
- Only device CVEs with CVSS >= 7.0
- No immediate alerts (effectively disabled with 10.0 threshold)
- Single daily summary

---

## 🔧 Manual Configuration

If you prefer to edit `config/config.yaml` directly:

```yaml
# Agent Settings
agent:
  name: "VOIGHT-SecVuln-Agent"
  interval_hours: 6

# Filtering Rules
filters:
  # Alert Mode: 'device-only' or 'all-cves'
  alert_mode: device-only

  # CVSS Thresholds
  min_cvss_devices: 4.0      # Minimum CVSS for device CVEs
  min_cvss_all: 7.0          # Minimum CVSS for non-device CVEs (all-cves mode only)

  # Immediate Alert Triggers
  immediate_alert_cvss: 9.0  # CVSS threshold for immediate alerts
  alert_on_cisa_kev: true    # Alert for CISA KEV entries
  alert_on_exploit: true     # Alert for CVEs with public exploits

# Notification Settings
notifications:
  schedule:
    frequency: both          # 'immediate-only', 'digest-only', or 'both'
    immediate_alerts: true
    digest_summary: true

  channels:
    email:
      enabled: true
      # ... email config ...

    teams:
      enabled: false
      # ... Teams config ...
```

---

## 🖥️ Device Monitoring Details

### How Device Matching Works

The agent matches CVEs to your devices using:

1. **Vendor/Product matching** (e.g., "Apache HTTP Server")
2. **Version comparison** (exact or range matching)
3. **CPE (Common Platform Enumeration)** matching

**Example:**
```csv
# devices.csv
device_id,vendor,product,version
WEB-01,Apache,HTTP Server,2.4.48
```

**CVE matches when:**
- Vendor = "Apache"
- Product = "HTTP Server" OR "Apache HTTP Server"
- Version = 2.4.48 OR version range includes 2.4.48

### Updating Devices

**To add/remove devices:**

1. Edit `config/devices.csv`
2. Save the file
3. Changes take effect on the next scan (automatic)
4. No need to restart the agent!

**Device CSV Format:**
```csv
device_id,type,vendor,product,version,criticality,location,notes
WEB-01,Server,Apache,HTTP Server,2.4.48,critical,DMZ,Production web server
DB-01,Database,PostgreSQL,PostgreSQL,13.2,critical,Internal,Main database
SWITCH-01,Network,Cisco,IOS,15.2,high,Core,Core switch
```

**Required Fields:**
- `device_id`: Unique identifier
- `vendor`: Vendor name
- `product`: Product name
- `version`: Software/firmware version

**Optional Fields:**
- `type`: Device type (Server, Database, Firewall, etc.)
- `criticality`: critical, high, medium, low
- `location`: Physical/logical location
- `notes`: Additional information

---

## 🚨 Immediate Alert Examples

### Example 1: Critical CVSS (9.8)
```
🚨 CRITICAL SECURITY ALERT
CVE-2024-1234 - CRITICAL

CVSS Score: 9.8 / 10.0
Severity: CRITICAL
Exploit Available: ⚠️ YES
CISA KEV: 🔴 YES

Affected Systems:
• WEB-01 (Apache HTTP Server 2.4.48)
• WEB-02 (Apache HTTP Server 2.4.48)

🤖 AI Analysis:
Urgency: Immediate
Risk: Remote code execution allows unauthenticated attackers...

🔧 Remediation Steps:
1. Apply emergency patch immediately
2. Restart Apache services
3. Verify patch with: httpd -v
...
```

### Example 2: CISA KEV Entry
```
🚨 CRITICAL SECURITY ALERT
CVE-2024-5678 - HIGH

CVSS Score: 7.5 / 10.0
CISA KEV: 🔴 YES (Actively Exploited)

This vulnerability is in CISA's Known Exploited Vulnerabilities catalog.
Active exploitation has been observed in the wild.

Immediate action required!
```

---

## 📧 Daily Digest Example

```
📊 Daily Vulnerability Digest
Monday, January 18, 2025

Summary: 47 vulnerabilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total: 47 | Critical: 3 | High: 12 | Medium: 32

🔴 Top CRITICAL Vulnerabilities (3 total)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CVE-2024-1234
Remote code execution vulnerability in Apache HTTP Server allows...
⚠️ Exploit | 🔴 KEV
CVSS: 9.8 | Devices: WEB-01, WEB-02 (+1 more)

CVE-2024-5678
...

📁 Full Report Available
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A comprehensive CSV report with all 47 vulnerabilities
has been generated:

📁 C:\Projects\secvuln-agent\reports\vulnerability_scan_20250118_143022.csv

💡 Tip: Open this file in Excel for detailed analysis
```

---

## 🎯 Best Practices

### 1. Start with Device-Only Mode
- Focus on what affects YOUR infrastructure
- Reduce alert fatigue
- Build confidence in the system

### 2. Set Appropriate CVSS Thresholds
- **Device CVEs**: 4.0-5.0 (catch early)
- **Non-device CVEs**: 7.0-8.0 (stay informed)
- **Immediate alerts**: 9.0+ (critical only)

### 3. Keep devices.csv Updated
- Add new systems immediately
- Remove decommissioned systems
- Update versions after patches
- Review monthly

### 4. Configure Multiple Notification Channels
- Email for detailed reports
- Teams/Slack for immediate alerts
- Redundancy ensures delivery

### 5. Monitor Regularly
- Review digest emails daily
- Check CSV reports weekly
- Update thresholds based on experience

---

## 🆘 Troubleshooting

### No Alerts Received
1. Check alert_mode: `device-only` requires devices in devices.csv
2. Verify CVSS thresholds aren't too high
3. Check notification channels are configured
4. Review agent logs

### Too Many Alerts
1. Increase min_cvss thresholds
2. Switch to device-only mode
3. Adjust immediate_alert_cvss higher
4. Disable alert_on_exploit if needed

### Devices Not Matching
1. Verify vendor/product names match CVE data
2. Check version format (use exact version from vendor)
3. Review device matcher logs
4. Add debug logging: `log_level: DEBUG`

---

## 📚 Next Steps

1. **Run Setup Wizard**: `python src/setup.py`
2. **Review Configuration**: Check `config/config.yaml`
3. **Update Devices**: Edit `config/devices.csv`
4. **Configure Notifications**: Add email/Teams credentials
5. **Start Agent**: `python src/main.py`
6. **Monitor First Scan**: Watch logs for any issues
7. **Adjust as Needed**: Fine-tune thresholds based on results

---

**VOIGHT SecVuln Agent - Your 24/7 Vulnerability Intelligence Partner** 🚨

For support, issues, or questions: [GitHub Issues](https://github.com/your-repo/issues)
