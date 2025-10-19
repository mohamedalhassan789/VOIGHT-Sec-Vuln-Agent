# Setup Wizard & Device Monitoring - Feature Summary

## 🎯 Overview

Added comprehensive setup wizard and flexible alert configuration to give users full control over how they receive vulnerability alerts.

---

## ✨ New Features

### 1. **Interactive Setup Wizard** (`src/setup.py`)

Run with: `python src/setup.py`

**Features:**
- 🎨 Beautiful terminal UI with VOIGHT branding
- 📋 Step-by-step configuration questions
- ✅ Configuration validation and review
- 💾 Automatic config.yaml generation
- 📚 Helpful explanations for each option

**Wizard Steps:**
1. Alert Mode (device-only vs all-cves)
2. Device Monitoring Threshold
3. Notification Frequency (immediate/digest/both)
4. Scan Interval (1-24 hours)
5. Immediate Alert Thresholds
6. Configuration Review & Save

---

### 2. **Alert Mode Configuration**

Users can now choose between two monitoring modes:

#### Device-Only Mode (Default)
```yaml
filters:
  alert_mode: device-only
  min_cvss_devices: 4.0
```

**Behavior:**
- ✅ Only alerts for CVEs affecting devices in `devices.csv`
- ✅ Lower CVSS threshold (e.g., 4.0) to catch issues early
- ✅ Reduced noise - only actionable alerts
- ✅ Perfect for focused monitoring

**Example:**
- Your device: Apache 2.4.48
- CVE affects Apache 2.4.48 (CVSS 6.0) → ✅ **Alert sent**
- CVE affects Nginx (CVSS 9.8) → ❌ **No alert** (you don't use Nginx)

---

#### All CVEs Mode
```yaml
filters:
  alert_mode: all-cves
  min_cvss_devices: 4.0    # Your devices
  min_cvss_all: 7.0        # Other CVEs
```

**Behavior:**
- ✅ Alerts for device CVEs (CVSS >= 4.0)
- ✅ Alerts for all critical CVEs (CVSS >= 7.0)
- ✅ Stay informed about threat landscape
- ✅ Good for security teams

**Example:**
- Your device CVE (CVSS 5.0) → ✅ **Alert** (>= 4.0)
- Other CVE (CVSS 8.5) → ✅ **Alert** (>= 7.0)
- Other CVE (CVSS 6.0) → ❌ **No alert** (< 7.0)

---

### 3. **24/7 Device Monitoring**

**Always Enabled - Your devices are continuously monitored!**

```yaml
filters:
  min_cvss_devices: 4.0  # Set your comfort level
```

**How it works:**
1. Agent scans CVE feeds every X hours
2. **Matches CVEs to your devices FIRST**
3. Applies device-specific CVSS threshold
4. Sends immediate alerts for critical device issues
5. Includes device breakdown in digest

**Device Matching:**
- Vendor/Product name matching
- Version comparison (exact or range)
- CPE (Common Platform Enumeration) matching
- Automatic updates when devices.csv changes

---

### 4. **Flexible Notification Frequency**

```yaml
notifications:
  schedule:
    frequency: both  # Options: immediate-only, digest-only, both
```

**Options:**

| Mode | Immediate Alerts | Daily Digest | Best For |
|------|------------------|--------------|----------|
| `immediate-only` | ✅ | ❌ | Critical systems requiring instant action |
| `digest-only` | ❌ | ✅ | Regular monitoring without interruptions |
| `both` | ✅ | ✅ | Maximum awareness (recommended) |

---

### 5. **Configurable Immediate Alert Triggers**

```yaml
filters:
  immediate_alert_cvss: 9.0    # CVSS threshold
  alert_on_cisa_kev: true      # CISA KEV vulnerabilities
  alert_on_exploit: true       # Has public exploit
```

**Immediate alerts triggered when:**
1. **CVSS >= threshold** (e.g., 9.0 = CRITICAL only)
2. **In CISA KEV catalog** (actively exploited)
3. **Has public exploit** AND CVSS >= 7.0

**Flexibility:**
- Set CVSS threshold (7.0-10.0)
- Enable/disable CISA KEV alerts
- Enable/disable exploit-based alerts
- Prevent alert fatigue

---

## 🔧 Technical Implementation

### Files Modified

#### 1. **src/setup.py** (NEW)
- Interactive setup wizard
- Question/answer flow
- Configuration generation
- Beautiful terminal UI

#### 2. **src/main.py**
**Lines 71-94:** Added alert mode configuration
```python
# Alert mode configuration
filters = self.config.get('filters', {})
self.alert_mode = filters.get('alert_mode', 'device-only')
self.min_cvss_devices = filters.get('min_cvss_devices', 4.0)
self.min_cvss_all = filters.get('min_cvss_all', 7.0)
self.immediate_alert_cvss = filters.get('immediate_alert_cvss', 9.0)
self.alert_on_cisa_kev = filters.get('alert_on_cisa_kev', True)
self.alert_on_exploit = filters.get('alert_on_exploit', True)
```

**Lines 213-253:** Implemented device-only vs all-cves filtering
```python
# Match to devices FIRST (important for device-only mode)
matched_devices = self.matcher.match_cve_to_devices(cve)

# Apply filtering based on alert mode
if self.alert_mode == 'device-only':
    # Only process CVEs affecting our devices
    if not matched_devices:
        continue
    if cvss_score < self.min_cvss_devices:
        continue
else:
    # ALL-CVES MODE: separate thresholds
    if matched_devices:
        # Device CVE: use device threshold
        if cvss_score < self.min_cvss_devices:
            continue
    else:
        # Non-device CVE: use all-CVEs threshold
        if cvss_score < self.min_cvss_all:
            continue
```

#### 3. **src/notifiers/notification_manager.py**
**Lines 37-47:** Load filter configuration
```python
# Load filter configuration from parent config
if 'filters' in config:
    filters = config['filters']
else:
    filters = {}

self.immediate_alert_cvss = filters.get('immediate_alert_cvss', 9.0)
self.alert_on_cisa_kev = filters.get('alert_on_cisa_kev', True)
self.alert_on_exploit = filters.get('alert_on_exploit', True)
```

**Lines 55-63:** Handle full config vs notifications-only
```python
# Handle both full config and notifications-only config
if 'notifications' in self.config:
    notifications = self.config['notifications']
else:
    notifications = self.config

channels = notifications.get('channels', {})
```

**Lines 199-228:** User-configurable immediate alert logic
```python
def _should_send_immediate(self, cve_data: Dict) -> bool:
    cvss = cve_data.get('cvss_score', 0)
    in_kev = cve_data.get('in_cisa_kev', False)
    exploit = cve_data.get('exploit_available', False)

    # Check CVSS threshold
    if cvss >= self.immediate_alert_cvss:
        return True

    # Check CISA KEV (if enabled)
    if self.alert_on_cisa_kev and in_kev:
        return True

    # Check exploit availability (if enabled)
    if self.alert_on_exploit and exploit and cvss >= 7.0:
        return True

    return False
```

---

## 📊 Configuration Structure

### New config.yaml Structure

```yaml
agent:
  name: "VOIGHT-SecVuln-Agent"
  interval_hours: 6

filters:
  # Alert Mode
  alert_mode: device-only          # or 'all-cves'

  # CVSS Thresholds
  min_cvss_devices: 4.0            # Device CVEs
  min_cvss_all: 7.0                # Non-device CVEs (all-cves mode)

  # Immediate Alert Triggers
  immediate_alert_cvss: 9.0        # CVSS threshold
  alert_on_cisa_kev: true          # Alert on CISA KEV
  alert_on_exploit: true           # Alert on exploits

notifications:
  schedule:
    frequency: both                 # immediate-only, digest-only, both
    immediate_alerts: true
    digest_summary: true

  channels:
    email:
      enabled: true
      # ... existing email config ...

    teams:
      enabled: false
      # ... existing Teams config ...

sources:
  # ... existing source config ...
```

---

## 🎬 User Workflow

### Initial Setup
```bash
# Run setup wizard
python src/setup.py

# Answer questions:
1. Choose alert mode (device-only recommended)
2. Set device CVSS threshold (4.0 recommended)
3. Choose notification frequency (both recommended)
4. Set scan interval (6 hours recommended)
5. Configure immediate alert thresholds

# Review and save configuration
✓ Configuration saved to config/config.yaml
```

### Update Device Inventory
```bash
# Edit devices list
nano config/devices.csv

# Add your devices:
device_id,vendor,product,version,criticality
WEB-01,Apache,HTTP Server,2.4.48,critical
DB-01,PostgreSQL,PostgreSQL,13.2,critical
FW-01,Palo Alto,PAN-OS,10.1.3,critical

# Save - changes take effect on next scan!
```

### Configure Notifications
```bash
# Add email credentials to config.yaml
notifications:
  channels:
    email:
      enabled: true
      smtp_host: smtp.gmail.com
      username: your-email@gmail.com
      password: your-app-password
      to_emails:
        - security-team@company.com
```

### Run Agent
```bash
# Start monitoring
python src/main.py

# Agent logs:
14:13:08 | INFO | Agent initialized
14:13:08 | INFO | Alert mode: device-only
14:13:08 | INFO | Device monitoring: ENABLED (CVSS >= 4.0)
14:13:08 | INFO | Devices loaded: 17
14:13:08 | INFO | Collectors configured: 5
✓ Agent initialized successfully
```

---

## 📈 Benefits

### For Users
- ✅ **Less Noise**: Only see what matters to you
- ✅ **Focused Alerts**: Device-only mode = actionable intelligence
- ✅ **Flexible**: Choose your own thresholds and frequencies
- ✅ **Easy Setup**: Interactive wizard makes configuration simple
- ✅ **24/7 Monitoring**: Devices continuously monitored
- ✅ **Automatic**: No manual CVE checking needed

### For Administrators
- ✅ **Customizable**: Adapt to any environment
- ✅ **Scalable**: Works for 5 devices or 500
- ✅ **Maintainable**: Simple CSV device inventory
- ✅ **Auditable**: CSV reports for compliance
- ✅ **Tested**: Proven filtering logic

---

## 🧪 Testing

### Test Device-Only Mode
```bash
# Set in config:
alert_mode: device-only
min_cvss_devices: 4.0

# Run agent
python src/main.py

# Expected: Only CVEs affecting your devices are processed
```

### Test All-CVEs Mode
```bash
# Set in config:
alert_mode: all-cves
min_cvss_devices: 4.0
min_cvss_all: 7.0

# Run agent
python src/main.py

# Expected: Device CVEs (>=4.0) + All CVEs (>=7.0) are processed
```

### Test Immediate Alerts
```bash
# Set in config:
immediate_alert_cvss: 9.0
alert_on_cisa_kev: true
alert_on_exploit: false

# Run agent
python src/main.py

# Expected: Only CVSS>=9.0 or CISA KEV trigger immediate alerts
```

---

## 📚 Documentation

Created comprehensive guides:
1. **SETUP_GUIDE.md** - Complete setup and configuration reference
2. **This file** - Technical implementation summary

---

## 🚀 Next Steps for Users

1. **Run Setup Wizard**: `python src/setup.py`
2. **Update devices.csv**: Add your infrastructure
3. **Configure Notifications**: Add email/Teams credentials
4. **Start Agent**: `python src/main.py`
5. **Monitor & Adjust**: Fine-tune thresholds based on results

---

**Generated:** 2025-01-18
**Version:** 2.0
**Status:** ✅ COMPLETE
