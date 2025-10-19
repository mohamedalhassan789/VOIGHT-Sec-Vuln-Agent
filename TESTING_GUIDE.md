# Complete Testing Guide - SecVuln Agent (VOIGHT)

## Prerequisites Checklist
- ✅ Windows 11
- ✅ SMTP credentials (work email)
- ✅ Microsoft Teams webhook URL
- ✅ OpenAI API key
- ✅ Device inventory ready

---

## Part 1: Windows Complete Setup & Test

### Step 1: Environment Setup

```bash
# Navigate to project
cd C:\Projects\secvuln-agent

# Create virtual environment (if not exists)
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Run Setup Wizard

```bash
python src\setup_wizard.py
```

**You'll see the VOIGHT theme animation!** 🚨

### Step 3: Setup Wizard Configuration

Follow the prompts:

#### **Agent Configuration**
- **Agent name**: `VOIGHT-SecVuln` (or your preference)
- **Check interval**: Start with `1 hour` for testing (change to 6-12 hours later)

#### **Filters**
- **Minimum CVSS score**: `7.0 (High+Critical)` for testing
- This will give you more results to verify the system works

#### **Data Sources**
Select these for comprehensive testing:
- ✅ **Hot Feeds**:
  - ✅ CISA KEV (Known Exploited)
  - ✅ GitHub Advisories
  - ✅ OpenCVE
- ✅ **RSS Feeds**:
  - ✅ Reddit r/netsec
  - ✅ Packet Storm
  - ✅ The Hacker News

#### **AI Analysis**
- **Enable AI**: `Yes`
- **Provider**: `OpenAI GPT-4 (Popular)`
- **API Key**: Enter your OpenAI API key
  - The wizard will store it securely using Windows Credential Manager

#### **Notifications**
Select both channels you have:
1. **Microsoft Teams**
   - Webhook URL: `https://outlook.office.com/webhook/YOUR-WEBHOOK-URL`
   - Get this from Teams: Channel → ⋯ → Connectors → Incoming Webhook

2. **Email**
   - **Provider**: Select your work email provider
     - If Gmail: Select `Gmail` → Use App Password
     - If Outlook/Office365: Select accordingly
     - If custom: Select `Custom SMTP`
   - **Email address**: Your work email
   - **Password**: Email password or app-specific password
   - **Recipients**: Your email (for testing) or team emails

#### **Device Inventory**
Choose one of:
- **Create sample devices**: Good for initial testing
- **Manual entry**: If you want to add your real devices now

For testing, I recommend **"Create sample devices"** first.

### Step 4: Verify Configuration

After setup completes, check the files:

```bash
# View configuration
type config\config.yaml

# View devices (if created)
type config\devices.csv
```

### Step 5: Add Your Real Devices

Edit `config\devices.csv` with your actual infrastructure:

```bash
notepad config\devices.csv
```

**Format:**
```csv
device_id,device_type,vendor,product,version,criticality,location,notes
FW-001,firewall,Palo Alto,PA-Series,10.2.3,critical,datacenter-1,Edge firewall
SW-CORE-01,switch,Cisco,Catalyst 9300,17.6.4,high,datacenter-1,Core switch
WEB-01,web_server,nginx,nginx,1.24.0,high,dmz,Production web server
DB-PROD-01,database,PostgreSQL,PostgreSQL,14.5,critical,internal,Production database
```

**Supported device types:**
- `firewall`, `switch`, `router`, `load_balancer`
- `web_server`, `application_server`, `database`
- `operating_system`, `hypervisor`, `container_runtime`

### Step 6: First Test Run

```bash
# Run the agent
python src\main.py
```

**Watch for:**
1. 🚨 **Police siren animation**
2. 📋 **Case file opening**
3. 🎯 **VOIGHT logo display**
4. 💬 **Random Voight quote**
5. ✅ **[10-4] status codes** for initialization

**The agent will:**
- Collect vulnerabilities from all enabled sources (~2-5 minutes)
- Match them to your devices
- Calculate risk scores
- Analyze critical ones with AI (if enabled)
- Send notifications

### Step 7: Verify Notifications

Check both channels:

**Microsoft Teams:**
- Look for a message in your configured channel
- Should show:
  - CVE details
  - Severity and CVSS score
  - Matched devices (if any)
  - AI analysis (for P0/P1)

**Email:**
- Check your inbox
- Look for HTML-formatted email with:
  - Color-coded severity
  - Vulnerability details
  - Device matches
  - Links to references

### Step 8: Check Database & Logs

```bash
# View logs
type logs\secvuln-agent.log

# Check database (using Python)
python -c "from src.utils.db_handler import DatabaseHandler; db = DatabaseHandler(); print(db.get_cve_statistics())"
```

### Step 9: Test Different Scenarios

#### Test 1: Manual Single Scan
```bash
python src\main.py
# Let it run once and exit with Ctrl+C after first scan
```

#### Test 2: Continuous Monitoring (Short Interval)
- Edit `config\config.yaml`
- Set `interval_hours: 1` (for testing)
- Run: `python src\main.py`
- Let it run for 2-3 hours, check multiple notifications

#### Test 3: Filter Testing
Edit `config\config.yaml` filters:
```yaml
filters:
  min_cvss_score: 9.0  # Only critical
  kev_only: true       # Only CISA KEV
```
Run again and verify filtering works.

### Step 10: Performance Monitoring

Watch for:
- ✅ Battery level checks (laptop only)
- ✅ Memory usage (should be < 200MB)
- ✅ API rate limiting (no errors)
- ✅ Deduplication (no duplicate alerts)

---

## Part 2: Troubleshooting Common Issues

### Issue 1: "No API key found"
```bash
# Manually store the key
python -c "from src.utils.secrets_manager import SecretsManager; sm = SecretsManager(); sm.store_provider_key('openai', 'sk-YOUR-KEY-HERE')"
```

### Issue 2: Teams webhook fails
- Verify webhook URL is complete
- Test with curl:
```bash
curl -H "Content-Type: application/json" -d "{\"text\":\"Test from VOIGHT\"}" YOUR_WEBHOOK_URL
```

### Issue 3: Email sending fails (Gmail)
- Must use **App Password**, not regular password
- Enable 2FA first: https://myaccount.google.com/security
- Generate App Password: https://myaccount.google.com/apppasswords
- Use 16-character app password in config

### Issue 4: No vulnerabilities collected
- Check internet connection
- Check logs: `type logs\secvuln-agent.log`
- Sources might be rate-limiting, wait 10 minutes and retry

### Issue 5: UTF-8 / Emoji Issues
```bash
# Run with UTF-8 encoding
chcp 65001
python src\main.py
```

---

## Part 3: Production Deployment (Windows)

### Option A: Task Scheduler (Recommended)

1. Open **Task Scheduler** (Win + R → `taskschd.msc`)

2. **Create Basic Task**
   - Name: `VOIGHT-SecVuln-Agent`
   - Description: `Security Vulnerability Intelligence Agent`

3. **Trigger**
   - When: `When the computer starts`
   - Or: `Daily` at startup time

4. **Action**
   - Start a program
   - Program: `C:\Projects\secvuln-agent\venv\Scripts\python.exe`
   - Arguments: `C:\Projects\secvuln-agent\src\main.py`
   - Start in: `C:\Projects\secvuln-agent`

5. **Conditions**
   - ✅ Start only if on AC power (laptop)
   - ✅ Start only if network is available

6. **Settings**
   - ✅ Allow task to be run on demand
   - ✅ If task fails, restart every 10 minutes
   - Attempt restart up to 3 times

### Option B: NSSM (Windows Service)

```bash
# Download NSSM: https://nssm.cc/download
# Extract and navigate to NSSM directory

# Install as service
nssm install VOIGHT-SecVuln "C:\Projects\secvuln-agent\venv\Scripts\python.exe" "C:\Projects\secvuln-agent\src\main.py"

# Configure service
nssm set VOIGHT-SecVuln AppDirectory C:\Projects\secvuln-agent
nssm set VOIGHT-SecVuln DisplayName "VOIGHT Security Vulnerability Agent"
nssm set VOIGHT-SecVuln Description "Intelligence Unit - Vulnerability Monitoring"
nssm set VOIGHT-SecVuln Start SERVICE_AUTO_START

# Start service
nssm start VOIGHT-SecVuln

# Check status
nssm status VOIGHT-SecVuln

# View logs
nssm set VOIGHT-SecVuln AppStdout C:\Projects\secvuln-agent\logs\service-output.log
nssm set VOIGHT-SecVuln AppStderr C:\Projects\secvuln-agent\logs\service-error.log
```

---

## Expected Results

After successful setup and first run:

### Console Output
```
[Police siren animation]

    Intelligence Unit - Active Monitoring

    ┌─────────────────────────────────────────┐
    │  INTELLIGENCE UNIT          │
    │ Case File: SEC-VULN-2025          │
    │ Lead Detective: VOIGHT                  │
    │ Status: [ACTIVE]                        │
    └─────────────────────────────────────────┘

   VOIGHT logo...

        "We protect this city, no matter what"
        No vulnerability escapes the Intelligence Unit

    ✓ [10-4] Loading configuration
    ✓ [10-4] Initializing collectors
    ✓ [10-4] Setting up processors
    ✓ [10-4] Preparing notifiers

    [Code 4] All units operational. Intelligence Unit standing by.

🚀 Initializing SecVuln Agent...
    ✓ [10-4] Agent initialized successfully

[10-20] Starting scan cycle at 2025-XX-XX...
[10-20] Collecting from CISA KEV...
[10-4] Collected 15 CVEs from CISA KEV
...
[10-4] Total unique CVEs collected: 47
[10-4] Processed 12 vulnerabilities
[Signal 25] Sending immediate alert for CVE-2024-XXXXX
[10-4] Scan complete
```

### Database Contents
- CVE records stored
- Device matches recorded
- Notification history tracked
- Source tracking updated

### Notifications Sent
- **Immediate alerts**: For critical (P0) vulnerabilities
- **Digest email**: Summary of all findings
- Both channels (Teams + Email) received messages

---

## Next Steps

1. ✅ **Review first scan results**
2. ✅ **Adjust filters** based on noise level
3. ✅ **Fine-tune device inventory**
4. ✅ **Set production interval** (6-12 hours)
5. ✅ **Deploy to production** (Task Scheduler or Service)
6. ✅ **Monitor for 1 week**, adjust as needed

---

## Support & Logs

**Log locations:**
- Main log: `logs\secvuln-agent.log`
- Error log: `logs\secvuln-agent_error.log`
- Database: `data\secvuln.db`
- Reports: `reports\*.csv` (if enabled)

**Check health:**
```bash
# View recent logs
powershell -command "Get-Content logs\secvuln-agent.log -Tail 50"

# Check database stats
python -c "from src.utils.db_handler import DatabaseHandler; db = DatabaseHandler(); stats = db.get_cve_statistics(); print(f'Total CVEs: {stats}')"
```

**[Code 4] You're ready to protect your infrastructure. Whatever it takes.** 🚨
