# 🚨 QUICK START - Get VOIGHT Running in 10 Minutes

**For Windows users who want to test right now!**

---

## Prerequisites Check

Before you start, ensure you have:

- [ ] **OpenAI API Key** - Get from https://platform.openai.com/api-keys
- [ ] **Teams Webhook URL** - Get from your Teams channel (Channel → ⋯ → Connectors → Incoming Webhook)
- [ ] **Work Email SMTP** - Your email credentials
- [ ] **Device list** - List of devices/software you want to monitor

---

## Step 1: Setup Environment (2 minutes)

```powershell
# Open PowerShell in the project directory
cd C:\Projects\secvuln-agent

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Expected output:** ~50 packages installed successfully

---

## Step 2: Run Setup Wizard (3 minutes)

```powershell
python src\setup_wizard.py
```

### 🚨 You'll see the VOIGHT animation! Follow the prompts:

**Agent Configuration:**
- Name: `VOIGHT-Test` (or anything you like)
- Interval: `1 hour` (for quick testing)

**Filters:**
- CVSS Score: `7.0 (High+Critical)`

**Data Sources:**
- Select all Hot Feeds: ✅ CISA KEV, ✅ GitHub, ✅ OpenCVE
- Select all RSS Feeds: ✅ Reddit, ✅ Packet Storm, ✅ Hacker News

**AI Analysis:**
- Enable: `Yes`
- Provider: `OpenAI GPT-4`
- **API Key**: Paste your OpenAI API key here

**Notifications:**
- Select: `Microsoft Teams` and `Email`

**Teams Setup:**
1. Get webhook URL from Teams:
   - Open your Teams channel
   - Click ⋯ (more options)
   - Click "Connectors"
   - Search "Incoming Webhook"
   - Click "Configure"
   - Give it a name: "VOIGHT Security Alerts"
   - Copy the webhook URL
2. Paste webhook URL in wizard

**Email Setup:**
- Provider: Choose your email provider (Gmail, Outlook, etc.)
- **For Gmail users:**
  - **IMPORTANT:** You MUST use an "App Password", not your regular password
  - Steps:
    1. Go to https://myaccount.google.com/security
    2. Enable 2-Factor Authentication (if not already)
    3. Go to https://myaccount.google.com/apppasswords
    4. Create app password for "Mail"
    5. Copy the 16-character password
    6. Use this in the wizard
- Email address: Your email
- Password: App password (for Gmail) or regular password (for others)
- Recipients: Your email (comma-separated for multiple)

**Device Inventory:**
- Choose: `Create sample devices` (for quick testing)
- Or choose `Manual entry` if you want to add your real devices now

**Wizard completes with celebration animation!** 🎖️

---

## Step 3: Add Your Real Devices (2 minutes) - OPTIONAL

If you want to track your actual infrastructure:

```powershell
notepad config\devices.csv
```

Replace sample devices with your actual devices:

```csv
device_id,device_type,vendor,product,version,criticality,location,notes
FW-EDGE-01,firewall,Palo Alto,PA-Series,10.2.3,critical,datacenter,Edge firewall
SW-CORE-01,switch,Cisco,Catalyst 9300,17.6.4,high,datacenter,Core switch
WEB-PROD-01,web_server,nginx,nginx,1.24.0,high,production,Production web
DB-MAIN-01,database,PostgreSQL,PostgreSQL,14.5,critical,production,Main database
APP-API-01,application_server,Node.js,express,4.18.2,high,production,API server
```

**Device types you can use:**
- `firewall`, `switch`, `router`, `load_balancer`
- `web_server`, `application_server`, `database`
- `operating_system`, `hypervisor`, `container_runtime`

Save and close.

---

## Step 4: First Test Run! (3 minutes)

```powershell
python src\main.py
```

### 🚨 Watch the Magic Happen:

1. **Police siren animation** (red/blue flashing) 🚨
2. **Case file opens** with "SEC-VULN-2025" 📋
3. **VOIGHT logo** appears with random quote 💬
4. **[10-20] status codes** as it initializes ✅
5. **Data collection begins:**
   - Collecting from CISA KEV...
   - Collecting from GitHub Advisories...
   - Collecting from OpenCVE...
   - Collecting from RSS Feeds...
6. **Processing vulnerabilities:**
   - Matching to your devices
   - Calculating risk scores
   - AI analyzing critical ones (P0/P1)
7. **Sending notifications:**
   - Immediate alerts for critical CVEs
   - Digest summary to Teams and Email

**This takes 2-5 minutes depending on how many CVEs are found.**

---

## Step 5: Verify Notifications (1 minute)

### Check Teams:
- Open your Teams channel
- You should see a message from "VOIGHT Security Alerts"
- Contains CVE details, severity, matched devices

### Check Email:
- Open your inbox
- Look for email from your configured sender
- HTML-formatted with color-coded severity
- Includes CVE details, device matches, AI analysis

---

## What You Should See in Console:

```
[Siren animation with 🚨]

    Intelligence Unit - Active Monitoring

    ┌─────────────────────────────────────────┐
    │  INTELLIGENCE UNIT          │
    │ Case File: SEC-VULN-2025          │
    │ Lead Detective: VOIGHT                  │
    │ Status: [ACTIVE]                        │
    └─────────────────────────────────────────┘

   [VOIGHT ASCII logo]

        "We protect this city, no matter what"
        No vulnerability escapes the Intelligence Unit

    ✓ [10-4] Loading configuration
    ✓ [10-4] Initializing collectors
    ✓ [10-4] Setting up processors
    ✓ [10-4] Preparing notifiers

    [Code 4] All units operational. Intelligence Unit standing by.

🚀 Initializing SecVuln Agent...
    ✓ [10-4] Agent initialized successfully

    ✓ [10-4] Starting scan cycle at 2025-XX-XX...
    ✓ [10-4] Collecting from CISA KEV...
    ✓ [10-4] Collected 15 CVEs from CISA KEV
    ✓ [10-4] Collecting from GitHub Advisories...
    ✓ [10-4] Collected 23 CVEs from GitHub Advisories
    ...
    ✓ [10-4] Total unique CVEs collected: 47
    ✓ [10-4] Processed 12 vulnerabilities
    🚨 [10-33] Critical vulnerability detected: CVE-2024-XXXXX
    📢 [Signal 25] Sending immediate alert...
    ✓ [10-4] Alert sent successfully
    ✓ [10-4] Scan complete
```

---

## Troubleshooting Common Issues

### ❌ "No API key found"

**Fix:**
```powershell
python -c "from src.utils.secrets_manager import SecretsManager; sm = SecretsManager(); sm.store_provider_key('openai', 'sk-YOUR-API-KEY-HERE')"
```

### ❌ Teams webhook fails

**Test webhook:**
```powershell
# Install curl for Windows if needed, or use:
Invoke-RestMethod -Uri "YOUR_WEBHOOK_URL" -Method Post -Body '{"text":"Test from VOIGHT"}' -ContentType "application/json"
```

### ❌ Gmail "Authentication failed"

**You MUST use App Password:**
1. Enable 2FA: https://myaccount.google.com/security
2. Create App Password: https://myaccount.google.com/apppasswords
3. Use the 16-character password, NOT your Gmail password
4. Update config: `notepad config\config.yaml`

### ❌ Emoji/UTF-8 issues

**Fix:**
```powershell
# Set UTF-8 encoding
chcp 65001
python src\main.py
```

### ❌ No vulnerabilities found

**This is normal if:**
- No new CVEs in the last 24 hours matching your filters
- Rate limiting from sources (wait 10 mins)

**Check logs:**
```powershell
type logs\secvuln-agent.log
```

---

## Next Steps

### ✅ If everything worked:

1. **Let it run for the scheduled interval** (it will scan again in 1 hour)
2. **Review the CVEs** that were found and matched
3. **Adjust filters** if needed:
   ```powershell
   notepad config\config.yaml
   # Change min_cvss_score to 8.0 or 9.0 for less noise
   ```
4. **Fine-tune device inventory** with your actual devices
5. **Deploy to production** (see TESTING_GUIDE.md for Task Scheduler setup)

### 📊 Monitor Performance:

```powershell
# View logs
type logs\secvuln-agent.log

# Check database stats
python -c "from src.utils.db_handler import DatabaseHandler; db = DatabaseHandler(); print(db.get_cve_statistics())"

# View last 20 lines of log
powershell -command "Get-Content logs\secvuln-agent.log -Tail 20"
```

### 🔧 Adjust Configuration:

```powershell
# Edit config
notepad config\config.yaml

# Change interval to 6 hours for production
interval_hours: 6

# Adjust CVSS threshold
min_cvss_score: 8.0

# Enable/disable sources
```

---

## Production Deployment (Optional)

### Windows Task Scheduler (Recommended):

1. Open Task Scheduler (Win + R → `taskschd.msc`)
2. Create Basic Task → Name: "VOIGHT-SecVuln"
3. Trigger: "When computer starts"
4. Action: Start a program
   - Program: `C:\Projects\secvuln-agent\venv\Scripts\python.exe`
   - Arguments: `C:\Projects\secvuln-agent\src\main.py`
   - Start in: `C:\Projects\secvuln-agent`
5. ✅ Enable → Done!

Now VOIGHT runs automatically on system startup.

---

## File Locations

- **Configuration**: `config\config.yaml`
- **Devices**: `config\devices.csv`
- **Logs**: `logs\secvuln-agent.log`
- **Database**: `data\secvuln.db`
- **Reports**: `reports\` (CSV exports if enabled)

---

## Support

**For detailed guides, see:**
- `TESTING_GUIDE.md` - Complete testing instructions
- `UBUNTU_DEPLOYMENT.md` - Linux deployment guide
- `README.md` - Full documentation

**Check logs for errors:**
```powershell
type logs\secvuln-agent.log | findstr /i "error"
```

---

## 🎯 Success Checklist

After following this guide, you should have:

- [x] VOIGHT agent installed and configured
- [x] OpenAI API key stored securely
- [x] Teams webhook configured and tested
- [x] Email notifications working
- [x] Device inventory loaded
- [x] First scan completed successfully
- [x] Notifications received in Teams and Email
- [x] Database populated with CVEs
- [x] Logs showing successful operation

---

**[Code 4] VOIGHT Intelligence Unit is now protecting your infrastructure. Whatever it takes.** 🚨

**"This is my unit, we handle things our way."** - Det. Hank Voight
