# VOIGHT SecVuln Agent - Sharing & Reset Guide

## 🔄 How to Reset Your Configuration

If you want to start fresh or prepare the tool for sharing, use the reset script:

### Quick Reset

```bash
# Run the reset script
python reset_config.py

# Answer the prompts:
# - Type 'yes' to confirm reset
# - Choose whether to delete logs

# Then run setup again:
python src/setup_wizard.py
```

### What Gets Deleted

The reset script removes:
- ✅ `config/config.yaml` - All your settings
- ✅ `config/devices.csv` - Your device inventory
- ✅ `data/secvuln.db` - CVE database
- ✅ `data/secrets.enc` - Encrypted API keys
- ✅ `reports/*.csv` - All scan reports
- ✅ `*.log` files (optional)

### What Stays

- ✅ All Python source code
- ✅ Default template files
- ✅ Documentation
- ✅ Virtual environment

---

## 📤 How to Share This Tool with Friends

### Method 1: Clean Share (Recommended)

**Step 1: Reset Your Configuration**
```bash
python reset_config.py
# Type 'yes' to confirm
```

**Step 2: Copy the Project Folder**
```bash
# Copy the entire project folder
xcopy /E /I C:\Projects\secvuln-agent C:\Path\To\Share\secvuln-agent

# Or compress to ZIP
# Right-click folder → Send to → Compressed (zipped) folder
```

**Step 3: Share the Clean Copy**
- Send the ZIP file or copy to your friends
- They can extract and run `python src/setup_wizard.py`
- No personal data will be included!

---

### Method 2: Manual Cleanup (If You Forget to Reset)

**Before sharing, delete these files manually:**

```bash
# Delete personal configuration
del /Q config\config.yaml
del /Q config\devices.csv

# Delete database and secrets
del /Q data\secvuln.db
del /Q data\secrets.enc

# Delete reports
del /Q reports\*.csv

# Delete logs
del /Q *.log
```

**Then share the folder.**

---

### Method 3: Git Repository (Best for Collaboration)

If you're using Git, the `.gitignore` file already excludes personal data:

```bash
# Initialize git (if not already done)
cd C:\Projects\secvuln-agent
git init

# Add files (personal data is automatically excluded)
git add .

# Commit
git commit -m "Initial commit - VOIGHT SecVuln Agent"

# Share via GitHub/GitLab
git remote add origin https://github.com/yourusername/secvuln-agent.git
git push -u origin main
```

**Files automatically excluded by .gitignore:**
- ❌ `config/config.yaml`
- ❌ `config/devices.csv`
- ❌ `data/secvuln.db`
- ❌ `data/secrets.enc`
- ❌ `reports/*.csv`
- ❌ `*.log`

---

## ✅ Verify Before Sharing

**Checklist to ensure no personal data:**

```bash
# Check these files DON'T exist:
dir config\config.yaml     # Should say "File Not Found"
dir config\devices.csv     # Should say "File Not Found"
dir data\secvuln.db        # Should say "File Not Found"
dir data\secrets.enc       # Should say "File Not Found"
```

If any of these files exist, **DO NOT SHARE** until you delete them!

---

## 🚀 Setup Instructions for Your Friends

**Send these instructions to your friends:**

### 1. Extract the Tool
```bash
# Extract the ZIP file
# Navigate to the extracted folder
cd secvuln-agent
```

### 2. Install Dependencies
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On Linux/Mac:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Run Setup Wizard
```bash
# Run the interactive setup
python src/setup_wizard.py

# Answer all questions:
# - Agent name and scan interval
# - Alert mode (device-only or all-cves)
# - Device monitoring thresholds
# - Data sources to monitor
# - AI analysis (optional)
# - Notification channels (email, Teams, etc.)
# - Device inventory
```

### 4. Configure API Keys (if needed)

**For AI Analysis:**
- Anthropic: https://console.anthropic.com/
- OpenAI: https://platform.openai.com/api-keys
- Google: https://aistudio.google.com/app/apikey

**For Vulnerability Feeds:**
- OpenCVE: https://www.opencve.io/ (free)
- NVD: https://nvd.nist.gov/developers/request-an-api-key (free)

### 5. Run the Agent
```bash
# Start monitoring
python src/main.py

# The agent will:
# ✓ Scan for vulnerabilities every X hours
# ✓ Match CVEs to your devices
# ✓ Send immediate alerts for critical issues
# ✓ Generate daily digest emails
# ✓ Create CSV reports
```

---

## ⚠️ Important Notes

### For the Person Sharing:
- ✅ Always reset before sharing
- ✅ Never share with config files
- ✅ Never share database or reports
- ✅ Never share API keys
- ✅ Check the ZIP/folder before sending

### For the Person Receiving:
- ✅ Run setup wizard first
- ✅ Create your own config
- ✅ Add your own devices
- ✅ Use your own API keys
- ✅ Don't copy someone else's config!

---

## 📋 File Structure (What to Share)

### ✅ Include These (Safe to Share):
```
secvuln-agent/
├── src/                          # All Python source code
│   ├── collectors/               # Data collectors
│   ├── processors/               # CVE processors
│   ├── notifiers/                # Notification channels
│   ├── utils/                    # Utility functions
│   ├── setup_wizard.py           # Setup script
│   └── main.py                   # Main agent
├── config/                       # Config directory (empty)
│   └── config.yaml.example       # Template (if exists)
├── data/                         # Data directory (empty)
├── reports/                      # Reports directory (empty)
├── requirements.txt              # Python dependencies
├── README.md                     # Documentation
├── SETUP_GUIDE.md                # Setup guide
├── .gitignore                    # Git ignore rules
└── reset_config.py               # Reset script
```

### ❌ Never Include These (Personal Data):
```
config/config.yaml                # Your settings
config/devices.csv                # Your devices
data/secvuln.db                   # Your CVE database
data/secrets.enc                  # Your API keys
reports/*.csv                     # Your vulnerability reports
*.log                             # Your logs
```

---

## 🔐 Security Best Practices

### When Sharing:
1. **Always reset first** - Use `python reset_config.py`
2. **Verify clean** - Check no personal files exist
3. **Use .gitignore** - If sharing via Git
4. **Don't rush** - Double-check before sending

### When Receiving:
1. **Don't use someone else's config** - Run setup yourself
2. **Use your own API keys** - Don't share keys
3. **Create your own device inventory** - Don't use theirs
4. **Customize to your needs** - Adjust thresholds

---

## 🆘 Troubleshooting

### "I accidentally shared my config!"
1. **Don't panic** - But act quickly
2. **Delete/recreate API keys** immediately
3. **Change email passwords** if they were in config
4. **Review who received the files**
5. **Ask them to delete the config files**

### "I want to start over"
```bash
# Just run reset and setup again:
python reset_config.py
python src/setup_wizard.py
```

### "My friend's setup doesn't work"
1. Check they ran `pip install -r requirements.txt`
2. Verify they ran `python src/setup_wizard.py`
3. Check config/config.yaml was created
4. Review logs for errors

---

## 📚 Additional Resources

- **Setup Guide**: See `SETUP_GUIDE.md` for detailed configuration
- **User Guide**: See `README.md` for usage instructions
- **Feature Summary**: See `SETUP_WIZARD_FEATURES.md` for new features

---

## 🤝 Support

If you or your friends need help:
1. Check the documentation files
2. Review the setup wizard prompts
3. Check agent logs for errors
4. Run `python src/setup_wizard.py` again to reconfigure

---

**Remember: The goal is to share the TOOL, not your personal DATA!**

Always reset before sharing, and everyone should run their own setup. This ensures privacy and proper configuration for each user's environment.

---

**Generated:** 2025-01-18
**VOIGHT SecVuln Agent v2.0**
