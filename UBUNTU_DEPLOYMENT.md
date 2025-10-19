# Ubuntu Linux Deployment Guide - VOIGHT SecVuln Agent

Complete guide for deploying the SecVuln Agent on Ubuntu 20.04+ (also works on Debian-based distros).

---

## Part 1: Fresh Ubuntu Setup

### Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.8+ and dependencies
sudo apt install -y python3 python3-pip python3-venv git

# Install system dependencies
sudo apt install -y build-essential libssl-dev libffi-dev python3-dev

# Install keyring dependencies (for secure credential storage)
sudo apt install -y gnome-keyring libsecret-1-0 libsecret-1-dev
```

### Optional: Install Docker (if you want containerized deployment)

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group
sudo usermod -aG docker $USER

# Logout and login for group changes to take effect
```

---

## Part 2: Application Setup

### Step 1: Clone/Copy Project

**Option A: If you have the project on Windows, transfer it:**

```bash
# On Windows, zip the project
# Compress-Archive -Path C:\Projects\secvuln-agent -DestinationPath C:\Projects\secvuln-agent.zip

# Transfer to Ubuntu (using SCP, USB, or network share)
# Then on Ubuntu:
cd ~
unzip secvuln-agent.zip
cd secvuln-agent
```

**Option B: Fresh clone (if using git):**

```bash
cd ~
git clone https://github.com/yourusername/secvuln-agent.git
cd secvuln-agent
```

**Option C: Manual copy (if you have files locally):**

```bash
mkdir -p ~/secvuln-agent
# Copy files from your source
```

### Step 2: Create Virtual Environment

```bash
cd ~/secvuln-agent

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Fix File Permissions

```bash
# Make sure scripts are executable
chmod +x src/*.py

# Secure credentials directory (will be created by app)
mkdir -p ~/.secvuln-agent
chmod 700 ~/.secvuln-agent
```

### Step 4: Configure Keyring (Important for Ubuntu)

Ubuntu uses `gnome-keyring` for secure storage. Initialize it:

```bash
# Start gnome-keyring daemon (if not running)
eval $(gnome-keyring-daemon --start)
export $(gnome-keyring-daemon --start)

# Add to your shell profile for persistence
echo 'eval $(gnome-keyring-daemon --start)' >> ~/.bashrc
echo 'export $(gnome-keyring-daemon --start)' >> ~/.bashrc
```

**For headless servers (no GUI):**

If you're running Ubuntu Server without GUI:

```bash
# Install and use pass (password store) as backend
sudo apt install -y pass gpg

# Generate GPG key if you don't have one
gpg --gen-key

# Initialize pass
pass init "your-email@example.com"

# Or use plain file storage (less secure, but works)
# Edit src/utils/secrets_manager.py to use file-based storage
```

---

## Part 3: Initial Configuration

### Step 5: Run Setup Wizard

```bash
cd ~/secvuln-agent
source venv/bin/activate

# Run setup wizard
python src/setup_wizard.py
```

Configure as per the TESTING_GUIDE.md, but use appropriate values for Linux:

- **Agent name**: `VOIGHT-Ubuntu-01` (or your hostname)
- **Check interval**: `6 hours` (for production)
- **Data sources**: Enable all for comprehensive monitoring
- **AI provider**: OpenAI (enter your API key)
- **Notifications**: Teams + Email
- **Device inventory**: Add your infrastructure

### Step 6: Create/Edit Device Inventory

```bash
nano config/devices.csv
```

Add your devices:
```csv
device_id,device_type,vendor,product,version,criticality,location,notes
LB-01,load_balancer,nginx,nginx,1.24.0,critical,prod-vpc,Production load balancer
K8S-MASTER-01,container_runtime,Kubernetes,kubernetes,1.28.2,critical,prod-cluster,K8s master node
DB-REPLICA-01,database,MySQL,mysql,8.0.34,high,prod-db,MySQL replica
```

---

## Part 4: Test Run

### Step 7: First Manual Test

```bash
cd ~/secvuln-agent
source venv/bin/activate

# Run agent once
python src/main.py
```

**Watch for:**
- 🚨 VOIGHT animations (should work in Linux terminal)
- [10-4] Status messages
- Data collection from sources
- Notifications sent

**Verify:**
```bash
# Check logs
tail -f logs/secvuln-agent.log

# Check database
python -c "from src.utils.db_handler import DatabaseHandler; db = DatabaseHandler(); print(db.get_cve_statistics())"

# Check credentials are stored
ls -la ~/.secvuln-agent/
```

---

## Part 5: Production Deployment

### Option 1: Systemd Service (Recommended)

Create systemd service file:

```bash
sudo nano /etc/systemd/system/voight-secvuln.service
```

**Service file content:**

```ini
[Unit]
Description=VOIGHT Security Vulnerability Intelligence Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USERNAME
Group=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/secvuln-agent
Environment="PATH=/home/YOUR_USERNAME/secvuln-agent/venv/bin"
ExecStart=/home/YOUR_USERNAME/secvuln-agent/venv/bin/python /home/YOUR_USERNAME/secvuln-agent/src/main.py

# Restart on failure
Restart=on-failure
RestartSec=300

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/YOUR_USERNAME/secvuln-agent/logs /home/YOUR_USERNAME/secvuln-agent/data /home/YOUR_USERNAME/secvuln-agent/reports

# Logging
StandardOutput=append:/home/YOUR_USERNAME/secvuln-agent/logs/systemd-output.log
StandardError=append:/home/YOUR_USERNAME/secvuln-agent/logs/systemd-error.log

[Install]
WantedBy=multi-user.target
```

**Replace** `YOUR_USERNAME` with your actual username:
```bash
# Find your username
whoami

# Edit the service file and replace YOUR_USERNAME
```

**Enable and start the service:**

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable voight-secvuln.service

# Start service now
sudo systemctl start voight-secvuln.service

# Check status
sudo systemctl status voight-secvuln.service

# View logs
sudo journalctl -u voight-secvuln.service -f
```

**Service management commands:**

```bash
# Stop service
sudo systemctl stop voight-secvuln.service

# Restart service
sudo systemctl restart voight-secvuln.service

# Disable service
sudo systemctl disable voight-secvuln.service

# View recent logs
sudo journalctl -u voight-secvuln.service -n 100 --no-pager
```

---

### Option 2: Cron Job (Simple Scheduled Runs)

If you prefer periodic runs instead of continuous monitoring:

```bash
# Edit crontab
crontab -e

# Add entry for every 6 hours
0 */6 * * * cd /home/YOUR_USERNAME/secvuln-agent && /home/YOUR_USERNAME/secvuln-agent/venv/bin/python src/main.py >> logs/cron-output.log 2>&1

# Or every day at 9 AM
0 9 * * * cd /home/YOUR_USERNAME/secvuln-agent && /home/YOUR_USERNAME/secvuln-agent/venv/bin/python src/main.py >> logs/cron-output.log 2>&1
```

**Note:** Cron runs single scans. The agent's internal scheduler won't work with cron.

---

### Option 3: Docker Deployment

#### Build Docker Image:

```bash
cd ~/secvuln-agent

# Build image
docker build -t voight-secvuln:latest .

# Verify image
docker images | grep voight
```

#### Run Container:

```bash
# Create directories for persistent data
mkdir -p ~/secvuln-data/{config,data,logs,reports}

# Copy config files
cp config/config.yaml ~/secvuln-data/config/
cp config/devices.csv ~/secvuln-data/config/

# Run container
docker run -d \
  --name voight-secvuln \
  --restart unless-stopped \
  -v ~/secvuln-data/config:/app/config:ro \
  -v ~/secvuln-data/data:/app/data \
  -v ~/secvuln-data/logs:/app/logs \
  -v ~/secvuln-data/reports:/app/reports \
  -e PYTHONUNBUFFERED=1 \
  voight-secvuln:latest

# Check container status
docker ps | grep voight

# View logs
docker logs -f voight-secvuln

# Stop container
docker stop voight-secvuln

# Restart container
docker restart voight-secvuln
```

#### Docker Compose (Advanced):

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  voight-secvuln:
    build: .
    container_name: voight-secvuln
    restart: unless-stopped
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
      - ./reports:/app/reports
    environment:
      - PYTHONUNBUFFERED=1
      - TZ=America/New_York  # Set your timezone
    networks:
      - secvuln-network
    mem_limit: 512m
    cpus: 0.5

networks:
  secvuln-network:
    driver: bridge
```

Deploy:
```bash
docker-compose up -d
docker-compose logs -f
```

---

## Part 6: Monitoring & Maintenance

### Log Monitoring

```bash
# Real-time log monitoring
tail -f logs/secvuln-agent.log

# Search for errors
grep -i error logs/secvuln-agent.log

# Check critical alerts
grep "\[10-33\]" logs/secvuln-agent.log

# View last 100 lines
tail -n 100 logs/secvuln-agent.log
```

### Log Rotation

Create logrotate config:

```bash
sudo nano /etc/logrotate.d/voight-secvuln
```

**Content:**
```
/home/YOUR_USERNAME/secvuln-agent/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 YOUR_USERNAME YOUR_USERNAME
}
```

Test:
```bash
sudo logrotate -f /etc/logrotate.d/voight-secvuln
```

### Database Maintenance

```bash
# Backup database
cp data/secvuln.db data/secvuln.db.backup-$(date +%Y%m%d)

# Clean old data (older than 90 days)
python -c "
from src.utils.db_handler import DatabaseHandler
import sqlite3
db = DatabaseHandler()
db.conn.execute('DELETE FROM cve_tracking WHERE first_seen < datetime(\"now\", \"-90 days\")')
db.conn.commit()
print('Old CVEs cleaned')
"

# Vacuum database
python -c "from src.utils.db_handler import DatabaseHandler; db = DatabaseHandler(); db.conn.execute('VACUUM')"
```

### Health Check Script

Create `health_check.sh`:

```bash
#!/bin/bash
# Health check for VOIGHT SecVuln Agent

LOG_FILE="logs/secvuln-agent.log"
LAST_RUN=$(grep "Starting scan cycle" "$LOG_FILE" | tail -1)
AGE=$(( $(date +%s) - $(date -d "$(echo "$LAST_RUN" | awk '{print $4, $5}')" +%s 2>/dev/null || echo 0) ))

# Check if last run was within 24 hours
if [ $AGE -gt 86400 ]; then
    echo "[10-999] Agent not running! Last run: $AGE seconds ago"
    # Send alert
    exit 1
else
    echo "[10-4] Agent healthy. Last run: $AGE seconds ago"
    exit 0
fi
```

Run health check via cron:
```bash
crontab -e

# Add health check every hour
0 * * * * /home/YOUR_USERNAME/secvuln-agent/health_check.sh >> /home/YOUR_USERNAME/secvuln-agent/logs/health.log 2>&1
```

---

## Part 7: Security Hardening

### Firewall Configuration

```bash
# If running on a server, ensure outbound HTTPS is allowed
sudo ufw allow out 443/tcp
sudo ufw allow out 80/tcp

# For SMTP
sudo ufw allow out 587/tcp
sudo ufw allow out 465/tcp
```

### File Permissions

```bash
# Secure sensitive files
chmod 600 config/config.yaml
chmod 600 config/.env
chmod 700 ~/.secvuln-agent

# Secure database
chmod 600 data/secvuln.db

# Logs readable by user only
chmod 600 logs/*.log
```

### Credential Security

```bash
# Never store credentials in config files
# Always use SecretsManager

# Verify credentials are encrypted
ls -la ~/.secvuln-agent/
# Should show credentials.enc with 600 permissions
```

---

## Part 8: Troubleshooting Ubuntu-Specific Issues

### Issue 1: Keyring not available (headless server)

**Solution: Use file-based storage**

Edit `src/utils/secrets_manager.py` (around line 60):
```python
# Comment out keyring usage
# kr.set_password('secvuln-agent', service_name, encrypted_key.decode())

# Use file-only storage instead
# Keys will be stored encrypted in ~/.secvuln-agent/credentials.enc
```

### Issue 2: Permission denied errors

```bash
# Fix ownership
sudo chown -R $USER:$USER ~/secvuln-agent

# Fix permissions
chmod -R u+rw ~/secvuln-agent
chmod +x src/*.py
```

### Issue 3: Python not found

```bash
# Install Python 3.10+
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.10 python3.10-venv python3.10-dev

# Use python3.10 explicitly
python3.10 -m venv venv
```

### Issue 4: Animations not displaying correctly

```bash
# Ensure terminal supports UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Add to ~/.bashrc
echo 'export LANG=en_US.UTF-8' >> ~/.bashrc
echo 'export LC_ALL=en_US.UTF-8' >> ~/.bashrc
```

### Issue 5: Service won't start

```bash
# Check service logs
sudo journalctl -u voight-secvuln.service -n 50

# Check Python path
which python3

# Check working directory
ls -la /home/YOUR_USERNAME/secvuln-agent

# Check permissions
sudo -u YOUR_USERNAME python3 /home/YOUR_USERNAME/secvuln-agent/src/main.py
```

---

## Part 9: Ubuntu Server Best Practices

### Resource Limits

```bash
# Check memory usage
ps aux | grep python | grep secvuln

# Set memory limit (systemd)
# Add to service file:
MemoryMax=512M
MemoryHigh=400M
```

### Automatic Updates

```bash
# Enable unattended upgrades (Ubuntu)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# Update dependencies monthly
0 0 1 * * cd /home/YOUR_USERNAME/secvuln-agent && source venv/bin/activate && pip install --upgrade -r requirements.txt
```

### Backup Strategy

```bash
# Create backup script
nano ~/backup-secvuln.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/backup/secvuln"
DATE=$(date +%Y%m%d)

mkdir -p "$BACKUP_DIR"

# Backup database
cp ~/secvuln-agent/data/secvuln.db "$BACKUP_DIR/secvuln-$DATE.db"

# Backup config
tar -czf "$BACKUP_DIR/config-$DATE.tar.gz" ~/secvuln-agent/config/

# Keep only 30 days
find "$BACKUP_DIR" -mtime +30 -delete

echo "[10-4] Backup complete: $DATE"
```

Schedule:
```bash
chmod +x ~/backup-secvuln.sh
crontab -e

# Daily backup at 2 AM
0 2 * * * /home/YOUR_USERNAME/backup-secvuln.sh >> /home/YOUR_USERNAME/secvuln-agent/logs/backup.log 2>&1
```

---

## Part 10: Multi-Server Deployment

For monitoring multiple locations:

### Central Monitoring Server

```bash
# Install on central server
# Configure with all data sources
# Set lower interval (1-3 hours)
```

### Regional Agents

```bash
# Install on regional servers
# Configure with specific device inventory
# Set higher interval (12-24 hours)
# Use different Teams channels per region
```

### Load Balancing

```bash
# Stagger scan times to avoid overwhelming sources
# Server 1: Run at :00 minutes
# Server 2: Run at :20 minutes
# Server 3: Run at :40 minutes

# Edit config.yaml on each:
# Or use cron with different times
```

---

## Quick Reference Commands

```bash
# Service management
sudo systemctl status voight-secvuln.service
sudo systemctl restart voight-secvuln.service
sudo journalctl -u voight-secvuln.service -f

# Logs
tail -f logs/secvuln-agent.log
grep "\[10-33\]" logs/secvuln-agent.log

# Database stats
python -c "from src.utils.db_handler import DatabaseHandler; print(DatabaseHandler().get_cve_statistics())"

# Manual run
cd ~/secvuln-agent && source venv/bin/activate && python src/main.py

# Update code
cd ~/secvuln-agent
git pull  # if using git
sudo systemctl restart voight-secvuln.service
```

---

**[Code 4] VOIGHT Agent deployed on Ubuntu. Intelligence Unit operational.** 🚨
