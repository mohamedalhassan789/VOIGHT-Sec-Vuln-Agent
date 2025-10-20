"""
Setup Wizard for SecVuln Agent
Interactive configuration using questionary
"""

import questionary
import yaml
import csv
from pathlib import Path
import sys
import time

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.secrets_manager import SecretsManager
from utils.animations import (
    animated_header_setup,
    print_colored,
    print_status,
    print_box,
    celebrate,
    Colors
)


def run_setup_wizard():
    """Run interactive setup wizard."""
    # Show animated header
    animated_header_setup()
    time.sleep(0.5)

    config = {}
    devices = []

    # Agent Configuration
    print_colored("\n📋 AGENT CONFIGURATION", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    config['agent'] = {
        'name': questionary.text(
            "Agent name:",
            default="SecVuln-Agent"
        ).ask(),

        'interval_hours': int(questionary.select(
            "Check interval:",
            choices=['1 hour', '6 hours', '12 hours', '24 hours']
        ).ask().split()[0])
    }

    # Filters & Alert Mode
    print_colored("\n🔍 ALERT MODE & FILTERS", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    print_colored("\n📱 VOIGHT can monitor vulnerabilities in two ways:", Colors.YELLOW)
    print_colored("  • Device-Only: Alert ONLY for CVEs affecting YOUR devices", Colors.WHITE)
    print_colored("  • All CVEs: Alert for all critical CVEs + your devices\n", Colors.WHITE)

    alert_mode_choice = questionary.select(
        "Which alert mode do you prefer?",
        choices=[
            "Device-Only (Recommended - focused alerts)",
            "All CVEs (Stay informed about threat landscape)"
        ]
    ).ask()

    alert_mode = 'device-only' if 'Device-Only' in alert_mode_choice else 'all-cves'

    # Device CVSS threshold
    min_cvss_devices = float(questionary.select(
        "Minimum CVSS score for YOUR device alerts:",
        choices=['4.0 (Catch issues early)', '5.0 (Medium+)', '7.0 (High+Critical)']
    ).ask().split()[0])

    # All CVEs threshold (if all-cves mode)
    min_cvss_all = 7.0
    if alert_mode == 'all-cves':
        print_colored("\n💡 Note: Device CVEs are ALWAYS monitored regardless of CVSS.", Colors.YELLOW)
        min_cvss_all = float(questionary.select(
            "Minimum CVSS score for non-device CVEs:",
            choices=['7.0 (High+Critical)', '8.0 (Mostly Critical)', '9.0 (Critical only)']
        ).ask().split()[0])

    # Immediate alert thresholds
    immediate_alert_cvss = float(questionary.select(
        "Minimum CVSS for immediate alerts:",
        choices=['9.0 (Critical only)', '8.0 (High+Critical)', '7.0 (All high severity)']
    ).ask().split()[0])

    alert_on_cisa_kev = questionary.confirm(
        "Send immediate alerts for ALL CISA KEV vulnerabilities?",
        default=True
    ).ask()

    alert_on_exploit = questionary.confirm(
        "Send immediate alerts for vulnerabilities with public exploits?",
        default=True
    ).ask()

    config['filters'] = {
        'alert_mode': alert_mode,
        'min_cvss_devices': min_cvss_devices,
        'min_cvss_all': min_cvss_all,
        'immediate_alert_cvss': immediate_alert_cvss,
        'alert_on_cisa_kev': alert_on_cisa_kev,
        'alert_on_exploit': alert_on_exploit,

        # Legacy fields (kept for compatibility)
        'min_cvss_score': min_cvss_all,
        'severity_levels': ['critical', 'high'],
        'exploit_available': False,
        'kev_only': False,
        'age_days': 30
    }

    # Data Sources
    print_colored("\n📡 DATA SOURCES", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    sources_hot = questionary.checkbox(
            "Select hot feeds (check every run):",
            choices=[
                questionary.Choice("CISA KEV (Known Exploited)", checked=True),
                questionary.Choice("GitHub Advisories", checked=True),
                questionary.Choice("OpenCVE", checked=True),
            ]
        ).ask()

    sources_rss = questionary.checkbox(
        "Select RSS feeds:",
        choices=[
            questionary.Choice("Reddit r/netsec", checked=True),
            questionary.Choice("Packet Storm", checked=True),
            questionary.Choice("The Hacker News", checked=True)
        ]
    ).ask()

    config['sources'] = {
        'hot_feeds': {
            'cisa_kev': "CISA KEV (Known Exploited)" in sources_hot,
            'github_advisories': "GitHub Advisories" in sources_hot,
            'opencve': "OpenCVE" in sources_hot,
        },
        'rss_feeds': {
            'reddit_netsec': "Reddit r/netsec" in sources_rss,
            'packetstorm': "Packet Storm" in sources_rss,
            'hackernews': "The Hacker News" in sources_rss
        },
        'official_sources': {
            'nvd_api': True
        },
        'vendor_feeds': {
            'cisco_psirt': 'auto',
            'microsoft_msrc': 'auto',
            'redhat_cve': 'auto'
        }
    }

    # AI Configuration
    print_colored("\n🤖 AI ANALYSIS", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    ai_enabled = questionary.confirm(
        "Enable AI vulnerability analysis?",
        default=False
    ).ask()

    if ai_enabled:
        ai_provider = questionary.select(
            "Select AI provider:",
            choices=[
                "Anthropic Claude (Best reasoning)",
                "OpenAI GPT-4 (Popular)",
                "Google Gemini (Free tier)",
                "Ollama (Local - No API key)"
            ]
        ).ask()

        provider_map = {
            "Anthropic Claude (Best reasoning)": "anthropic",
            "OpenAI GPT-4 (Popular)": "openai",
            "Google Gemini (Free tier)": "google",
            "Ollama (Local - No API key)": "ollama"
        }

        provider = provider_map[ai_provider]

        config['ai'] = {
            'enabled': True,
            'provider': provider,
            'anthropic': {'model': 'claude-sonnet-4-5'},
            'openai': {'model': 'gpt-4o-mini'},
            'google': {'model': 'gemini-2.0-flash-exp'},
            'ollama': {
                'base_url': 'http://localhost:11434',
                'model': 'llama3.2'
            }
        }

        # Store API key if needed
        if provider != 'ollama':
            api_key = questionary.password(
                f"Enter {provider.capitalize()} API key:"
            ).ask()

            if api_key:
                secrets = SecretsManager()
                secrets.store_provider_key(provider, api_key)
                print_status(f"API key stored securely for {provider}", 'success')

    else:
        config['ai'] = {'enabled': False, 'provider': 'none'}

    # Notifications
    print_colored("\n📢 NOTIFICATIONS", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    notif_channels = questionary.checkbox(
        "Select notification channels:",
        choices=[
            "Slack",
            "Microsoft Teams",
            "Telegram",
            "Google Chat",
            "Email"
        ]
    ).ask()

    config['notifications'] = {
        'channels': {
            'slack': {'enabled': False, 'webhook_url': ''},
            'teams': {'enabled': False, 'webhook_url': ''},
            'telegram': {'enabled': False, 'bot_token': '', 'chat_id': ''},
            'gchat': {'enabled': False, 'webhook_url': ''},
            'email': {
                'enabled': False,
                'preset': 'gmail',
                'smtp_host': '',
                'smtp_port': 587,
                'use_tls': True,
                'use_ssl': False,
                'username': '',
                'password': '',
                'from_email': '',
                'to_emails': []
            }
        },
        'schedule': {},
        'max_immediate_per_hour': 5
    }

    # Notification frequency
    print_colored("\n📅 Notification Frequency", Colors.YELLOW)
    frequency_choice = questionary.select(
        "How often do you want notifications?",
        choices=[
            "Both (Immediate alerts + Daily digest) [Recommended]",
            "Immediate alerts only (Real-time for critical CVEs)",
            "Daily digest only (One summary per day)"
        ]
    ).ask()

    if 'Both' in frequency_choice:
        frequency = 'both'
        immediate_alerts = True
        digest_summary = True
    elif 'Immediate' in frequency_choice:
        frequency = 'immediate-only'
        immediate_alerts = True
        digest_summary = False
    else:
        frequency = 'digest-only'
        immediate_alerts = False
        digest_summary = True

    config['notifications']['schedule'] = {
        'frequency': frequency,
        'immediate_alerts': immediate_alerts,
        'digest_summary': digest_summary,
        'digest_time': '09:00'
    }

    # Initialize SecretsManager for storing notification credentials
    secrets = SecretsManager()

    for channel in notif_channels:
        channel_key = channel.lower().replace(' ', '').replace('microsoft', '')

        if channel == "Slack":
            webhook = questionary.text("Slack webhook URL:").ask()
            if webhook:
                # Store webhook URL securely
                secrets.store_webhook_url('slack', webhook)
                config['notifications']['channels']['slack'] = {
                    'enabled': True
                }
                print_status("Slack webhook URL stored securely", 'success')

        elif channel == "Microsoft Teams":
            webhook = questionary.text("Teams webhook URL:").ask()
            if webhook:
                # Store webhook URL securely
                secrets.store_webhook_url('teams', webhook)
                config['notifications']['channels']['teams'] = {
                    'enabled': True
                }
                print_status("Teams webhook URL stored securely", 'success')

        elif channel == "Telegram":
            bot_token = questionary.text("Telegram bot token:").ask()
            chat_id = questionary.text("Telegram chat ID:").ask()
            if bot_token and chat_id:
                # Store Telegram credentials securely
                secrets.store_telegram_credentials(bot_token, chat_id)
                config['notifications']['channels']['telegram'] = {
                    'enabled': True
                }
                print_status("Telegram credentials stored securely", 'success')

        elif channel == "Google Chat":
            webhook = questionary.text("Google Chat webhook URL:").ask()
            if webhook:
                # Store webhook URL securely
                secrets.store_webhook_url('gchat', webhook)
                config['notifications']['channels']['gchat'] = {
                    'enabled': True
                }
                print_status("Google Chat webhook URL stored securely", 'success')

        elif channel == "Email":
            print_colored("\n📧 Email Configuration", Colors.YELLOW)
            preset = questionary.select(
                "Select email provider:",
                choices=[
                    "Gmail",
                    "Outlook / Hotmail",
                    "Office 365",
                    "Yahoo",
                    "Custom SMTP"
                ]
            ).ask()

            preset_map = {
                "Gmail": "gmail",
                "Outlook / Hotmail": "outlook",
                "Office 365": "office365",
                "Yahoo": "yahoo",
                "Custom SMTP": "custom"
            }

            email_preset = preset_map[preset]

            # Get email credentials
            username = questionary.text(
                "Email address (username):",
                validate=lambda x: '@' in x or "Must be a valid email"
            ).ask()

            password = questionary.password(
                "Email password (or app-specific password):"
            ).ask()

            # Store credentials securely
            if username and password:
                secrets.store_email_credentials(username, password)
                print_status("Email credentials stored securely", 'success')

            # Get recipient emails
            recipients_input = questionary.text(
                "Recipient email addresses (comma-separated):",
                validate=lambda x: '@' in x or "Must contain at least one email"
            ).ask()

            recipients = [email.strip() for email in recipients_input.split(',')]

            # Email configuration (WITHOUT sensitive credentials)
            email_config = {
                'enabled': True,
                'preset': email_preset,
                'from_email': username,
                'to_emails': recipients,
                'smtp_port': 587,
                'use_tls': True,
                'use_ssl': False
            }

            # Custom SMTP configuration
            if email_preset == "custom":
                smtp_host = questionary.text("SMTP host:").ask()
                smtp_port = int(questionary.text("SMTP port:", default="587").ask())
                use_tls = questionary.confirm("Use TLS?", default=True).ask()
                use_ssl = questionary.confirm("Use SSL?", default=False).ask()

                email_config.update({
                    'smtp_host': smtp_host,
                    'smtp_port': smtp_port,
                    'use_tls': use_tls,
                    'use_ssl': use_ssl
                })

            config['notifications']['channels']['email'] = email_config
            print_status(f"Email configured for {len(recipients)} recipient(s)", 'success')

    # Advanced
    config['advanced'] = {
        'cache_duration_hours': 24,
        'max_results_per_run': 50,
        'export_csv': True
    }

    # Device Inventory
    print_colored("\n💻 DEVICE INVENTORY", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    device_option = questionary.select(
        "How would you like to configure your device inventory?",
        choices=[
            "Create sample devices",
            "Manual entry (I'll add devices)",
            "Skip for now"
        ]
    ).ask()

    if device_option == "Create sample devices":
        devices = [
            {
                'device_id': 'FW-001',
                'device_type': 'firewall',
                'vendor': 'Palo Alto',
                'product': 'PA-Series',
                'version': '10.2.3',
                'criticality': 'critical',
                'location': 'datacenter-1',
                'notes': 'Edge firewall'
            },
            {
                'device_id': 'SW-001',
                'device_type': 'switch',
                'vendor': 'Cisco',
                'product': 'Catalyst 9300',
                'version': '17.6.4',
                'criticality': 'high',
                'location': 'datacenter-1',
                'notes': 'Core switch'
            },
            {
                'device_id': 'DB-001',
                'device_type': 'database',
                'vendor': 'PostgreSQL',
                'product': 'PostgreSQL',
                'version': '14.5',
                'criticality': 'critical',
                'location': 'internal',
                'notes': 'Production DB'
            }
        ]

    # Save Configuration
    print_colored("\n💾 SAVING CONFIGURATION", Colors.CYAN, bold=True)
    print_colored("-" * 70, Colors.GRAY)

    # Create config directory
    project_root = Path(__file__).parent.parent
    config_dir = project_root / "config"
    config_dir.mkdir(exist_ok=True)

    # Save config.yaml
    config_path = config_dir / "config.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    print_status(f"Saved config.yaml to {config_path}", 'success')

    # Save devices.csv
    if devices:
        devices_path = config_dir / "devices.csv"
        with open(devices_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)
        print_status(f"Saved devices.csv to {devices_path}", 'success')

    # Celebration!
    print()
    celebrate()

    # Summary box
    summary_content = [
        f"Configuration: {config_path}",
    ]
    if devices:
        summary_content.append(f"Device inventory: {devices_path}")
    summary_content.extend([
        "",
        "To start the agent, run:",
        "  python src/main.py"
    ])

    print_box("✨ SETUP COMPLETE! ✨", summary_content, Colors.GREEN)
    print()


if __name__ == "__main__":
    try:
        run_setup_wizard()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(0)
