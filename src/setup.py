"""
SecVuln Agent - Interactive Setup Wizard
Configures alert preferences, notification settings, and device monitoring
"""

import os
import sys
import yaml
from pathlib import Path
from utils.animations import print_colored, print_status, Colors, animated_header_setup, print_box

def clear_screen():
    """Clear terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print setup wizard header."""
    animated_header_setup()
    print_colored("\n╔════════════════════════════════════════════════════════════╗", Colors.CYAN)
    print_colored("║        VOIGHT SecVuln Agent - Setup Wizard                 ║", Colors.CYAN, bold=True)
    print_colored("╚════════════════════════════════════════════════════════════╝\n", Colors.CYAN)

def ask_question(question, options, default=None):
    """
    Ask a multiple choice question.

    Args:
        question: Question text
        options: List of (key, description) tuples
        default: Default option key

    Returns:
        Selected option key
    """
    print_colored(f"\n{question}", Colors.YELLOW, bold=True)
    print()

    for i, (key, desc) in enumerate(options, 1):
        default_marker = " [DEFAULT]" if key == default else ""
        print_colored(f"  {i}. ", Colors.CYAN, end="")
        print_colored(f"{desc}{default_marker}", Colors.WHITE)

    print()
    while True:
        choice = input(f"Enter choice [1-{len(options)}]" + (f" (default: {options[[k for k, _ in options].index(default)] + 1}): " if default else ": "))

        if not choice and default:
            return default

        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(options):
                return options[choice_num - 1][0]
        except ValueError:
            pass

        print_colored("Invalid choice. Please try again.", Colors.RED)

def ask_number(question, min_val, max_val, default):
    """Ask for a number within range."""
    print_colored(f"\n{question}", Colors.YELLOW, bold=True)
    print_colored(f"(Range: {min_val} - {max_val})", Colors.WHITE)

    while True:
        value = input(f"Enter value (default: {default}): ")

        if not value:
            return default

        try:
            num = float(value)
            if min_val <= num <= max_val:
                return num
        except ValueError:
            pass

        print_colored(f"Invalid value. Must be between {min_val} and {max_val}.", Colors.RED)

def ask_yes_no(question, default=True):
    """Ask a yes/no question."""
    default_str = "Y/n" if default else "y/N"
    print_colored(f"\n{question}", Colors.YELLOW, bold=True)

    while True:
        choice = input(f"[{default_str}]: ").strip().lower()

        if not choice:
            return default

        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False

        print_colored("Please enter 'y' or 'n'.", Colors.RED)

def setup_alert_mode():
    """Configure alert mode (device-only vs all CVEs)."""
    print_box("Step 1: Alert Mode Configuration", Colors.CYAN)

    print_colored("\nVOIGHT can monitor vulnerabilities in two ways:\n", Colors.WHITE)
    print_colored("  📱 Device-Only Mode:", Colors.GREEN, bold=True)
    print_colored("     Only alerts you about CVEs affecting your specific devices", Colors.WHITE)
    print_colored("     (from devices.csv)", Colors.WHITE)
    print_colored("\n  🌐 All CVEs Mode:", Colors.BLUE, bold=True)
    print_colored("     Alerts about ALL critical CVEs, even if they don't affect", Colors.WHITE)
    print_colored("     your devices (keeps you informed about the threat landscape)", Colors.WHITE)

    mode = ask_question(
        "Which alert mode do you prefer?",
        [
            ('device-only', "Device-Only: Alert ONLY for CVEs affecting my devices"),
            ('all-cves', "All CVEs: Alert for all critical CVEs (+ my devices)")
        ],
        default='device-only'
    )

    min_cvss_all = 7.0
    if mode == 'all-cves':
        print_colored("\n💡 Note: Device CVEs are ALWAYS monitored regardless of CVSS.", Colors.YELLOW)
        min_cvss_all = ask_number(
            "What minimum CVSS score for non-device CVEs?",
            min_val=4.0,
            max_val=10.0,
            default=7.0
        )

    return mode, min_cvss_all

def setup_device_monitoring():
    """Configure device-specific monitoring."""
    print_box("Step 2: Device Monitoring Configuration", Colors.CYAN)

    print_colored("\n🔍 VOIGHT continuously monitors your devices 24/7:\n", Colors.WHITE)
    print_colored("  ✓ Scans for CVEs matching your devices.csv inventory", Colors.GREEN)
    print_colored("  ✓ Matches by vendor, product, and version", Colors.GREEN)
    print_colored("  ✓ Alerts immediately for critical device vulnerabilities", Colors.GREEN)

    min_cvss_devices = ask_number(
        "\nMinimum CVSS score for device-specific alerts?",
        min_val=0.0,
        max_val=10.0,
        default=4.0
    )

    print_colored("\n💡 Tip: Set this lower (4.0-7.0) to catch medium-severity issues", Colors.YELLOW)
    print_colored("   affecting YOUR devices before they become critical.", Colors.YELLOW)

    return min_cvss_devices

def setup_notification_frequency():
    """Configure notification frequency."""
    print_box("Step 3: Notification Frequency", Colors.CYAN)

    print_colored("\nHow often do you want to receive notifications?\n", Colors.WHITE)

    options = [
        ('immediate-only', "Immediate Alerts Only: Real-time notifications for critical CVEs"),
        ('digest-only', "Daily Digest Only: One email/message per day with all CVEs"),
        ('both', "Both: Immediate alerts for critical + daily digest summary")
    ]

    frequency = ask_question(
        "Choose notification frequency:",
        options,
        default='both'
    )

    return frequency

def setup_scan_interval():
    """Configure scan interval."""
    print_box("Step 4: Scan Interval", Colors.CYAN)

    print_colored("\nHow often should VOIGHT check for new vulnerabilities?\n", Colors.WHITE)
    print_colored("  ⚡ 1 hour:  Maximum responsiveness (recommended for production)", Colors.GREEN)
    print_colored("  🕐 6 hours: Balanced (good for most users)", Colors.BLUE)
    print_colored("  📅 24 hours: Daily checks only", Colors.YELLOW)

    interval_options = [
        (1, "Every 1 hour (maximum protection)"),
        (2, "Every 2 hours"),
        (6, "Every 6 hours (balanced)"),
        (12, "Every 12 hours"),
        (24, "Every 24 hours (daily)")
    ]

    interval = ask_question(
        "Select scan interval:",
        interval_options,
        default=6
    )

    return interval

def setup_immediate_alerts():
    """Configure immediate alert thresholds."""
    print_box("Step 5: Immediate Alert Thresholds", Colors.CYAN)

    print_colored("\n🚨 Immediate alerts are triggered for:\n", Colors.WHITE)
    print_colored("  • CVSS scores above threshold", Colors.WHITE)
    print_colored("  • CVEs in CISA KEV (Known Exploited Vulnerabilities)", Colors.WHITE)
    print_colored("  • CVEs with public exploits available", Colors.WHITE)

    cvss_threshold = ask_number(
        "\nMinimum CVSS score for immediate alerts?",
        min_val=7.0,
        max_val=10.0,
        default=9.0
    )

    alert_cisa_kev = ask_yes_no(
        "Send immediate alerts for ALL CISA KEV vulnerabilities?",
        default=True
    )

    alert_exploits = ask_yes_no(
        "Send immediate alerts for vulnerabilities with public exploits?",
        default=True
    )

    return cvss_threshold, alert_cisa_kev, alert_exploits

def review_configuration(config):
    """Display configuration summary for review."""
    print_box("Configuration Summary", Colors.GREEN)

    print_colored("\n📋 Your VOIGHT Agent Configuration:\n", Colors.CYAN, bold=True)

    # Alert mode
    mode = config['filters']['alert_mode']
    mode_display = "Device-Only Mode" if mode == 'device-only' else "All CVEs Mode"
    print_colored(f"  Alert Mode: ", Colors.YELLOW, end="")
    print_colored(mode_display, Colors.WHITE, bold=True)

    # CVSS thresholds
    print_colored(f"\n  CVSS Thresholds:", Colors.YELLOW)
    print_colored(f"    • Device CVEs: {config['filters']['min_cvss_devices']}", Colors.WHITE)
    if mode == 'all-cves':
        print_colored(f"    • Non-Device CVEs: {config['filters']['min_cvss_all']}", Colors.WHITE)
    print_colored(f"    • Immediate Alerts: {config['filters']['immediate_alert_cvss']}", Colors.WHITE)

    # Notification settings
    frequency = config['notifications']['schedule']['frequency']
    freq_display = {
        'immediate-only': 'Immediate Alerts Only',
        'digest-only': 'Daily Digest Only',
        'both': 'Immediate + Daily Digest'
    }[frequency]
    print_colored(f"\n  Notifications: ", Colors.YELLOW, end="")
    print_colored(freq_display, Colors.WHITE, bold=True)

    # Alert triggers
    print_colored(f"\n  Immediate Alert Triggers:", Colors.YELLOW)
    print_colored(f"    • CVSS ≥ {config['filters']['immediate_alert_cvss']}: ✓", Colors.GREEN)
    print_colored(f"    • CISA KEV: {'✓' if config['filters']['alert_on_cisa_kev'] else '✗'}", Colors.GREEN if config['filters']['alert_on_cisa_kev'] else Colors.RED)
    print_colored(f"    • Has Exploit: {'✓' if config['filters']['alert_on_exploit'] else '✗'}", Colors.GREEN if config['filters']['alert_on_exploit'] else Colors.RED)

    # Scan interval
    interval = config['agent']['interval_hours']
    print_colored(f"\n  Scan Interval: ", Colors.YELLOW, end="")
    print_colored(f"Every {interval} hour(s)", Colors.WHITE, bold=True)

    # Device monitoring
    print_colored(f"\n  Device Monitoring: ", Colors.YELLOW, end="")
    print_colored("✓ ENABLED 24/7", Colors.GREEN, bold=True)
    print_colored(f"    Monitoring devices from: devices.csv", Colors.WHITE)

    print()

def save_configuration(config, config_path):
    """Save configuration to config.yaml."""
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        print_colored(f"\n✗ Error saving configuration: {e}", Colors.RED)
        return False

def main():
    """Run setup wizard."""
    clear_screen()
    print_header()

    print_colored("Welcome to the VOIGHT SecVuln Agent Setup Wizard!", Colors.GREEN, bold=True)
    print_colored("\nThis wizard will help you configure:", Colors.WHITE)
    print_colored("  • Alert mode (device-only vs all CVEs)", Colors.WHITE)
    print_colored("  • Notification frequency and thresholds", Colors.WHITE)
    print_colored("  • Scan interval and monitoring settings", Colors.WHITE)
    print_colored("\nPress Enter to continue...", Colors.CYAN)
    input()

    # Step 1: Alert mode
    clear_screen()
    print_header()
    alert_mode, min_cvss_all = setup_alert_mode()

    # Step 2: Device monitoring
    clear_screen()
    print_header()
    min_cvss_devices = setup_device_monitoring()

    # Step 3: Notification frequency
    clear_screen()
    print_header()
    frequency = setup_notification_frequency()

    # Step 4: Scan interval
    clear_screen()
    print_header()
    scan_interval = setup_scan_interval()

    # Step 5: Immediate alerts (only if frequency includes immediate)
    cvss_immediate = 9.0
    alert_cisa_kev = True
    alert_exploits = True

    if frequency in ['immediate-only', 'both']:
        clear_screen()
        print_header()
        cvss_immediate, alert_cisa_kev, alert_exploits = setup_immediate_alerts()

    # Build configuration
    config_path = Path(__file__).parent.parent / 'config' / 'config.yaml'

    # Load existing config
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except:
        config = {}

    # Update with new settings
    if 'agent' not in config:
        config['agent'] = {}
    config['agent']['interval_hours'] = scan_interval

    if 'filters' not in config:
        config['filters'] = {}

    config['filters']['alert_mode'] = alert_mode
    config['filters']['min_cvss_devices'] = min_cvss_devices
    config['filters']['min_cvss_all'] = min_cvss_all
    config['filters']['immediate_alert_cvss'] = cvss_immediate
    config['filters']['alert_on_cisa_kev'] = alert_cisa_kev
    config['filters']['alert_on_exploit'] = alert_exploits

    if 'notifications' not in config:
        config['notifications'] = {}
    if 'schedule' not in config['notifications']:
        config['notifications']['schedule'] = {}

    config['notifications']['schedule']['frequency'] = frequency
    config['notifications']['schedule']['immediate_alerts'] = frequency in ['immediate-only', 'both']
    config['notifications']['schedule']['digest_summary'] = frequency in ['digest-only', 'both']

    # Review configuration
    clear_screen()
    print_header()
    review_configuration(config)

    print_colored("\n" + "="*60, Colors.CYAN)
    confirm = ask_yes_no("\nSave this configuration?", default=True)

    if confirm:
        if save_configuration(config, config_path):
            print_colored("\n✓ Configuration saved successfully!", Colors.GREEN, bold=True)
            print_colored(f"  Config file: {config_path}", Colors.WHITE)

            print_colored("\n🚀 Next Steps:", Colors.CYAN, bold=True)
            print_colored("  1. Review/update your devices.csv file", Colors.WHITE)
            print_colored("  2. Configure notification channels (email/Teams/Slack)", Colors.WHITE)
            print_colored("  3. Run: python src/main.py", Colors.WHITE)

            print_colored("\n💡 Device Monitoring:", Colors.YELLOW, bold=True)
            print_colored("  Your devices are now monitored 24/7!", Colors.GREEN)
            print_colored("  Update devices.csv anytime - changes take effect on next scan.", Colors.WHITE)

            print_status("\nSetup complete!", 'success')
        else:
            print_status("\nSetup failed!", 'error')
            sys.exit(1)
    else:
        print_colored("\nSetup cancelled.", Colors.YELLOW)
        sys.exit(0)

if __name__ == "__main__":
    main()
