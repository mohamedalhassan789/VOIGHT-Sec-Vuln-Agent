"""
Reset Configuration Script
Clears all personal configuration and data to start fresh or prepare for sharing
"""

import os
import shutil
from pathlib import Path

def reset_configuration():
    """Reset all configuration and personal data."""
    project_root = Path(__file__).parent

    print("="*70)
    print(" VOIGHT SecVuln Agent - Configuration Reset")
    print("="*70)
    print("\nThis will delete:")
    print("  • config/config.yaml (all settings)")
    print("  • config/devices.csv (device inventory)")
    print("  • data/secvuln.db (database)")
    print("  • data/secrets.enc (API keys)")
    print("  • reports/*.csv (all reports)")
    print("\n⚠️  This action cannot be undone!")

    confirm = input("\nAre you sure you want to reset? (yes/no): ").strip().lower()

    if confirm != 'yes':
        print("\n❌ Reset cancelled.")
        return

    deleted_items = []

    # 1. Delete config files
    config_files = [
        project_root / 'config' / 'config.yaml',
        project_root / 'config' / 'devices.csv'
    ]

    for file_path in config_files:
        if file_path.exists():
            file_path.unlink()
            deleted_items.append(str(file_path.name))
            print(f"✓ Deleted {file_path.name}")

    # 2. Delete database
    db_path = project_root / 'data' / 'secvuln.db'
    if db_path.exists():
        db_path.unlink()
        deleted_items.append('secvuln.db')
        print(f"✓ Deleted secvuln.db")

    # 3. Delete secrets
    secrets_path = project_root / 'data' / 'secrets.enc'
    if secrets_path.exists():
        secrets_path.unlink()
        deleted_items.append('secrets.enc')
        print(f"✓ Deleted secrets.enc (API keys)")

    # 4. Delete all reports
    reports_dir = project_root / 'reports'
    if reports_dir.exists():
        report_count = len(list(reports_dir.glob('*.csv')))
        for report_file in reports_dir.glob('*.csv'):
            report_file.unlink()
        if report_count > 0:
            deleted_items.append(f'{report_count} CSV reports')
            print(f"✓ Deleted {report_count} CSV reports")

    # 5. Delete logs (optional)
    log_confirm = input("\nDelete logs as well? (yes/no): ").strip().lower()
    if log_confirm == 'yes':
        log_file = project_root / 'secvuln_agent.log'
        if log_file.exists():
            log_file.unlink()
            deleted_items.append('secvuln_agent.log')
            print(f"✓ Deleted secvuln_agent.log")

    print("\n" + "="*70)
    print("✅ RESET COMPLETE")
    print("="*70)

    if deleted_items:
        print("\nDeleted items:")
        for item in deleted_items:
            print(f"  • {item}")
    else:
        print("\nNo configuration files found. Already clean!")

    print("\n📋 Next Steps:")
    print("  1. Run setup wizard: python src/setup_wizard.py")
    print("  2. Configure your settings")
    print("  3. Add your devices to devices.csv")
    print("  4. Start the agent: python src/main.py")
    print()

if __name__ == "__main__":
    try:
        reset_configuration()
    except KeyboardInterrupt:
        print("\n\n❌ Reset cancelled by user")
    except Exception as e:
        print(f"\n❌ Error during reset: {e}")
