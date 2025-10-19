"""
Credential Migration Script
Migrates notification credentials from config.yaml to encrypted storage
"""

import sys
import yaml
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from utils.secrets_manager import SecretsManager


def migrate_credentials():
    """Migrate credentials from config.yaml to encrypted storage."""
    project_root = Path(__file__).parent
    config_path = project_root / 'config' / 'config.yaml'

    print("=" * 70)
    print(" VOIGHT SecVuln Agent - Credential Migration")
    print("=" * 70)
    print("\n🔐 This script will migrate your notification credentials to encrypted storage.")
    print("\n⚠️  WARNING: This will:")
    print("  • Read credentials from config/config.yaml")
    print("  • Encrypt and store them securely")
    print("  • Remove sensitive credentials from config.yaml")
    print("\n💡 After migration:")
    print("  • config.yaml will only contain non-sensitive settings")
    print("  • Credentials will be stored in encrypted format")
    print("  • You can safely share config.yaml (it won't have secrets)\n")

    # Check if config exists
    if not config_path.exists():
        print(f"\n❌ Configuration file not found: {config_path}")
        print("   Run setup wizard first: python src/setup_wizard.py")
        return

    # Read config
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    if not config:
        print("\n❌ Configuration file is empty")
        return

    # Initialize SecretsManager
    secrets = SecretsManager()

    # Track what was migrated
    migrated_items = []
    channels_updated = {}

    # Get notifications section
    notifications = config.get('notifications', {})
    channels = notifications.get('channels', {})

    print("\n🔍 Scanning for credentials to migrate...\n")

    # 1. Migrate Email credentials
    if channels.get('email', {}).get('enabled'):
        email_config = channels['email']
        username = email_config.get('username')
        password = email_config.get('password')

        if username and password:
            print(f"✓ Found email credentials (username: {username})")
            secrets.store_email_credentials(username, password)
            migrated_items.append(f"Email credentials ({username})")

            # Remove sensitive data from config
            del email_config['username']
            del email_config['password']
            channels_updated['email'] = True

    # 2. Migrate Slack webhook
    if channels.get('slack', {}).get('enabled'):
        slack_config = channels['slack']
        webhook_url = slack_config.get('webhook_url')

        if webhook_url and webhook_url.strip():
            print(f"✓ Found Slack webhook URL")
            secrets.store_webhook_url('slack', webhook_url)
            migrated_items.append("Slack webhook URL")

            # Remove webhook from config
            del slack_config['webhook_url']
            channels_updated['slack'] = True

    # 3. Migrate Teams webhook
    if channels.get('teams', {}).get('enabled'):
        teams_config = channels['teams']
        webhook_url = teams_config.get('webhook_url')

        if webhook_url and webhook_url.strip():
            print(f"✓ Found Teams webhook URL")
            secrets.store_webhook_url('teams', webhook_url)
            migrated_items.append("Teams webhook URL")

            # Remove webhook from config
            del teams_config['webhook_url']
            channels_updated['teams'] = True

    # 4. Migrate Telegram credentials
    if channels.get('telegram', {}).get('enabled'):
        telegram_config = channels['telegram']
        bot_token = telegram_config.get('bot_token')
        chat_id = telegram_config.get('chat_id')

        if bot_token and chat_id:
            print(f"✓ Found Telegram credentials (chat_id: {chat_id})")
            secrets.store_telegram_credentials(bot_token, chat_id)
            migrated_items.append(f"Telegram credentials (chat_id: {chat_id})")

            # Remove credentials from config
            del telegram_config['bot_token']
            del telegram_config['chat_id']
            channels_updated['telegram'] = True

    # 5. Migrate Google Chat webhook
    if channels.get('gchat', {}).get('enabled'):
        gchat_config = channels['gchat']
        webhook_url = gchat_config.get('webhook_url')

        if webhook_url and webhook_url.strip():
            print(f"✓ Found Google Chat webhook URL")
            secrets.store_webhook_url('gchat', webhook_url)
            migrated_items.append("Google Chat webhook URL")

            # Remove webhook from config
            del gchat_config['webhook_url']
            channels_updated['gchat'] = True

    # Check if anything was migrated
    if not migrated_items:
        print("\n✅ No credentials found in config.yaml")
        print("   All credentials are already encrypted or no notification channels configured.")
        return

    # Save updated config
    print(f"\n💾 Updating configuration file...")

    # Create backup
    backup_path = config_path.with_suffix('.yaml.backup')
    with open(config_path, 'r') as f_in:
        with open(backup_path, 'w') as f_out:
            f_out.write(f_in.read())
    print(f"   ✓ Backup created: {backup_path}")

    # Save cleaned config
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    print(f"   ✓ Updated config saved: {config_path}")

    # Summary
    print("\n" + "=" * 70)
    print("✅ MIGRATION COMPLETE")
    print("=" * 70)

    print("\n📊 Migrated credentials:")
    for item in migrated_items:
        print(f"  • {item}")

    print("\n🔐 Credentials are now stored securely in:")
    print(f"  {secrets.CREDENTIALS_FILE}")

    print("\n📋 Updated channels in config.yaml:")
    for channel in channels_updated.keys():
        print(f"  • {channel} (credentials removed)")

    print("\n✅ Your config.yaml is now safe to share!")
    print("   It no longer contains sensitive credentials.")

    print("\n📝 Backup:")
    print(f"  Original config backed up to: {backup_path}")

    print("\n💡 Next steps:")
    print("  1. Verify the agent still works: python src/main.py")
    print("  2. If everything works, you can delete the backup file")
    print("  3. Your credentials are now encrypted!")
    print()


if __name__ == "__main__":
    try:
        migrate_credentials()
    except KeyboardInterrupt:
        print("\n\n❌ Migration cancelled by user")
    except Exception as e:
        print(f"\n❌ Error during migration: {e}")
        import traceback
        traceback.print_exc()
