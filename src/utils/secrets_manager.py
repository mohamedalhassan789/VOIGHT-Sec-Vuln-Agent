"""
Secure API Key Storage Manager
Handles encryption and secure storage of API keys using OS-level keyring
"""

import os
import json
import keyring
from pathlib import Path
from cryptography.fernet import Fernet
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)

class SecretsManager:
    """
    Manages secure storage and retrieval of API keys and secrets.
    Uses cryptography.fernet for encryption and OS keyring for key storage.
    """

    SERVICE_NAME = "secvuln-agent"
    ENCRYPTION_KEY_NAME = "encryption_key"
    CREDENTIALS_DIR = Path.home() / ".secvuln-agent"
    CREDENTIALS_FILE = CREDENTIALS_DIR / "credentials.enc"
    KEY_FILE = CREDENTIALS_DIR / "key.enc"  # Fallback key file for headless systems

    def __init__(self):
        """Initialize the secrets manager and ensure secure storage is set up."""
        self._ensure_credentials_dir()
        self._keyring_available = self._check_keyring_availability()
        self._encryption_key = self._get_or_create_encryption_key()
        self._fernet = Fernet(self._encryption_key)

    def _ensure_credentials_dir(self):
        """Create credentials directory with secure permissions."""
        self.CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)

        # Set secure permissions on Unix systems (0o700 = rwx------)
        if os.name != 'nt':  # Not Windows
            os.chmod(self.CREDENTIALS_DIR, 0o700)

    def _check_keyring_availability(self) -> bool:
        """
        Check if OS keyring is available and functional.

        Returns:
            bool: True if keyring is available, False otherwise
        """
        try:
            # Try to access keyring
            keyring.get_password(self.SERVICE_NAME, "test_availability")
            logger.debug("OS keyring is available")
            return True
        except Exception as e:
            logger.warning(f"OS keyring not available ({e.__class__.__name__}), falling back to file-based storage")
            return False

    def _get_or_create_encryption_key(self) -> bytes:
        """
        Get encryption key from OS keyring or file (fallback) or create a new one.

        Returns:
            bytes: The encryption key for Fernet
        """
        if self._keyring_available:
            # Try to get existing key from keyring
            try:
                stored_key = keyring.get_password(self.SERVICE_NAME, self.ENCRYPTION_KEY_NAME)
                if stored_key:
                    logger.debug("Retrieved encryption key from OS keyring")
                    return stored_key.encode()
            except Exception as e:
                logger.warning(f"Failed to retrieve key from keyring: {e}")
                self._keyring_available = False

        # Fallback: Use file-based key storage
        if self.KEY_FILE.exists():
            try:
                with open(self.KEY_FILE, 'rb') as f:
                    stored_key = f.read()

                # Set secure permissions
                if os.name != 'nt':
                    os.chmod(self.KEY_FILE, 0o600)

                logger.debug("Retrieved encryption key from file (headless mode)")
                return stored_key
            except Exception as e:
                logger.error(f"Failed to read key file: {e}")

        # Create new encryption key
        new_key = Fernet.generate_key()

        # Try to store in keyring first
        if self._keyring_available:
            try:
                keyring.set_password(self.SERVICE_NAME, self.ENCRYPTION_KEY_NAME, new_key.decode())
                logger.info("Created new encryption key and stored in OS keyring")
                return new_key
            except Exception as e:
                logger.warning(f"Failed to store key in keyring: {e}")
                self._keyring_available = False

        # Fallback: Store in file
        try:
            with open(self.KEY_FILE, 'wb') as f:
                f.write(new_key)

            # Set secure permissions
            if os.name != 'nt':
                os.chmod(self.KEY_FILE, 0o600)

            logger.info("Created new encryption key and stored in file (headless mode)")
            logger.warning("Running in headless mode - encryption key stored in file, not OS keyring")
            return new_key
        except Exception as e:
            logger.error(f"Failed to create key file: {e}")
            raise

    def _load_credentials(self) -> Dict[str, str]:
        """
        Load and decrypt credentials from file.

        Returns:
            Dict[str, str]: Dictionary of provider -> encrypted_api_key
        """
        if not self.CREDENTIALS_FILE.exists():
            return {}

        try:
            # Set secure permissions on Unix
            if os.name != 'nt':
                os.chmod(self.CREDENTIALS_FILE, 0o600)

            with open(self.CREDENTIALS_FILE, 'rb') as f:
                encrypted_data = f.read()

            if not encrypted_data:
                return {}

            decrypted_data = self._fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())

        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            return {}

    def _save_credentials(self, credentials: Dict[str, str]):
        """
        Encrypt and save credentials to file.

        Args:
            credentials: Dictionary of provider -> encrypted_api_key
        """
        try:
            json_data = json.dumps(credentials).encode()
            encrypted_data = self._fernet.encrypt(json_data)

            with open(self.CREDENTIALS_FILE, 'wb') as f:
                f.write(encrypted_data)

            # Set secure permissions on Unix (0o600 = rw-------)
            if os.name != 'nt':
                os.chmod(self.CREDENTIALS_FILE, 0o600)

            logger.debug(f"Saved encrypted credentials to {self.CREDENTIALS_FILE}")

        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            raise

    def store_provider_key(self, provider: str, api_key: str):
        """
        Store an API key for a specific provider.

        Args:
            provider: Name of the provider (e.g., 'anthropic', 'openai', 'google')
            api_key: The API key to store securely
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")

        credentials = self._load_credentials()

        # Encrypt the API key
        encrypted_key = self._fernet.encrypt(api_key.encode()).decode()
        credentials[provider] = encrypted_key

        self._save_credentials(credentials)
        logger.info(f"Stored API key for provider: {provider}")

    def get_provider_key(self, provider: str) -> Optional[str]:
        """
        Retrieve and decrypt an API key for a specific provider.

        Args:
            provider: Name of the provider (e.g., 'anthropic', 'openai', 'google')

        Returns:
            str: The decrypted API key, or None if not found
        """
        credentials = self._load_credentials()

        encrypted_key = credentials.get(provider)
        if not encrypted_key:
            logger.warning(f"No API key found for provider: {provider}")
            return None

        try:
            decrypted_key = self._fernet.decrypt(encrypted_key.encode()).decode()
            return decrypted_key
        except Exception as e:
            logger.error(f"Failed to decrypt API key for {provider}: {e}")
            return None

    def remove_provider_key(self, provider: str) -> bool:
        """
        Remove an API key for a specific provider.

        Args:
            provider: Name of the provider to remove

        Returns:
            bool: True if key was removed, False if not found
        """
        credentials = self._load_credentials()

        if provider in credentials:
            del credentials[provider]
            self._save_credentials(credentials)
            logger.info(f"Removed API key for provider: {provider}")
            return True

        logger.warning(f"No API key found to remove for provider: {provider}")
        return False

    def list_providers(self) -> list:
        """
        List all providers that have stored API keys.

        Returns:
            list: List of provider names
        """
        credentials = self._load_credentials()
        return list(credentials.keys())

    # ==================== Notification Credentials Methods ====================

    def store_notification_credential(self, channel: str, key_name: str, value: str):
        """
        Store a notification channel credential (email password, webhook URL, bot token, etc.).

        Args:
            channel: Notification channel (e.g., 'email', 'slack', 'teams', 'telegram')
            key_name: Credential key name (e.g., 'password', 'webhook_url', 'bot_token')
            value: The credential value to store securely
        """
        if not value or not value.strip():
            raise ValueError(f"Credential value for {channel}.{key_name} cannot be empty")

        credentials = self._load_credentials()

        # Use namespaced keys: notification:{channel}:{key_name}
        credential_key = f"notification:{channel}:{key_name}"

        # Encrypt the credential
        encrypted_value = self._fernet.encrypt(value.encode()).decode()
        credentials[credential_key] = encrypted_value

        self._save_credentials(credentials)
        logger.info(f"Stored notification credential: {channel}.{key_name}")

    def get_notification_credential(self, channel: str, key_name: str) -> Optional[str]:
        """
        Retrieve and decrypt a notification channel credential.

        Args:
            channel: Notification channel (e.g., 'email', 'slack', 'teams', 'telegram')
            key_name: Credential key name (e.g., 'password', 'webhook_url', 'bot_token')

        Returns:
            str: The decrypted credential value, or None if not found
        """
        credentials = self._load_credentials()

        credential_key = f"notification:{channel}:{key_name}"
        encrypted_value = credentials.get(credential_key)

        if not encrypted_value:
            logger.debug(f"No credential found for {channel}.{key_name}")
            return None

        try:
            decrypted_value = self._fernet.decrypt(encrypted_value.encode()).decode()
            return decrypted_value
        except Exception as e:
            logger.error(f"Failed to decrypt credential for {channel}.{key_name}: {e}")
            return None

    def store_email_credentials(self, username: str, password: str):
        """
        Store email credentials securely.

        Args:
            username: Email username
            password: Email password or app-specific password
        """
        self.store_notification_credential('email', 'username', username)
        self.store_notification_credential('email', 'password', password)
        logger.info("Stored email credentials securely")

    def get_email_credentials(self) -> Optional[Dict[str, str]]:
        """
        Retrieve email credentials.

        Returns:
            dict: {'username': str, 'password': str} or None if not found
        """
        username = self.get_notification_credential('email', 'username')
        password = self.get_notification_credential('email', 'password')

        if username and password:
            return {'username': username, 'password': password}

        return None

    def store_webhook_url(self, channel: str, webhook_url: str):
        """
        Store a webhook URL securely (Slack, Teams, Google Chat).

        Args:
            channel: Channel name (e.g., 'slack', 'teams', 'gchat')
            webhook_url: The webhook URL to store
        """
        self.store_notification_credential(channel, 'webhook_url', webhook_url)
        logger.info(f"Stored {channel} webhook URL securely")

    def get_webhook_url(self, channel: str) -> Optional[str]:
        """
        Retrieve a webhook URL.

        Args:
            channel: Channel name (e.g., 'slack', 'teams', 'gchat')

        Returns:
            str: The webhook URL or None if not found
        """
        return self.get_notification_credential(channel, 'webhook_url')

    def store_telegram_credentials(self, bot_token: str, chat_id: str):
        """
        Store Telegram bot credentials securely.

        Args:
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
        """
        self.store_notification_credential('telegram', 'bot_token', bot_token)
        self.store_notification_credential('telegram', 'chat_id', chat_id)
        logger.info("Stored Telegram credentials securely")

    def get_telegram_credentials(self) -> Optional[Dict[str, str]]:
        """
        Retrieve Telegram credentials.

        Returns:
            dict: {'bot_token': str, 'chat_id': str} or None if not found
        """
        bot_token = self.get_notification_credential('telegram', 'bot_token')
        chat_id = self.get_notification_credential('telegram', 'chat_id')

        if bot_token and chat_id:
            return {'bot_token': bot_token, 'chat_id': chat_id}

        return None

    def remove_notification_credential(self, channel: str, key_name: str) -> bool:
        """
        Remove a notification credential.

        Args:
            channel: Notification channel
            key_name: Credential key name

        Returns:
            bool: True if removed, False if not found
        """
        credentials = self._load_credentials()
        credential_key = f"notification:{channel}:{key_name}"

        if credential_key in credentials:
            del credentials[credential_key]
            self._save_credentials(credentials)
            logger.info(f"Removed notification credential: {channel}.{key_name}")
            return True

        logger.warning(f"No credential found to remove: {channel}.{key_name}")
        return False

    def list_notification_credentials(self) -> Dict[str, list]:
        """
        List all stored notification credentials by channel.

        Returns:
            dict: {channel: [key_names]} for all notification credentials
        """
        credentials = self._load_credentials()
        notifications = {}

        for key in credentials.keys():
            if key.startswith('notification:'):
                parts = key.split(':', 2)
                if len(parts) == 3:
                    channel = parts[1]
                    key_name = parts[2]

                    if channel not in notifications:
                        notifications[channel] = []

                    notifications[channel].append(key_name)

        return notifications

    def encrypt_api_key(self, api_key: str) -> str:
        """
        Encrypt an API key (for direct encryption needs).

        Args:
            api_key: The API key to encrypt

        Returns:
            str: The encrypted API key
        """
        return self._fernet.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_key: str) -> str:
        """
        Decrypt an API key (for direct decryption needs).

        Args:
            encrypted_key: The encrypted API key

        Returns:
            str: The decrypted API key
        """
        return self._fernet.decrypt(encrypted_key.encode()).decode()

    def clear_all_keys(self):
        """
        Remove all stored API keys (use with caution).
        This will require re-entering all API keys.
        """
        if self.CREDENTIALS_FILE.exists():
            self.CREDENTIALS_FILE.unlink()
            logger.warning("All API keys have been cleared")

    def reset_encryption_key(self):
        """
        Reset the encryption key (use with EXTREME caution).
        This will invalidate all stored credentials.
        """
        # Delete the encryption key from keyring
        try:
            keyring.delete_password(self.SERVICE_NAME, self.ENCRYPTION_KEY_NAME)
        except keyring.errors.PasswordDeleteError:
            pass

        # Clear credentials file
        self.clear_all_keys()

        # Generate new key
        self._encryption_key = self._get_or_create_encryption_key()
        self._fernet = Fernet(self._encryption_key)

        logger.warning("Encryption key has been reset. All previous credentials are invalidated.")


def main():
    """Example usage and testing."""
    print("SecVuln Agent - Secrets Manager")
    print("=" * 50)

    manager = SecretsManager()

    # Show stored providers
    providers = manager.list_providers()
    if providers:
        print(f"\nCurrently stored providers: {', '.join(providers)}")
    else:
        print("\nNo API keys stored yet.")

    print(f"\nCredentials directory: {manager.CREDENTIALS_DIR}")
    print(f"Credentials file: {manager.CREDENTIALS_FILE}")

    if manager._keyring_available:
        print(f"Using OS keyring: {keyring.get_keyring().__class__.__name__}")
        print("Status: Keyring available (secure mode)")
    else:
        print(f"Using file-based key storage: {manager.KEY_FILE}")
        print("Status: Headless mode (file-based encryption)")


if __name__ == "__main__":
    main()
