"""Telegram Notifier - Sends alerts via Telegram Bot API"""
import requests
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class TelegramNotifier:
    def __init__(self, bot_token: str = None, chat_id: str = None, config: Dict = None, secrets_manager=None):
        """
        Initialize Telegram notifier.

        Args:
            bot_token: Telegram bot token (deprecated, use secrets_manager)
            chat_id: Telegram chat ID (deprecated, use secrets_manager)
            config: Optional configuration dictionary
            secrets_manager: SecretsManager for retrieving encrypted credentials
        """
        self.config = config or {}
        self.secrets_manager = secrets_manager
        self.bot_token = None
        self.chat_id = None

        # Try to get credentials from SecretsManager first
        if self.secrets_manager:
            telegram_creds = self.secrets_manager.get_telegram_credentials()
            if telegram_creds:
                self.bot_token = telegram_creds['bot_token']
                self.chat_id = telegram_creds['chat_id']
                logger.debug("Retrieved Telegram credentials from secure storage")
            else:
                logger.warning("No Telegram credentials found in secure storage")

        # Fall back to constructor parameters (for backward compatibility)
        if not self.bot_token or not self.chat_id:
            self.bot_token = bot_token
            self.chat_id = chat_id
            if self.bot_token and self.chat_id:
                logger.warning("Using Telegram credentials from config file (INSECURE). Run migration script to encrypt.")

        if not self.bot_token or not self.chat_id:
            raise ValueError("Telegram bot_token and chat_id must be provided either through secrets_manager or constructor")

        self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        self.timeout = self.config.get('timeout', 10)

    def send_alert(self, cve_data: Dict, matched_devices: List[Dict] = None, ai_analysis: Dict = None) -> bool:
        try:
            message = self._format_alert(cve_data, matched_devices, ai_analysis)
            response = requests.post(
                self.api_url,
                json={"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=self.timeout
            )
            response.raise_for_status()
            logger.info(f"Sent Telegram alert for {cve_data.get('cve_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False

    def send_digest(self, cves: List[Dict], summary: Dict) -> bool:
        try:
            message = self._format_digest(cves, summary)
            response = requests.post(
                self.api_url,
                json={"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send Telegram digest: {e}")
            return False

    def _format_alert(self, cve_data: Dict, matched_devices: List[Dict], ai_analysis: Dict) -> str:
        cve_id = cve_data.get('cve_id', 'Unknown')
        cvss = cve_data.get('cvss_score', 0)
        severity = cve_data.get('severity', 'UNKNOWN')

        emoji = "🔴" if severity == 'CRITICAL' else "🟠" if severity == 'HIGH' else "🟡"

        msg = f"🚨 *SECURITY ALERT*\n\n"
        msg += f"*{cve_id}* | CVSS: {cvss} | {emoji} {severity}\n\n"
        msg += f"{cve_data.get('description', '')[:300]}...\n\n"
        msg += f"Exploit: {'✅' if cve_data.get('exploit_available') else '❌'} | "
        msg += f"CISA KEV: {'⚠️' if cve_data.get('in_cisa_kev') else '❌'}"

        return msg

    def _format_digest(self, cves: List[Dict], summary: Dict) -> str:
        from datetime import datetime
        total = len(cves)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)

        msg = f"📊 *Daily Security Digest*\n"
        msg += f"_{datetime.now().strftime('%Y-%m-%d')}_\n\n"
        msg += f"*{total}* vulnerabilities | *{critical}* CRITICAL | *{high}* HIGH\n\n"

        p0 = [c for c in cves if c.get('priority') == 'P0']
        if p0:
            msg += f"⚠️ *P0 Immediate:*\n"
            for cve in p0[:3]:
                msg += f"• `{cve.get('cve_id')}` - CVSS {cve.get('cvss_score')}\n"

        return msg
