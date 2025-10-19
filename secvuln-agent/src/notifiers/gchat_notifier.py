"""Google Chat Notifier - Sends alerts to Google Chat via webhook"""
import requests
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class GChatNotifier:
    def __init__(self, webhook_url: str = None, config: Dict = None, secrets_manager=None):
        """
        Initialize Google Chat notifier.

        Args:
            webhook_url: Google Chat webhook URL (deprecated, use secrets_manager)
            config: Configuration dictionary
            secrets_manager: SecretsManager for retrieving encrypted webhook URL
        """
        self.config = config or {}
        self.secrets_manager = secrets_manager
        self.webhook_url = None

        # Try to get webhook URL from SecretsManager first
        if self.secrets_manager:
            secure_webhook = self.secrets_manager.get_webhook_url('gchat')
            if secure_webhook:
                self.webhook_url = secure_webhook
                logger.debug("Retrieved Google Chat webhook URL from secure storage")
            else:
                logger.warning("No Google Chat webhook URL found in secure storage")

        # Fall back to constructor parameter (for backward compatibility)
        if not self.webhook_url:
            self.webhook_url = webhook_url
            if self.webhook_url:
                logger.warning("Using Google Chat webhook URL from config file (INSECURE). Run migration script to encrypt.")

        if not self.webhook_url:
            raise ValueError("Google Chat webhook_url must be provided either through secrets_manager or constructor")

        self.timeout = self.config.get('timeout', 10)

    def send_alert(self, cve_data: Dict, matched_devices: List[Dict] = None, ai_analysis: Dict = None) -> bool:
        try:
            message = self._format_alert(cve_data, matched_devices, ai_analysis)
            response = requests.post(self.webhook_url, json=message, timeout=self.timeout)
            response.raise_for_status()
            logger.info(f"Sent Google Chat alert for {cve_data.get('cve_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Google Chat alert: {e}")
            return False

    def send_digest(self, cves: List[Dict], summary: Dict) -> bool:
        try:
            message = self._format_digest(cves, summary)
            response = requests.post(self.webhook_url, json=message, timeout=self.timeout)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send Google Chat digest: {e}")
            return False

    def _format_alert(self, cve_data: Dict, matched_devices: List[Dict], ai_analysis: Dict) -> Dict:
        cve_id = cve_data.get('cve_id', 'Unknown')
        cvss = cve_data.get('cvss_score', 0)
        severity = cve_data.get('severity', 'UNKNOWN')

        text = f"🚨 *SECURITY ALERT*\n\n"
        text += f"*{cve_id}* | CVSS: {cvss} | {severity}\n\n"
        text += f"{cve_data.get('description', '')[:400]}"

        return {"text": text}

    def _format_digest(self, cves: List[Dict], summary: Dict) -> Dict:
        from datetime import datetime
        total = len(cves)
        text = f"📊 *Daily Security Digest - {datetime.now().strftime('%Y-%m-%d')}*\n\n"
        text += f"{total} vulnerabilities found\n"
        text += f"{summary.get('critical', 0)} CRITICAL | {summary.get('high', 0)} HIGH"

        return {"text": text}
