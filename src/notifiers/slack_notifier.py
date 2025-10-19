"""
Slack Notifier
Sends vulnerability notifications to Slack channels via webhook
"""

import requests
import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class SlackNotifier:
    """
    Sends notifications to Slack via incoming webhooks.
    """

    def __init__(self, webhook_url: str = None, config: Dict = None, secrets_manager=None):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack incoming webhook URL (deprecated, use secrets_manager)
            config: Additional configuration
            secrets_manager: SecretsManager for retrieving encrypted webhook URL
        """
        self.config = config or {}
        self.secrets_manager = secrets_manager
        self.webhook_url = None

        # Try to get webhook URL from SecretsManager first
        if self.secrets_manager:
            secure_webhook = self.secrets_manager.get_webhook_url('slack')
            if secure_webhook:
                self.webhook_url = secure_webhook
                logger.debug("Retrieved Slack webhook URL from secure storage")
            else:
                logger.warning("No Slack webhook URL found in secure storage")

        # Fall back to constructor parameter (for backward compatibility)
        if not self.webhook_url:
            self.webhook_url = webhook_url
            if self.webhook_url:
                logger.warning("Using Slack webhook URL from config file (INSECURE). Run migration script to encrypt.")

        if not self.webhook_url:
            raise ValueError("Slack webhook_url must be provided either through secrets_manager or constructor")

        self.timeout = self.config.get('timeout', 10)

    def send_alert(self, cve_data: Dict, matched_devices: List[Dict] = None, ai_analysis: Dict = None) -> bool:
        """
        Send immediate alert for a critical vulnerability.

        Args:
            cve_data: CVE data dictionary
            matched_devices: List of matched devices
            ai_analysis: AI analysis results

        Returns:
            bool: True if sent successfully
        """
        try:
            message = self._format_alert(cve_data, matched_devices, ai_analysis)

            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            response.raise_for_status()

            logger.info(f"Sent Slack alert for {cve_data.get('cve_id')}")
            return True

        except requests.RequestException as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def send_digest(self, cves: List[Dict], summary: Dict) -> bool:
        """
        Send daily digest of vulnerabilities.

        Args:
            cves: List of CVE dictionaries
            summary: Summary statistics

        Returns:
            bool: True if sent successfully
        """
        try:
            message = self._format_digest(cves, summary)

            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            response.raise_for_status()

            logger.info(f"Sent Slack digest with {len(cves)} CVEs")
            return True

        except requests.RequestException as e:
            logger.error(f"Failed to send Slack digest: {e}")
            return False

    def _format_alert(self, cve_data: Dict, matched_devices: List[Dict], ai_analysis: Dict) -> Dict:
        """Format immediate alert message."""
        cve_id = cve_data.get('cve_id', 'Unknown')
        cvss_score = cve_data.get('cvss_score', 0)
        severity = cve_data.get('severity', 'UNKNOWN')
        description = cve_data.get('description', 'No description')[:500]

        # Color coding
        color = '#d13212' if severity == 'CRITICAL' else '#ff8c00' if severity == 'HIGH' else '#ffd700'

        # Build device list
        device_text = "No matching devices"
        if matched_devices:
            devices = [f"• {d.get('device_id', 'Unknown')} ({d.get('device_type', 'unknown')})"
                       for d in matched_devices[:5]]
            device_text = "\n".join(devices)
            if len(matched_devices) > 5:
                device_text += f"\n...and {len(matched_devices) - 5} more"

        # Severity emoji
        emoji = "🔴" if severity == 'CRITICAL' else "🟠" if severity == 'HIGH' else "🟡"

        fields = [
            {"title": "CVSS Score", "value": f"{cvss_score}", "short": True},
            {"title": "Severity", "value": f"{emoji} {severity}", "short": True},
            {"title": "Exploit Available", "value": "✅ Yes" if cve_data.get('exploit_available') else "❌ No", "short": True},
            {"title": "CISA KEV", "value": "⚠️ Yes" if cve_data.get('in_cisa_kev') else "No", "short": True},
            {"title": "Affected Devices", "value": device_text, "short": False}
        ]

        # Add AI analysis if available
        if ai_analysis:
            urgency = ai_analysis.get('urgency', 'Unknown')
            actions = ai_analysis.get('recommended_actions', [])

            fields.append({
                "title": "AI Assessment",
                "value": f"*Urgency:* {urgency}\n*Actions:* {actions[0] if actions else 'Review vendor advisories'}",
                "short": False
            })

        return {
            "text": f"🚨 CRITICAL Security Vulnerability Detected",
            "attachments": [{
                "color": color,
                "title": f"{cve_id} - Security Alert",
                "text": description,
                "fields": fields,
                "footer": "SecVuln Agent",
                "ts": int(datetime.now().timestamp())
            }]
        }

    def _format_digest(self, cves: List[Dict], summary: Dict) -> Dict:
        """Format digest message."""
        total = len(cves)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)

        # Group by priority
        p0_cves = [c for c in cves if c.get('priority') == 'P0']
        p1_cves = [c for c in cves if c.get('priority') == 'P1']

        text = f"📊 *Daily Security Vulnerability Digest - {datetime.now().strftime('%Y-%m-%d')}*\n\n"
        text += f"*Summary:* {total} vulnerabilities | {critical} CRITICAL | {high} HIGH\n\n"

        if p0_cves:
            text += "*⚠️ P0 - Immediate Action Required:*\n"
            for cve in p0_cves[:5]:
                text += f"• `{cve.get('cve_id')}` - CVSS: {cve.get('cvss_score')} - {cve.get('description', '')[:60]}...\n"
            text += "\n"

        if p1_cves:
            text += "*🔥 P1 - High Priority (24h):*\n"
            for cve in p1_cves[:5]:
                text += f"• `{cve.get('cve_id')}` - CVSS: {cve.get('cvss_score')} - {cve.get('description', '')[:60]}...\n"

        return {
            "text": text
        }


if __name__ == "__main__":
    # Test with example webhook URL
    print("Slack notifier module loaded")
