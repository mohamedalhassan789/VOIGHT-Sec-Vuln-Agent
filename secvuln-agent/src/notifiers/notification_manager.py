"""
Notification Manager
Orchestrates notifications across multiple channels
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Manages notifications across all configured channels.
    Handles rate limiting and notification scheduling.
    """

    def __init__(self, config: Dict, secrets_manager=None, ai_analyzer=None):
        """
        Initialize notification manager.

        Args:
            config: Notifications configuration
            secrets_manager: Secrets manager for API tokens
            ai_analyzer: AI analyzer instance for remediation queries
        """
        self.config = config
        self.secrets = secrets_manager
        self.ai_analyzer = ai_analyzer
        self.notifiers = {}
        self.rate_limit_count = 0
        self.rate_limit_reset = datetime.now()
        self.max_immediate_alerts = config.get('max_immediate_per_hour', 5)

        # Load filter configuration from parent config
        # (NotificationManager may receive full config or just notifications section)
        if 'filters' in config:
            filters = config['filters']
        else:
            # Try to find filters in parent or use defaults
            filters = {}

        self.immediate_alert_cvss = filters.get('immediate_alert_cvss', 9.0)
        self.alert_on_cisa_kev = filters.get('alert_on_cisa_kev', True)
        self.alert_on_exploit = filters.get('alert_on_exploit', True)

        # Initialize CSV report generator
        from utils.csv_report_generator import CSVReportGenerator
        self.csv_generator = CSVReportGenerator()

        self._initialize_notifiers()

    def _initialize_notifiers(self):
        """Initialize enabled notification channels."""
        # Handle both full config and notifications-only config
        if 'notifications' in self.config:
            notifications = self.config['notifications']
        else:
            notifications = self.config

        channels = notifications.get('channels', {})

        # Slack
        if channels.get('slack', {}).get('enabled', False):
            has_secure_webhook = self.secrets and self.secrets.get_webhook_url('slack')
            webhook_url = channels['slack'].get('webhook_url')

            if has_secure_webhook or webhook_url:
                from .slack_notifier import SlackNotifier
                self.notifiers['slack'] = SlackNotifier(
                    webhook_url=webhook_url,
                    secrets_manager=self.secrets
                )
                logger.info("Initialized Slack notifier")
            else:
                logger.warning("Slack notifier enabled but missing webhook URL")

        # Teams
        if channels.get('teams', {}).get('enabled', False):
            has_secure_webhook = self.secrets and self.secrets.get_webhook_url('teams')
            webhook_url = channels['teams'].get('webhook_url')

            if has_secure_webhook or webhook_url:
                from .teams_notifier import TeamsNotifier
                self.notifiers['teams'] = TeamsNotifier(
                    webhook_url=webhook_url,
                    secrets_manager=self.secrets
                )
                logger.info("Initialized Teams notifier")
            else:
                logger.warning("Teams notifier enabled but missing webhook URL")

        # Telegram
        if channels.get('telegram', {}).get('enabled', False):
            # Check if credentials are in secure storage or config
            has_secure_creds = self.secrets and self.secrets.get_telegram_credentials()
            bot_token = channels['telegram'].get('bot_token')
            chat_id = channels['telegram'].get('chat_id')
            has_config_creds = bot_token and chat_id

            if has_secure_creds or has_config_creds:
                from .telegram_notifier import TelegramNotifier
                self.notifiers['telegram'] = TelegramNotifier(
                    bot_token=bot_token,
                    chat_id=chat_id,
                    secrets_manager=self.secrets
                )
                logger.info("Initialized Telegram notifier")
            else:
                logger.warning("Telegram notifier enabled but missing credentials")

        # Google Chat
        if channels.get('gchat', {}).get('enabled', False):
            has_secure_webhook = self.secrets and self.secrets.get_webhook_url('gchat')
            webhook_url = channels['gchat'].get('webhook_url')

            if has_secure_webhook or webhook_url:
                from .gchat_notifier import GChatNotifier
                self.notifiers['gchat'] = GChatNotifier(
                    webhook_url=webhook_url,
                    secrets_manager=self.secrets
                )
                logger.info("Initialized Google Chat notifier")
            else:
                logger.warning("Google Chat notifier enabled but missing webhook URL")

        # Email
        if channels.get('email', {}).get('enabled', False):
            email_config = channels['email']
            # Check if email is properly configured (either in secrets or config)
            has_secure_creds = self.secrets and self.secrets.get_email_credentials()
            has_config_creds = email_config.get('username') and email_config.get('password')

            if email_config.get('to_emails') and (has_secure_creds or has_config_creds):
                from .email_notifier import EmailNotifier
                self.notifiers['email'] = EmailNotifier(
                    email_config,
                    ai_analyzer=self.ai_analyzer,
                    secrets_manager=self.secrets
                )
                logger.info("Initialized Email notifier")
            else:
                logger.warning("Email notifier enabled but missing required configuration")

        if not self.notifiers:
            logger.warning("No notification channels configured")

    def send_immediate_alert(self, cve_data: Dict, matched_devices: List[Dict] = None,
                             ai_analysis: Dict = None) -> bool:
        """
        Send immediate alert for critical vulnerability.

        Args:
            cve_data: CVE data
            matched_devices: Matched devices
            ai_analysis: AI analysis results

        Returns:
            bool: True if at least one channel succeeded
        """
        # Check rate limit
        if not self._check_rate_limit():
            logger.warning(f"Rate limit exceeded for immediate alerts")
            return False

        # Check if should send immediate alert
        if not self._should_send_immediate(cve_data):
            logger.debug(f"CVE {cve_data.get('cve_id')} does not meet immediate alert criteria")
            return False

        success = False
        for channel_name, notifier in self.notifiers.items():
            try:
                if notifier.send_alert(cve_data, matched_devices, ai_analysis):
                    success = True
                    logger.info(f"Sent immediate alert to {channel_name}")
            except Exception as e:
                logger.error(f"Failed to send alert via {channel_name}: {e}")

        if success:
            self.rate_limit_count += 1

        return success

    def send_digest(self, cves: List[Dict], summary: Dict) -> bool:
        """
        Send digest summary of vulnerabilities.

        Args:
            cves: List of CVE dictionaries
            summary: Summary statistics

        Returns:
            bool: True if at least one channel succeeded
        """
        if not cves:
            logger.info("No CVEs to send in digest")
            return False

        # Generate CSV report
        csv_report_path = None
        try:
            csv_report_path = self.csv_generator.generate_report(cves)
            if csv_report_path:
                logger.info(f"CSV report generated: {csv_report_path}")

            # Cleanup old reports
            self.csv_generator.cleanup_old_reports()
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")

        success = False
        for channel_name, notifier in self.notifiers.items():
            try:
                # Pass csv_report_path to notifiers that support it (email)
                if hasattr(notifier, 'send_digest'):
                    if channel_name == 'email' and csv_report_path:
                        if notifier.send_digest(cves, summary, csv_report_path):
                            success = True
                            logger.info(f"Sent digest to {channel_name}")
                    else:
                        if notifier.send_digest(cves, summary):
                            success = True
                            logger.info(f"Sent digest to {channel_name}")
            except Exception as e:
                logger.error(f"Failed to send digest via {channel_name}: {e}")

        return success

    def _check_rate_limit(self) -> bool:
        """Check if within rate limit for immediate alerts."""
        now = datetime.now()

        # Reset counter every hour
        if (now - self.rate_limit_reset).total_seconds() >= 3600:
            self.rate_limit_count = 0
            self.rate_limit_reset = now

        return self.rate_limit_count < self.max_immediate_alerts

    def _should_send_immediate(self, cve_data: Dict) -> bool:
        """
        Determine if CVE should trigger immediate alert based on user configuration.

        Args:
            cve_data: CVE data dictionary

        Returns:
            bool: True if should send immediately
        """
        cvss = cve_data.get('cvss_score', 0)
        in_kev = cve_data.get('in_cisa_kev', False)
        exploit = cve_data.get('exploit_available', False)

        # Check CVSS threshold
        if cvss >= self.immediate_alert_cvss:
            logger.debug(f"CVE {cve_data.get('cve_id')} meets CVSS threshold ({cvss} >= {self.immediate_alert_cvss})")
            return True

        # Check CISA KEV (if enabled)
        if self.alert_on_cisa_kev and in_kev:
            logger.debug(f"CVE {cve_data.get('cve_id')} is in CISA KEV catalog")
            return True

        # Check exploit availability (if enabled)
        if self.alert_on_exploit and exploit and cvss >= 7.0:
            logger.debug(f"CVE {cve_data.get('cve_id')} has public exploit and CVSS >= 7.0")
            return True

        return False


if __name__ == "__main__":
    print("Notification Manager module loaded")
