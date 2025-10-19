"""
Microsoft Teams Notifier - Sends alerts to Teams via webhook
Enhanced with Adaptive Cards for rich, interactive notifications
"""

import requests
import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


def get_severity_from_cvss(cvss_score: float) -> str:
    """
    Determine severity level from CVSS score.
    CRITICAL: 9.0-10.0
    HIGH: 7.0-8.9
    MEDIUM: 4.0-6.9
    LOW: 0.1-3.9
    NONE: 0.0 or None
    """
    # Handle None values
    if cvss_score is None:
        return 'NONE'

    if cvss_score >= 9.0:
        return 'CRITICAL'
    elif cvss_score >= 7.0:
        return 'HIGH'
    elif cvss_score >= 4.0:
        return 'MEDIUM'
    elif cvss_score > 0:
        return 'LOW'
    else:
        return 'NONE'


class TeamsNotifier:
    """
    Microsoft Teams notifier with Adaptive Cards support.
    Sends rich, interactive notifications to Teams channels.
    """

    def __init__(self, webhook_url: str = None, config: Dict = None, secrets_manager=None):
        """
        Initialize Teams notifier.

        Args:
            webhook_url: Teams webhook URL (deprecated, use secrets_manager)
            config: Configuration dictionary
            secrets_manager: SecretsManager for retrieving encrypted webhook URL
        """
        self.config = config or {}
        self.secrets_manager = secrets_manager
        self.webhook_url = None

        # Try to get webhook URL from SecretsManager first
        if self.secrets_manager:
            secure_webhook = self.secrets_manager.get_webhook_url('teams')
            if secure_webhook:
                self.webhook_url = secure_webhook
                logger.debug("Retrieved Teams webhook URL from secure storage")
            else:
                logger.warning("No Teams webhook URL found in secure storage")

        # Fall back to constructor parameter (for backward compatibility)
        if not self.webhook_url:
            self.webhook_url = webhook_url
            if self.webhook_url:
                logger.warning("Using Teams webhook URL from config file (INSECURE). Run migration script to encrypt.")

        if not self.webhook_url:
            raise ValueError("Teams webhook_url must be provided either through secrets_manager or constructor")

        self.timeout = self.config.get('timeout', 10)

    def send_alert(self, cve_data: Dict, matched_devices: List[Dict] = None, ai_analysis: Dict = None) -> bool:
        """
        Send critical vulnerability alert with Adaptive Card.

        Args:
            cve_data: CVE data dictionary
            matched_devices: List of matched devices
            ai_analysis: AI analysis results

        Returns:
            bool: True if sent successfully
        """
        try:
            message = self._format_alert_adaptive_card(cve_data, matched_devices, ai_analysis)
            response = requests.post(self.webhook_url, json=message, timeout=self.timeout)
            response.raise_for_status()
            logger.info(f"Sent Teams alert for {cve_data.get('cve_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")
            return False

    def send_digest(self, cves: List[Dict], summary: Dict) -> bool:
        """
        Send daily digest with Adaptive Card.

        Args:
            cves: List of CVE dictionaries
            summary: Summary statistics

        Returns:
            bool: True if sent successfully
        """
        try:
            message = self._format_digest_adaptive_card(cves, summary)
            response = requests.post(self.webhook_url, json=message, timeout=self.timeout)
            response.raise_for_status()
            logger.info("Sent Teams digest")
            return True
        except Exception as e:
            logger.error(f"Failed to send Teams digest: {e}")
            return False

    def _format_alert_adaptive_card(self, cve_data: Dict, matched_devices: List[Dict], ai_analysis: Dict) -> Dict:
        """
        Format critical alert as Adaptive Card with action buttons and rich layout.
        """
        cve_id = cve_data.get('cve_id', 'Unknown')
        cvss_score = cve_data.get('cvss_score', 0)
        severity = get_severity_from_cvss(cvss_score)
        description = cve_data.get('description', 'No description available')
        exploit_available = cve_data.get('exploit_available', False)
        in_cisa_kev = cve_data.get('in_cisa_kev', False)

        # Determine color based on severity
        severity_colors = {
            'CRITICAL': 'Attention',  # Red
            'HIGH': 'Warning',        # Orange
            'MEDIUM': 'Accent',       # Blue
            'LOW': 'Good'            # Green
        }
        color = severity_colors.get(severity, 'Default')

        # Build device list
        device_facts = []
        if matched_devices:
            for device in matched_devices[:5]:  # Limit to 5 devices
                device_id = device.get('device_id', 'Unknown')
                device_type = device.get('type', 'Unknown')
                vendor = device.get('vendor', 'Unknown')
                product = device.get('product', 'Unknown')
                version = device.get('version', 'Unknown')
                device_facts.append({
                    "title": f"**{device_id}** ({device_type})",
                    "value": f"{vendor} {product} v{version}"
                })

        # Build AI analysis section if available
        ai_section = []
        if ai_analysis:
            urgency = ai_analysis.get('urgency', 'Unknown')
            risk_assessment = ai_analysis.get('risk_assessment', 'No assessment available')

            ai_section = [
                {
                    "type": "TextBlock",
                    "text": "🤖 AI Analysis",
                    "weight": "Bolder",
                    "size": "Medium",
                    "spacing": "Medium"
                },
                {
                    "type": "TextBlock",
                    "text": f"**Urgency:** {urgency}",
                    "wrap": True
                },
                {
                    "type": "TextBlock",
                    "text": f"**Risk Assessment:** {risk_assessment[:300]}...",
                    "wrap": True,
                    "isSubtle": True
                }
            ]

        # Build action buttons
        actions = [
            {
                "type": "Action.OpenUrl",
                "title": "View on NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            },
            {
                "type": "Action.OpenUrl",
                "title": "View on MITRE",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            }
        ]

        if in_cisa_kev:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "CISA KEV Catalog",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            })

        # Build the Adaptive Card
        adaptive_card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            # Header
                            {
                                "type": "Container",
                                "style": color,
                                "bleed": True,
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": f"🚨 CRITICAL SECURITY ALERT",
                                        "weight": "Bolder",
                                        "size": "Large",
                                        "color": "Light" if severity in ['CRITICAL', 'HIGH'] else "Dark"
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": f"{cve_id} - {severity}",
                                        "weight": "Bolder",
                                        "size": "ExtraLarge",
                                        "color": "Light" if severity in ['CRITICAL', 'HIGH'] else "Dark"
                                    }
                                ]
                            },
                            # Key metrics
                            {
                                "type": "FactSet",
                                "spacing": "Medium",
                                "facts": [
                                    {"title": "CVSS Score:", "value": f"**{cvss_score:.1f}**"},
                                    {"title": "Severity:", "value": f"**{severity}**"},
                                    {"title": "Exploit Available:", "value": "⚠️ **YES**" if exploit_available else "No"},
                                    {"title": "CISA KEV:", "value": "🔴 **YES**" if in_cisa_kev else "No"},
                                    {"title": "Affected Devices:", "value": f"**{len(matched_devices) if matched_devices else 0}**"}
                                ]
                            },
                            # Description
                            {
                                "type": "TextBlock",
                                "text": "📋 Description",
                                "weight": "Bolder",
                                "size": "Medium",
                                "spacing": "Medium"
                            },
                            {
                                "type": "TextBlock",
                                "text": description[:500] + ("..." if len(description) > 500 else ""),
                                "wrap": True,
                                "isSubtle": True
                            }
                        ] + (
                            # Affected devices section
                            [
                                {
                                    "type": "TextBlock",
                                    "text": f"🖥️ Affected Devices ({len(matched_devices)})",
                                    "weight": "Bolder",
                                    "size": "Medium",
                                    "spacing": "Medium"
                                }
                            ] + [
                                {
                                    "type": "FactSet",
                                    "facts": device_facts
                                }
                            ] if matched_devices else []
                        ) + ai_section + [
                            # Footer
                            {
                                "type": "TextBlock",
                                "text": f"🕐 Alert sent: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                                "isSubtle": True,
                                "spacing": "Medium",
                                "size": "Small"
                            },
                            {
                                "type": "TextBlock",
                                "text": "Powered by VOIGHT SecVuln Agent",
                                "isSubtle": True,
                                "size": "Small"
                            }
                        ],
                        "actions": actions
                    }
                }
            ]
        }

        return adaptive_card

    def _format_digest_adaptive_card(self, cves: List[Dict], summary: Dict) -> Dict:
        """
        Format daily digest as Adaptive Card with expandable sections and stats.
        """
        # Recalculate severity counts from CVSS scores
        critical_cves = []
        high_cves = []
        medium_cves = []
        low_cves = []

        for cve in cves:
            cvss = cve.get('cvss_score', 0)
            severity = get_severity_from_cvss(cvss)
            cve['calculated_severity'] = severity

            if severity == 'CRITICAL':
                critical_cves.append(cve)
            elif severity == 'HIGH':
                high_cves.append(cve)
            elif severity == 'MEDIUM':
                medium_cves.append(cve)
            elif severity == 'LOW':
                low_cves.append(cve)

        total = len(cves)
        critical_count = len(critical_cves)
        high_count = len(high_cves)
        medium_count = len(medium_cves)
        low_count = len(low_cves)

        # Build CVE list sections with descriptions (limit to top CVEs)
        def build_cve_column(cve):
            cve_id = cve.get('cve_id', 'Unknown')
            cvss = cve.get('cvss_score', 0)
            severity = cve.get('calculated_severity', 'UNKNOWN')

            # Get description highlight
            description = cve.get('description', 'No description available')
            highlight = description[:120] + '...' if len(description) > 120 else description

            # Get affected devices
            matched_devices = cve.get('matched_devices', [])
            device_count = len(matched_devices)

            # Check for exploit and KEV
            badges = []
            if cve.get('exploit_available'):
                badges.append("⚠️ Exploit")
            if cve.get('in_cisa_kev'):
                badges.append("🔴 KEV")
            badge_str = " | ".join(badges)

            return {
                "type": "Column",
                "width": "stretch",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"**[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})**",
                        "wrap": True,
                        "weight": "Bolder"
                    },
                    {
                        "type": "TextBlock",
                        "text": highlight,
                        "size": "Small",
                        "wrap": True,
                        "spacing": "Small"
                    },
                    {
                        "type": "TextBlock",
                        "text": f"CVSS: {cvss:.1f} | Devices: {device_count}" + (f" | {badge_str}" if badge_str else ""),
                        "size": "Small",
                        "isSubtle": True,
                        "wrap": True,
                        "spacing": "Small"
                    }
                ]
            }

        # Build vulnerability sections - show only top critical/high
        cve_sections = []

        if critical_cves:
            cve_sections.append({
                "type": "TextBlock",
                "text": f"🔴 Top CRITICAL Vulnerabilities ({critical_count} total)",
                "weight": "Bolder",
                "size": "Medium",
                "spacing": "Medium",
                "color": "Attention"
            })
            for cve in critical_cves[:8]:  # Top 8 critical
                cve_sections.append({
                    "type": "ColumnSet",
                    "columns": [build_cve_column(cve)]
                })
            if critical_count > 8:
                cve_sections.append({
                    "type": "TextBlock",
                    "text": f"_...and {critical_count - 8} more critical CVEs. See full CSV report for details._",
                    "size": "Small",
                    "isSubtle": True,
                    "wrap": True,
                    "spacing": "Small"
                })

        if high_cves:
            cve_sections.append({
                "type": "TextBlock",
                "text": f"🟠 Top HIGH Vulnerabilities ({high_count} total)",
                "weight": "Bolder",
                "size": "Medium",
                "spacing": "Medium",
                "color": "Warning"
            })
            for cve in high_cves[:8]:  # Top 8 high
                cve_sections.append({
                    "type": "ColumnSet",
                    "columns": [build_cve_column(cve)]
                })
            if high_count > 8:
                cve_sections.append({
                    "type": "TextBlock",
                    "text": f"_...and {high_count - 8} more high severity CVEs. See full CSV report for details._",
                    "size": "Small",
                    "isSubtle": True,
                    "wrap": True,
                    "spacing": "Small"
                })

        if medium_cves:
            cve_sections.append({
                "type": "TextBlock",
                "text": f"🟡 Top MEDIUM Vulnerabilities ({medium_count} total)",
                "weight": "Bolder",
                "size": "Medium",
                "spacing": "Medium",
                "color": "Accent"
            })
            for cve in medium_cves[:5]:  # Top 5 medium
                cve_sections.append({
                    "type": "ColumnSet",
                    "columns": [build_cve_column(cve)]
                })
            if medium_count > 5:
                cve_sections.append({
                    "type": "TextBlock",
                    "text": f"_...and {medium_count - 5} more medium severity CVEs. See full CSV report for details._",
                    "size": "Small",
                    "isSubtle": True,
                    "wrap": True,
                    "spacing": "Small"
                })

        # Build the Adaptive Card
        adaptive_card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            # Header
                            {
                                "type": "Container",
                                "style": "emphasis",
                                "bleed": True,
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "📊 Daily Vulnerability Digest",
                                        "weight": "Bolder",
                                        "size": "ExtraLarge"
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": datetime.now().strftime('%A, %B %d, %Y'),
                                        "weight": "Lighter",
                                        "spacing": "None"
                                    }
                                ]
                            },
                            # Statistics
                            {
                                "type": "ColumnSet",
                                "spacing": "Medium",
                                "separator": True,
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": f"**{total}**",
                                                "size": "ExtraLarge",
                                                "horizontalAlignment": "Center"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Total",
                                                "size": "Small",
                                                "horizontalAlignment": "Center",
                                                "isSubtle": True
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": f"**{critical_count}**",
                                                "size": "ExtraLarge",
                                                "color": "Attention",
                                                "horizontalAlignment": "Center"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Critical",
                                                "size": "Small",
                                                "horizontalAlignment": "Center",
                                                "isSubtle": True
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": f"**{high_count}**",
                                                "size": "ExtraLarge",
                                                "color": "Warning",
                                                "horizontalAlignment": "Center"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "High",
                                                "size": "Small",
                                                "horizontalAlignment": "Center",
                                                "isSubtle": True
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": f"**{medium_count}**",
                                                "size": "ExtraLarge",
                                                "color": "Accent",
                                                "horizontalAlignment": "Center"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Medium",
                                                "size": "Small",
                                                "horizontalAlignment": "Center",
                                                "isSubtle": True
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "stretch",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": f"**{low_count}**",
                                                "size": "ExtraLarge",
                                                "color": "Good",
                                                "horizontalAlignment": "Center"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Low",
                                                "size": "Small",
                                                "horizontalAlignment": "Center",
                                                "isSubtle": True
                                            }
                                        ]
                                    }
                                ]
                            }
                        ] + cve_sections + [
                            # CSV Report info
                            {
                                "type": "Container",
                                "spacing": "Medium",
                                "separator": True,
                                "style": "emphasis",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "📊 Full CSV Report Available",
                                        "weight": "Bolder",
                                        "size": "Medium"
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": f"A comprehensive CSV report with all {total} vulnerabilities has been generated and saved to the `reports/` directory on your server. Open the CSV file for detailed analysis, filtering, and export capabilities.",
                                        "wrap": True,
                                        "size": "Small",
                                        "spacing": "Small"
                                    }
                                ]
                            },
                            # Footer
                            {
                                "type": "TextBlock",
                                "text": f"🕐 Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                                "isSubtle": True,
                                "spacing": "Medium",
                                "size": "Small"
                            },
                            {
                                "type": "TextBlock",
                                "text": "Powered by VOIGHT SecVuln Agent",
                                "isSubtle": True,
                                "size": "Small"
                            }
                        ]
                    }
                }
            ]
        }

        return adaptive_card


# Example usage for testing
if __name__ == "__main__":
    print("Teams Notifier with Adaptive Cards - Ready")
