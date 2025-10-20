"""
Email Notifier via SMTP
Sends vulnerability notifications via email using SMTP
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
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


class EmailNotifier:
    """
    Sends notifications via email using SMTP.
    Supports various SMTP providers (Gmail, Outlook, Office365, custom).
    """

    # Common SMTP configurations
    SMTP_CONFIGS = {
        'gmail': {
            'host': 'smtp.gmail.com',
            'port': 587,
            'use_tls': True
        },
        'outlook': {
            'host': 'smtp-mail.outlook.com',
            'port': 587,
            'use_tls': True
        },
        'office365': {
            'host': 'smtp.office365.com',
            'port': 587,
            'use_tls': True
        },
        'yahoo': {
            'host': 'smtp.mail.yahoo.com',
            'port': 587,
            'use_tls': True
        }
    }

    def __init__(self, config: Dict, ai_analyzer=None, secrets_manager=None):
        """
        Initialize email notifier.

        Args:
            config: Email configuration dictionary
            ai_analyzer: Optional AI analyzer for remediation steps
            secrets_manager: Optional SecretsManager for retrieving encrypted credentials
        """
        self.config = config
        self.ai_analyzer = ai_analyzer
        self.secrets_manager = secrets_manager
        self.timeout = self.config.get('timeout', 30)

        # SMTP configuration
        self.smtp_host = self.config.get('smtp_host')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.use_tls = self.config.get('use_tls', True)
        self.use_ssl = self.config.get('use_ssl', False)

        # Authentication - Retrieve from SecretsManager first, fall back to config
        self.username = None
        self.password = None

        if self.secrets_manager:
            # Try to get credentials from encrypted storage
            email_creds = self.secrets_manager.get_email_credentials()
            if email_creds:
                self.username = email_creds['username']
                self.password = email_creds['password']
                logger.debug("Retrieved email credentials from secure storage")
            else:
                logger.warning("No email credentials found in secure storage")

        # Fall back to config (for backward compatibility during migration)
        if not self.username or not self.password:
            self.username = self.config.get('username')
            self.password = self.config.get('password')
            if self.username and self.password:
                logger.warning("Using email credentials from config file (INSECURE). Run migration script to encrypt.")

        # Email addresses
        self.from_email = self.config.get('from_email') or self.username
        self.to_emails = self.config.get('to_emails', [])

        # Convert string to list if needed
        if isinstance(self.to_emails, str):
            self.to_emails = [e.strip() for e in self.to_emails.split(',')]

        # Preset configuration
        preset = self.config.get('preset')
        if preset and preset in self.SMTP_CONFIGS:
            preset_config = self.SMTP_CONFIGS[preset]
            self.smtp_host = self.smtp_host or preset_config['host']
            self.smtp_port = self.smtp_port or preset_config['port']
            self.use_tls = preset_config.get('use_tls', True)

    def send_alert(self, cve_data: Dict, matched_devices: List[Dict] = None, ai_analysis: Dict = None) -> bool:
        """
        Send immediate alert email for a critical vulnerability.

        Args:
            cve_data: CVE data dictionary
            matched_devices: List of matched devices
            ai_analysis: AI analysis results

        Returns:
            bool: True if sent successfully
        """
        try:
            subject, body = self._format_alert(cve_data, matched_devices, ai_analysis)

            success = self._send_email(subject, body, html=True)

            if success:
                logger.info(f"Sent email alert for {cve_data.get('cve_id')}")
            return success

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def send_digest(self, cves: List[Dict], summary: Dict, csv_report_path: str = None) -> bool:
        """
        Send daily digest email of vulnerabilities.

        Args:
            cves: List of CVE dictionaries
            summary: Summary statistics
            csv_report_path: Optional path to generated CSV report

        Returns:
            bool: True if sent successfully
        """
        try:
            subject, body = self._format_digest(cves, summary, csv_report_path)

            success = self._send_email(subject, body, html=True)

            if success:
                logger.info(f"Sent email digest with {len(cves)} CVEs")
            return success

        except Exception as e:
            logger.error(f"Failed to send email digest: {e}")
            return False

    def _send_email(self, subject: str, body: str, html: bool = True) -> bool:
        """
        Send email via SMTP.

        Args:
            subject: Email subject
            body: Email body (HTML or plain text)
            html: Whether body is HTML

        Returns:
            bool: True if sent successfully
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)

            # Attach body
            if html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))

            # Connect to SMTP server
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=self.timeout)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout)
                if self.use_tls:
                    server.starttls()

            # Authenticate
            if self.username and self.password:
                server.login(self.username, self.password)

            # Send email
            server.sendmail(self.from_email, self.to_emails, msg.as_string())
            server.quit()

            logger.debug(f"Email sent to {len(self.to_emails)} recipients")
            return True

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def _format_alert(self, cve_data: Dict, matched_devices: List[Dict], ai_analysis: Dict) -> tuple:
        """Format immediate alert email with enhanced information."""
        cve_id = cve_data.get('cve_id', 'Unknown')
        cvss_score = cve_data.get('cvss_score', 0)

        # FIX: Calculate severity from CVSS score, not from data
        severity = get_severity_from_cvss(cvss_score)
        description = cve_data.get('description', 'No description')

        # Color coding
        severity_colors = {
            'CRITICAL': '#d13212',
            'HIGH': '#ff8c00',
            'MEDIUM': '#ffd700',
            'LOW': '#90EE90',
            'NONE': '#808080'
        }
        color = severity_colors.get(severity, '#808080')

        # Generate CVE reference links
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        mitre_link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        cisa_kev_link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

        # Build detailed device list
        device_html = """
        <div style="background-color: #f0f8ff; padding: 15px; margin: 15px 0; border-left: 4px solid #28a745;">
            <p style="color: #28a745; font-weight: bold;">✅ Good news! This CVE doesn't affect any monitored assets.</p>
        </div>
        """

        if matched_devices:
            device_html = """
            <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                <thead>
                    <tr style="background-color: #f5f5f5;">
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Device ID</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Type</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Vendor/Product</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Current Version</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Criticality</th>
                    </tr>
                </thead>
                <tbody>
            """

            for device in matched_devices[:15]:
                device_id = device.get('device_id', 'Unknown')
                device_type = device.get('device_type', 'unknown')
                vendor = device.get('vendor', 'Unknown')
                product = device.get('product', 'Unknown')
                version = device.get('version', 'Unknown')
                criticality = device.get('criticality', 'unknown')

                # Color code criticality
                crit_colors = {
                    'critical': '#d13212',
                    'high': '#ff8c00',
                    'medium': '#ffd700',
                    'low': '#90EE90'
                }
                crit_color = crit_colors.get(criticality.lower(), '#808080')

                device_html += f"""
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>{device_id}</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid #ddd;">{device_type}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #ddd;">{vendor} {product}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #ddd;"><code>{version}</code></td>
                    <td style="padding: 10px; border-bottom: 1px solid #ddd;">
                        <span style="background-color: {crit_color}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px;">
                            {criticality.upper()}
                        </span>
                    </td>
                </tr>
                """

            if len(matched_devices) > 15:
                device_html += f"""
                <tr>
                    <td colspan="5" style="padding: 10px; text-align: center; font-style: italic;">
                        ...and {len(matched_devices) - 15} more devices
                    </td>
                </tr>
                """

            device_html += "</tbody></table>"

        # AI-powered remediation section
        remediation_html = ""

        # Try to get remediation steps from AI if analyzer available and not already in ai_analysis
        remediation_steps = []
        if self.ai_analyzer and matched_devices:
            try:
                # Build context for AI remediation query
                affected_products = set()
                for device in matched_devices[:5]:
                    vendor = device.get('vendor', 'Unknown')
                    product = device.get('product', 'Unknown')
                    version = device.get('version', 'Unknown')
                    affected_products.add(f"{vendor} {product} {version}")

                # Query AI for remediation
                remediation_prompt = f"""Provide specific remediation steps for {cve_id} affecting {', '.join(affected_products)}.

Include:
1. Immediate mitigation steps (before patch)
2. Patch/update commands if available
3. Vendor advisory links if known
4. Workarounds if no patch available
5. Verification steps after remediation

Format as clear, numbered steps."""

                remediation_result = self.ai_analyzer.query_ai(remediation_prompt)
                if remediation_result:
                    # Parse remediation steps
                    lines = remediation_result.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and (line[0].isdigit() or line.startswith('-') or line.startswith('•')):
                            remediation_steps.append(line.lstrip('0123456789.-•).  '))

            except Exception as e:
                logger.warning(f"Failed to get AI remediation: {e}")

        # AI analysis section
        ai_html = ""
        if ai_analysis or remediation_steps:
            urgency = ai_analysis.get('urgency', 'Unknown') if ai_analysis else 'Unknown'
            risk = ai_analysis.get('risk_assessment', 'No assessment') if ai_analysis else ''
            actions = ai_analysis.get('recommended_actions', []) if ai_analysis else []

            ai_html = f"""
            <div style="background-color: #f0f8ff; padding: 15px; margin: 15px 0; border-left: 4px solid #0078d7;">
                <h3 style="margin-top: 0; color: #0078d7;">🤖 AI Analysis</h3>
                {f'<p><strong>Urgency:</strong> {urgency}</p>' if ai_analysis else ''}
                {f'<p><strong>Risk Assessment:</strong> {risk[:300]}...</p>' if risk else ''}
                {f'''<p><strong>Recommended Actions:</strong></p>
                <ol>
                    {"".join(f"<li>{action}</li>" for action in actions[:5])}
                </ol>''' if actions else ''}
            </div>
            """

        # Remediation steps section (from AI or general)
        if remediation_steps:
            remediation_html = f"""
            <div style="background-color: #fff3cd; padding: 15px; margin: 15px 0; border-left: 4px solid #ffc107;">
                <h3 style="margin-top: 0; color: #856404;">🔧 Remediation Steps</h3>
                <ol style="margin: 10px 0; padding-left: 20px;">
                    {"".join(f"<li style='margin-bottom: 8px;'>{step}</li>" for step in remediation_steps[:10])}
                </ol>
            </div>
            """
        else:
            # Generic remediation if no AI available
            remediation_html = f"""
            <div style="background-color: #fff3cd; padding: 15px; margin: 15px 0; border-left: 4px solid #ffc107;">
                <h3 style="margin-top: 0; color: #856404;">🔧 Recommended Actions</h3>
                <ol style="margin: 10px 0; padding-left: 20px;">
                    <li>Review CVE details at NVD and vendor advisories</li>
                    <li>Check if your systems/software are affected</li>
                    <li>Apply patches or vendor-recommended mitigations immediately</li>
                    <li>Monitor for signs of exploitation</li>
                    <li>Update WAF/IDS rules if applicable</li>
                    <li>Document all remediation actions taken</li>
                </ol>
            </div>
            """

        # Subject with correct severity
        subject = f"🚨 {severity} Security Alert: {cve_id} (CVSS {cvss_score})"

        # HTML body
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; max-width: 800px; margin: 0 auto; }}
                .info-box {{ background-color: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; }}
                .critical {{ background-color: #d13212; }}
                .high {{ background-color: #ff8c00; }}
                .medium {{ background-color: #ffd700; color: #333; }}
                .low {{ background-color: #90EE90; color: #333; }}
                .ref-links {{ background-color: #e7f3ff; padding: 15px; margin: 15px 0; border-left: 4px solid #0078d7; }}
                .ref-links a {{ color: #0078d7; text-decoration: none; font-weight: bold; margin-right: 15px; }}
                .ref-links a:hover {{ text-decoration: underline; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
                td:first-child {{ font-weight: bold; width: 150px; }}
                .footer {{ background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 Security Vulnerability Alert</h1>
                <h2>{cve_id}</h2>
            </div>

            <div class="content">
                <div class="info-box">
                    <table>
                        <tr>
                            <td>CVE ID</td>
                            <td><strong>{cve_id}</strong></td>
                        </tr>
                        <tr>
                            <td>CVSS Score</td>
                            <td><strong>{cvss_score}</strong> / 10.0</td>
                        </tr>
                        <tr>
                            <td>Severity</td>
                            <td><span class="badge {severity.lower()}">{severity}</span></td>
                        </tr>
                        <tr>
                            <td>Exploit Available</td>
                            <td>{'✅ Yes' if cve_data.get('exploit_available') else '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>CISA KEV</td>
                            <td>{'⚠️ Yes - Active Exploitation' if cve_data.get('in_cisa_kev') else 'No'}</td>
                        </tr>
                        <tr>
                            <td>Source</td>
                            <td>{cve_data.get('source', 'Unknown')}</td>
                        </tr>
                    </table>
                </div>

                <div class="ref-links">
                    <h3 style="margin-top: 0; color: #0078d7;">🔗 Reference Links</h3>
                    <a href="{nvd_link}" target="_blank">📖 NVD Details</a>
                    <a href="{mitre_link}" target="_blank">🔍 MITRE CVE</a>
                    {f'<a href="{cisa_kev_link}" target="_blank">⚠️ CISA KEV Catalog</a>' if cve_data.get('in_cisa_kev') else ''}
                </div>

                <h3>📋 Description</h3>
                <p>{description}</p>

                <h3>💻 Affected Systems</h3>
                {device_html}

                {ai_html}

                {remediation_html}
            </div>

            <div class="footer">
                <p>🤖 Generated by VOIGHT SecVuln Agent | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>This is an automated security alert. Do not reply to this email.</p>
            </div>
        </body>
        </html>
        """

        return subject, body

    def _format_digest(self, cves: List[Dict], summary: Dict, csv_report_path: str = None) -> tuple:
        """Format digest email with detailed vulnerability breakdown."""
        total = len(cves)

        # FIX: Recalculate severity counts from CVSS scores
        critical_cves = []
        high_cves = []
        medium_cves = []
        low_cves = []

        for cve in cves:
            cvss = cve.get('cvss_score', 0)
            severity = get_severity_from_cvss(cvss)
            cve['calculated_severity'] = severity  # Store for later use

            if severity == 'CRITICAL':
                critical_cves.append(cve)
            elif severity == 'HIGH':
                high_cves.append(cve)
            elif severity == 'MEDIUM':
                medium_cves.append(cve)
            elif severity == 'LOW':
                low_cves.append(cve)

        critical = len(critical_cves)
        high = len(high_cves)
        medium = len(medium_cves)
        low = len(low_cves)

        # Subject
        subject = f"📊 Daily Security Digest - {datetime.now().strftime('%Y-%m-%d')} ({total} vulnerabilities)"

        # Build device-based breakdown
        device_vuln_count = {}
        for cve in cves:
            matched_devices = cve.get('matched_devices', [])
            for device, confidence in matched_devices:
                device_id = device.get('device_id', 'Unknown')
                if device_id not in device_vuln_count:
                    device_vuln_count[device_id] = {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'device_info': device
                    }

                severity = cve.get('calculated_severity', 'UNKNOWN')
                if severity.lower() in device_vuln_count[device_id]:
                    device_vuln_count[device_id][severity.lower()] += 1

        # Create device breakdown HTML
        device_breakdown_html = ""
        if device_vuln_count:
            device_breakdown_html = """
            <div style="background-color: #f9f9f9; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <h3 style="margin-top: 0;">📱 Affected Devices Breakdown</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background-color: #f5f5f5;">
                            <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Device</th>
                            <th style="padding: 10px; text-align: center; border-bottom: 2px solid #ddd;">Critical</th>
                            <th style="padding: 10px; text-align: center; border-bottom: 2px solid #ddd;">High</th>
                            <th style="padding: 10px; text-align: center; border-bottom: 2px solid #ddd;">Medium</th>
                            <th style="padding: 10px; text-align: center; border-bottom: 2px solid #ddd;">Low</th>
                            <th style="padding: 10px; text-align: center; border-bottom: 2px solid #ddd;">Total</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for device_id, counts in sorted(device_vuln_count.items()):
                device_info = counts['device_info']
                device_type = device_info.get('device_type', 'unknown')
                total_device = counts['critical'] + counts['high'] + counts['medium'] + counts['low']

                device_breakdown_html += f"""
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #ddd;">
                        <strong>{device_id}</strong><br>
                        <small style="color: #666;">({device_type})</small>
                    </td>
                    <td style="padding: 10px; text-align: center; border-bottom: 1px solid #ddd; color: #d13212; font-weight: bold;">
                        {counts['critical'] if counts['critical'] > 0 else '-'}
                    </td>
                    <td style="padding: 10px; text-align: center; border-bottom: 1px solid #ddd; color: #ff8c00; font-weight: bold;">
                        {counts['high'] if counts['high'] > 0 else '-'}
                    </td>
                    <td style="padding: 10px; text-align: center; border-bottom: 1px solid #ddd; color: #ffc107; font-weight: bold;">
                        {counts['medium'] if counts['medium'] > 0 else '-'}
                    </td>
                    <td style="padding: 10px; text-align: center; border-bottom: 1px solid #ddd;">
                        {counts['low'] if counts['low'] > 0 else '-'}
                    </td>
                    <td style="padding: 10px; text-align: center; border-bottom: 1px solid #ddd; font-weight: bold;">
                        {total_device}
                    </td>
                </tr>
                """

            device_breakdown_html += "</tbody></table></div>"

        # Create CVE row function with links and description highlights
        def cve_row(cve):
            cve_id = cve.get('cve_id', 'Unknown')
            cvss = cve.get('cvss_score', 0)
            severity = cve.get('calculated_severity', 'UNKNOWN')
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Get description and create brief highlight
            description = cve.get('description', 'No description available')
            # Truncate to first 150 chars or first sentence
            highlight = description[:150] + '...' if len(description) > 150 else description

            # Get affected devices
            matched_devices = cve.get('matched_devices', [])
            device_names = ', '.join([d.get('device_id', 'Unknown') for d, conf in matched_devices[:3]])
            if len(matched_devices) > 3:
                device_names += f" (+{len(matched_devices)-3} more)"
            if not device_names:
                device_names = "None"

            # Check for exploit and KEV
            exploit_badge = "⚠️ Exploit" if cve.get('exploit_available') else ""
            kev_badge = "🔴 KEV" if cve.get('in_cisa_kev') else ""
            badges = " ".join([b for b in [exploit_badge, kev_badge] if b])

            return f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top;">
                    <a href="{nvd_link}" target="_blank" style="color: #0078d7; font-weight: bold; text-decoration: none;">
                        {cve_id}
                    </a>
                    <div style="margin-top: 5px; font-size: 13px; color: #666; line-height: 1.4;">
                        {highlight}
                    </div>
                    {f'<div style="margin-top: 5px; font-size: 11px;">{badges}</div>' if badges else ''}
                </td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd; text-align: center; vertical-align: top;">
                    <strong style="font-size: 16px;">{cvss}</strong>
                </td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top;">
                    <span class="badge {severity.lower()}">{severity}</span>
                </td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top;">
                    <small>{device_names}</small>
                </td>
            </tr>
            """

        # HTML body
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #0078d7; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; max-width: 1000px; margin: 0 auto; }}
                .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ text-align: center; padding: 15px; background-color: #f5f5f5; border-radius: 5px; flex: 1; margin: 0 10px; }}
                .stat-number {{ font-size: 36px; font-weight: bold; color: #0078d7; }}
                .badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; font-size: 12px; }}
                .critical {{ background-color: #d13212; }}
                .high {{ background-color: #ff8c00; }}
                .medium {{ background-color: #ffd700; color: #333; }}
                .low {{ background-color: #90EE90; color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f5f5f5; font-weight: bold; }}
                .severity-section {{ margin: 30px 0; }}
                .footer {{ background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Security Vulnerability Digest</h1>
                <h2>{datetime.now().strftime('%B %d, %Y')}</h2>
            </div>

            <div class="content">
                <div class="summary">
                    <div class="stat-box">
                        <div class="stat-number">{total}</div>
                        <div>Total</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: #d13212;">{critical}</div>
                        <div>Critical</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: #ff8c00;">{high}</div>
                        <div>High</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: #ffc107;">{medium}</div>
                        <div>Medium</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: #90EE90;">{low}</div>
                        <div>Low</div>
                    </div>
                </div>

                {device_breakdown_html}

                {f'''
                <div class="severity-section">
                    <h2 style="color: #d13212;">🚨 Top CRITICAL Vulnerabilities ({len(critical_cves)} total)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 50%;">CVE ID & Description</th>
                                <th style="text-align: center; width: 80px;">CVSS</th>
                                <th style="width: 100px;">Severity</th>
                                <th style="width: 20%;">Affected Devices</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(cve_row(cve) for cve in critical_cves[:10])}
                        </tbody>
                    </table>
                    {f'<p style="text-align: center; color: #666; font-style: italic;">Showing top 10 of {len(critical_cves)} critical CVEs. See CSV report for complete list.</p>' if len(critical_cves) > 10 else ''}
                </div>
                ''' if critical_cves else ''}

                {f'''
                <div class="severity-section">
                    <h2 style="color: #ff8c00;">🔥 Top HIGH Vulnerabilities ({len(high_cves)} total)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 50%;">CVE ID & Description</th>
                                <th style="text-align: center; width: 80px;">CVSS</th>
                                <th style="width: 100px;">Severity</th>
                                <th style="width: 20%;">Affected Devices</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(cve_row(cve) for cve in high_cves[:10])}
                        </tbody>
                    </table>
                    {f'<p style="text-align: center; color: #666; font-style: italic;">Showing top 10 of {len(high_cves)} high severity CVEs. See CSV report for complete list.</p>' if len(high_cves) > 10 else ''}
                </div>
                ''' if high_cves else ''}

                {f'''
                <div class="severity-section">
                    <h2 style="color: #ffc107;">📋 Top MEDIUM Vulnerabilities ({len(medium_cves)} total)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 50%;">CVE ID & Description</th>
                                <th style="text-align: center; width: 80px;">CVSS</th>
                                <th style="width: 100px;">Severity</th>
                                <th style="width: 20%;">Affected Devices</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(cve_row(cve) for cve in medium_cves[:5])}
                        </tbody>
                    </table>
                    {f'<p style="text-align: center; color: #666; font-style: italic;">Showing top 5 of {len(medium_cves)} medium severity CVEs. See CSV report for complete list.</p>' if len(medium_cves) > 5 else ''}
                </div>
                ''' if medium_cves else ''}

                <div style="background-color: #fff4e5; padding: 20px; margin: 20px 0; border: 2px solid #ff9800; border-radius: 8px;">
                    <h3 style="margin-top: 0; color: #e65100;">📊 Full Report Available</h3>
                    {f'''
                    <p style="font-size: 14px; margin: 10px 0;">A comprehensive CSV report with <strong>all {total} vulnerabilities</strong> has been generated:</p>
                    <p style="background-color: #f5f5f5; padding: 12px; border-radius: 5px; font-family: monospace; font-size: 13px; word-break: break-all;">
                        📁 {csv_report_path}
                    </p>
                    <p style="font-size: 13px; color: #666; margin-top: 15px;">
                        <strong>💡 Tip:</strong> Open this file in Excel or your preferred spreadsheet application for detailed analysis, filtering, and reporting.
                    </p>
                    ''' if csv_report_path else '<p>CSV report will be saved to the <code>reports/</code> directory on your server.</p>'}
                    <div style="background-color: #f9f9f9; padding: 12px; margin-top: 15px; border-radius: 5px;">
                        <p style="margin: 5px 0; font-size: 13px;"><strong>Report includes:</strong></p>
                        <ul style="margin: 8px 0; padding-left: 20px; font-size: 13px;">
                            <li>All CVE IDs with CVSS scores and severity levels</li>
                            <li>Complete vulnerability descriptions</li>
                            <li>Full list of affected devices with version details</li>
                            <li>Exploit availability and CISA KEV status</li>
                            <li>Reference links to NVD and MITRE</li>
                            <li>Risk scores and priority rankings</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="footer">
                <p>🤖 Generated by VOIGHT SecVuln Agent | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>This is an automated security digest. Do not reply to this email.</p>
            </div>
        </body>
        </html>
        """

        return subject, body

    def test_connection(self) -> bool:
        """
        Test SMTP connection and authentication.

        Returns:
            bool: True if connection successful
        """
        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=self.timeout)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout)
                if self.use_tls:
                    server.starttls()

            if self.username and self.password:
                server.login(self.username, self.password)

            server.quit()
            logger.info("SMTP connection test successful")
            return True

        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False


if __name__ == "__main__":
    # Test configuration
    config = {
        'preset': 'gmail',
        'username': 'your-email@gmail.com',
        'password': 'your-app-password',
        'to_emails': ['recipient@example.com']
    }

    notifier = EmailNotifier(config)
    print("Email notifier module loaded")
    print(f"SMTP Host: {notifier.smtp_host}:{notifier.smtp_port}")
    print(f"Recipients: {notifier.to_emails}")
