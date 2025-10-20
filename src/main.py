"""
SecVuln Agent - Main Orchestrator
Coordinates vulnerability collection, processing, and notification
"""

import schedule
import time
import psutil
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict

from utils import setup_logger, ConfigLoader, DatabaseHandler, SecretsManager
from utils.animations import animated_header_agent, print_status, progress_bar, Colors, print_colored
from processors import AIAnalyzer, DeviceMatcher, RiskScorer
from notifiers import NotificationManager
from collectors.cisa_kev import CISAKEVCollector
from collectors.github_advisories import GitHubAdvisoriesCollector
from collectors.rss_collector import RSSCollector
from collectors.opencve_collector import OpenCVECollector
from collectors.nvd_collector import NVDCollector
from collectors.cvefeed_collector import CVEFeedCollector

logger = logging.getLogger(__name__)


class SecVulnAgent:
    """
    Main Security Vulnerability Agent.
    Orchestrates data collection, processing, and notifications.
    """

    def __init__(self, config_path: Path = None):
        """
        Initialize the agent.

        Args:
            config_path: Path to config.yaml file
        """
        # Setup logging first
        global logger
        logger = setup_logger(log_level="INFO")
        logger.info("=" * 60)
        logger.info("SecVuln Agent Starting...")
        logger.info("=" * 60)

        # Load configuration
        self.config_loader = ConfigLoader(config_path)
        self.config = self.config_loader.load_config()
        self.devices = self.config_loader.load_devices()

        # Initialize components
        self.db = DatabaseHandler()
        self.secrets = SecretsManager()

        # Initialize AI analyzer (needed for matcher)
        ai_config = self.config.get('ai', {})
        self.ai_analyzer = AIAnalyzer(ai_config, self.secrets) if ai_config.get('enabled') else None

        # Initialize processors (pass ai_analyzer and config to matcher for two-stage matching)
        self.matcher = DeviceMatcher(self.devices, self.ai_analyzer, self.config)
        self.scorer = RiskScorer(self.config.get('advanced', {}))

        # Initialize notification manager (pass full config for filter access)
        self.notifier = NotificationManager(self.config, self.secrets, ai_analyzer=self.ai_analyzer)

        # Initialize collectors
        self.collectors = self._initialize_collectors()

        # Agent configuration
        self.interval_hours = self.config.get('agent', {}).get('interval_hours', 6)

        # Alert mode configuration
        filters = self.config.get('filters', {})
        self.alert_mode = filters.get('alert_mode', 'device-only')  # 'device-only' or 'all-cves'
        self.min_cvss_devices = filters.get('min_cvss_devices', 4.0)
        self.min_cvss_all = filters.get('min_cvss_all', 7.0)
        self.immediate_alert_cvss = filters.get('immediate_alert_cvss', 9.0)
        self.alert_on_cisa_kev = filters.get('alert_on_cisa_kev', True)
        self.alert_on_exploit = filters.get('alert_on_exploit', True)

        # Legacy support
        if 'min_cvss_score' in filters:
            self.min_cvss_all = filters['min_cvss_score']

        logger.info(f"Agent '{self.config.get('agent', {}).get('name', 'SecVuln-Agent')}' initialized")
        logger.info(f"Alert mode: {self.alert_mode}")
        logger.info(f"Check interval: {self.interval_hours} hours")
        logger.info(f"Devices loaded: {len(self.devices)}")
        logger.info(f"Device monitoring: ENABLED (CVSS >= {self.min_cvss_devices})")
        if self.alert_mode == 'all-cves':
            logger.info(f"All CVEs monitoring: ENABLED (CVSS >= {self.min_cvss_all})")
        logger.info(f"Collectors configured: {len(self.collectors)}")

    def _initialize_collectors(self) -> List:
        """Initialize all enabled collectors."""
        collectors = []
        sources_config = self.config.get('sources', {})

        # Hot Feeds (Tier 1)
        hot_feeds = sources_config.get('hot_feeds', {})

        if hot_feeds.get('cisa_kev', True):
            collectors.append(('CISA KEV', CISAKEVCollector(), 'tier1'))

        if hot_feeds.get('github_advisories', True):
            collectors.append(('GitHub Advisories', GitHubAdvisoriesCollector(), 'tier1'))

        if hot_feeds.get('opencve', True):
            opencve_key = self.secrets.get_provider_key('opencve') if self.secrets else None
            collectors.append(('OpenCVE', OpenCVECollector(api_key=opencve_key), 'tier1'))

        # CVEFeed.io (Tier 1) - 15-minute updates
        cvefeed_config = hot_feeds.get('cvefeed', {})
        if cvefeed_config.get('enabled', True):
            collectors.append(('CVEFeed.io', CVEFeedCollector(cvefeed_config), 'tier1'))

        # RSS Feeds (Tier 2)
        rss_feeds = sources_config.get('rss_feeds', {})
        rss_config = {
            'reddit_netsec': rss_feeds.get('reddit_netsec', True),
            'packetstorm': rss_feeds.get('packetstorm', True),
            'hackernews': rss_feeds.get('hackernews', True)
        }
        if any(rss_config.values()):
            collectors.append(('RSS Feeds', RSSCollector(rss_config), 'tier2'))

        # Official Sources (Tier 3) - Less frequent
        official = sources_config.get('official_sources', {})
        if official.get('nvd_api', True):
            nvd_key = self.secrets.get_provider_key('nvd') if self.secrets else None
            collectors.append(('NVD', NVDCollector(api_key=nvd_key), 'tier3'))

        logger.info(f"Initialized {len(collectors)} collectors")
        return collectors

    def check_system_conditions(self) -> bool:
        """
        Check if system conditions are suitable for running.
        Laptop-friendly: check battery and network.

        Returns:
            bool: True if conditions are good
        """
        # Check battery level (if on laptop)
        try:
            battery = psutil.sensors_battery()
            if battery:
                if not battery.power_plugged and battery.percent < 20:
                    logger.warning(f"Battery low ({battery.percent}%), skipping run")
                    return False
        except Exception:
            pass  # Not a laptop or battery info not available

        # Could add network connectivity check here
        # For now, assume network is available

        return True

    def collect_vulnerabilities(self) -> List[Dict]:
        """
        Collect vulnerabilities from all enabled sources.

        Returns:
            List[Dict]: Combined list of CVEs
        """
        all_cves = []

        for collector_name, collector, tier in self.collectors:
            try:
                logger.info(f"Collecting from {collector_name} ({tier})...")

                # Get last fetch time for incremental updates
                last_fetch = self.db.get_last_fetch_time(collector_name)

                # Collect CVEs
                cves = collector.collect(since=last_fetch)

                logger.info(f"Collected {len(cves)} CVEs from {collector_name}")

                # Add to combined list
                all_cves.extend(cves)

                # Update tracking
                self.db.update_source_tracking(collector_name, success=True)

                # Small delay between collectors
                time.sleep(2)

            except Exception as e:
                logger.error(f"Failed to collect from {collector_name}: {e}")
                self.db.update_source_tracking(collector_name, success=False, error=str(e))
                continue

        # Deduplicate by CVE ID
        unique_cves = {}
        for cve in all_cves:
            cve_id = cve.get('cve_id')
            if cve_id and cve_id not in unique_cves:
                unique_cves[cve_id] = cve

        logger.info(f"Total unique CVEs collected: {len(unique_cves)}")
        return list(unique_cves.values())

    def process_vulnerabilities(self, cves: List[Dict]) -> List[Dict]:
        """
        Process and enrich vulnerabilities.

        Args:
            cves: List of raw CVE data

        Returns:
            List[Dict]: Processed and enriched CVEs
        """
        processed = []

        for cve in cves:
            try:
                # Normalize CVSS score (handle None values)
                cvss_score = cve.get('cvss_score')
                if cvss_score is None:
                    cvss_score = 0.0
                    cve['cvss_score'] = 0.0

                # Match to devices FIRST (important for device-only mode)
                matched_devices = self.matcher.match_cve_to_devices(cve)
                cve['matched_devices'] = matched_devices

                # Apply filtering based on alert mode
                if self.alert_mode == 'device-only':
                    # DEVICE-ONLY MODE: Only process CVEs affecting our devices
                    if not matched_devices:
                        logger.debug(f"CVE {cve.get('cve_id')} doesn't affect any devices, skipping (device-only mode)")
                        continue

                    # Check device CVSS threshold
                    if cvss_score < self.min_cvss_devices:
                        logger.debug(f"CVE {cve.get('cve_id')} below device threshold ({cvss_score} < {self.min_cvss_devices})")
                        continue

                else:
                    # ALL-CVES MODE: Process device CVEs + high-CVSS CVEs
                    if matched_devices:
                        # Device CVE: use device threshold
                        if cvss_score < self.min_cvss_devices:
                            logger.debug(f"Device CVE {cve.get('cve_id')} below threshold ({cvss_score} < {self.min_cvss_devices})")
                            continue
                    else:
                        # Non-device CVE: use all-CVEs threshold
                        if cvss_score < self.min_cvss_all:
                            logger.debug(f"Non-device CVE {cve.get('cve_id')} below threshold ({cvss_score} < {self.min_cvss_all})")
                            continue

                # Check if already notified
                if self.db.is_cve_notified(cve.get('cve_id')):
                    logger.debug(f"CVE {cve.get('cve_id')} already notified, skipping")
                    continue

                # Calculate risk score
                risk_info = self.scorer.calculate_risk_score(cve, matched_devices)
                cve.update(risk_info)

                # AI analysis (if enabled and high priority)
                if self.ai_analyzer and risk_info.get('priority') in ['P0', 'P1']:
                    try:
                        ai_analysis = self.ai_analyzer.analyze_vulnerability(cve)
                        cve['ai_analysis'] = ai_analysis
                    except Exception as e:
                        logger.warning(f"AI analysis failed for {cve.get('cve_id')}: {e}")

                # Record in database
                self.db.record_cve(
                    cve_id=cve.get('cve_id'),
                    cvss_score=cve.get('cvss_score'),
                    severity=cve.get('severity'),
                    description=cve.get('description'),
                    source=cve.get('source'),
                    exploit_available=cve.get('exploit_available', False),
                    in_cisa_kev=cve.get('in_cisa_kev', False),
                    metadata=cve.get('metadata')
                )

                # Record device matches
                for device, confidence in matched_devices:
                    self.db.record_device_match(
                        cve_id=cve.get('cve_id'),
                        device_id=device.get('device_id'),
                        confidence=confidence
                    )

                processed.append(cve)

            except Exception as e:
                logger.error(f"Failed to process CVE {cve.get('cve_id', 'Unknown')}: {e}")
                continue

        logger.info(f"Processed {len(processed)} vulnerabilities")
        return processed

    def send_notifications(self, cves: List[Dict]):
        """
        Send notifications for vulnerabilities.

        Args:
            cves: List of processed CVEs
        """
        if not cves:
            logger.info("No new vulnerabilities to notify")
            return

        # Send immediate alerts for critical CVEs
        immediate_cves = [cve for cve in cves if cve.get('immediate_action_required', False)]

        for cve in immediate_cves:
            try:
                matched_devices = cve.get('matched_devices', [])
                matched_device_dicts = [d for d, conf in matched_devices]
                ai_analysis = cve.get('ai_analysis')

                success = self.notifier.send_immediate_alert(cve, matched_device_dicts, ai_analysis)

                if success:
                    self.db.mark_cve_notified(cve.get('cve_id'), 'immediate', 'sent')

            except Exception as e:
                logger.error(f"Failed to send immediate alert for {cve.get('cve_id')}: {e}")

        # Prepare digest for all CVEs
        summary = {
            'total': len(cves),
            'critical': len([c for c in cves if c.get('severity') == 'CRITICAL']),
            'high': len([c for c in cves if c.get('severity') == 'HIGH']),
            'medium': len([c for c in cves if c.get('severity') == 'MEDIUM'])
        }

        # Send digest
        try:
            if self.config.get('notifications', {}).get('schedule', {}).get('digest_summary', True):
                self.notifier.send_digest(cves, summary)

                # Mark all as notified
                for cve in cves:
                    if not self.db.is_cve_notified(cve.get('cve_id')):
                        self.db.mark_cve_notified(cve.get('cve_id'), 'digest', 'sent')

        except Exception as e:
            logger.error(f"Failed to send digest: {e}")

    def run_scan(self):
        """Execute a single vulnerability scan cycle."""
        logger.info(f"Starting scan cycle at {datetime.now()}")

        # Reset AI query counter for this scan cycle
        if hasattr(self.matcher, 'reset_ai_query_count'):
            self.matcher.reset_ai_query_count()
            logger.debug("AI query counter reset for new scan cycle")

        try:
            # Check system conditions
            if not self.check_system_conditions():
                logger.info("System conditions not suitable, skipping scan")
                return

            # Collect vulnerabilities
            cves = self.collect_vulnerabilities()

            if not cves:
                logger.info("No new vulnerabilities found")
                return

            # Process vulnerabilities
            processed_cves = self.process_vulnerabilities(cves)

            # Send notifications
            self.send_notifications(processed_cves)

            # Log statistics
            stats = self.db.get_cve_statistics()
            logger.info(f"Scan complete. Database stats: {stats}")

        except Exception as e:
            logger.error(f"Error during scan cycle: {e}", exc_info=True)

    def start(self):
        """Start the agent with scheduled scans."""
        logger.info(f"Starting SecVuln Agent with {self.interval_hours}h interval")

        # Run immediately
        self.run_scan()

        # Schedule regular scans
        schedule.every(self.interval_hours).hours.do(self.run_scan)

        logger.info("Agent running. Press Ctrl+C to stop.")

        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute

        except KeyboardInterrupt:
            logger.info("Agent stopped by user")

        finally:
            self.db.close()


def main():
    """Main entry point."""
    import sys

    # Show animated header when run from CLI
    if sys.stdout.isatty():  # Only show animation if running in terminal
        animated_header_agent()
        time.sleep(1)

    try:
        print_colored("\n🚀 Initializing SecVuln Agent...", Colors.CYAN, bold=True)
        agent = SecVulnAgent()
        print_status("Agent initialized successfully", 'success')
        print()
        agent.start()

    except KeyboardInterrupt:
        print()
        print_status("Agent stopped by user", 'info')
        sys.exit(0)

    except Exception as e:
        print_status(f"Fatal error: {e}", 'error')
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
