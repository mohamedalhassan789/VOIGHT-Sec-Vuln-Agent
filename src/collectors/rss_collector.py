"""
RSS Feed Collector
Collects security news from RSS feeds (Reddit r/netsec, Packet Storm, The Hacker News)
"""

import feedparser
import requests
import logging
import re
from typing import List, Dict, Optional
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class RSSCollector:
    """
    Collects security news from multiple RSS feeds.
    Tier 2 - Community feeds, check every run.
    """

    SOURCE_NAME = "RSS_Feeds"

    FEEDS = {
        'reddit_netsec': 'https://www.reddit.com/r/netsec/.rss',
        'packetstorm': 'https://packetstormsecurity.com/feeds',  # Updated URL
        'hackernews': 'https://feeds.feedburner.com/TheHackersNews'
    }

    def __init__(self, config: Dict = None):
        """
        Initialize RSS collector.

        Args:
            config: Configuration dictionary with enabled feeds
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)

        # Determine which feeds are enabled
        self.enabled_feeds = {}
        for feed_name, feed_url in self.FEEDS.items():
            if self.config.get(feed_name, True):  # Default to enabled
                self.enabled_feeds[feed_name] = feed_url

        logger.debug(f"Enabled RSS feeds: {list(self.enabled_feeds.keys())}")

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect entries from RSS feeds.

        Args:
            since: Only return entries since this datetime

        Returns:
            List[Dict]: List of security news items (not strict CVEs)
        """
        all_entries = []

        for feed_name, feed_url in self.enabled_feeds.items():
            try:
                logger.info(f"Fetching RSS feed: {feed_name}")
                entries = self._fetch_feed(feed_name, feed_url, since)
                all_entries.extend(entries)

                # Rate limiting between feeds
                time.sleep(1)

            except Exception as e:
                logger.error(f"Failed to fetch RSS feed {feed_name}: {e}")
                continue

        logger.info(f"Collected {len(all_entries)} entries from RSS feeds")
        return all_entries

    def _fetch_feed(self, feed_name: str, feed_url: str, since: Optional[datetime] = None) -> List[Dict]:
        """Fetch and parse a single RSS feed."""
        try:
            # Parse feed with custom agent to avoid blocking
            feed = feedparser.parse(
                feed_url,
                agent='Mozilla/5.0 (VOIGHT SecVuln Agent)'
            )

            if feed.bozo:  # Error in feed
                # Check if it's a certificate error (non-fatal)
                if 'certificate' in str(feed.bozo_exception).lower():
                    logger.warning(f"RSS feed {feed_name} has SSL certificate issues (continuing anyway)")
                else:
                    logger.warning(f"RSS feed {feed_name} has errors: {feed.bozo_exception}")

            entries = []
            for entry in feed.entries[:50]:  # Limit to 50 most recent
                try:
                    parsed_entry = self._parse_entry(entry, feed_name)

                    # Filter by date if requested
                    if since and parsed_entry.get('published_date'):
                        pub_date = datetime.fromisoformat(parsed_entry['published_date'])
                        if pub_date < since:
                            continue

                    # Extract CVEs if mentioned
                    cves = self._extract_cves(parsed_entry)

                    if cves:
                        # If CVEs mentioned, create entries for each
                        for cve_id in cves:
                            cve_entry = parsed_entry.copy()
                            cve_entry['cve_id'] = cve_id
                            cve_entry['mentioned_cves'] = cves
                            entries.append(cve_entry)
                    else:
                        # General security news (no specific CVE)
                        entries.append(parsed_entry)

                except Exception as e:
                    logger.debug(f"Failed to parse RSS entry: {e}")
                    continue

            logger.debug(f"Parsed {len(entries)} entries from {feed_name}")
            return entries

        except Exception as e:
            logger.error(f"Failed to fetch RSS feed {feed_url}: {e}")
            raise

    def _parse_entry(self, entry, feed_name: str) -> Dict:
        """Parse an RSS entry."""
        title = entry.get('title', '')
        description = entry.get('summary', entry.get('description', ''))
        link = entry.get('link', '')

        # Parse publish date
        published_date = None
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            try:
                published_date = datetime(*entry.published_parsed[:6]).isoformat()
            except:
                pass

        # Extract severity hints from title/description
        text = f"{title} {description}".lower()
        severity = 'MEDIUM'  # Default

        if any(word in text for word in ['critical', 'severe', 'dangerous']):
            severity = 'CRITICAL'
        elif any(word in text for word in ['high', 'important', 'serious']):
            severity = 'HIGH'
        elif any(word in text for word in ['low', 'minor', 'info']):
            severity = 'LOW'

        # Check for exploit mentions
        exploit_mentioned = any(word in text for word in [
            'exploit', 'poc', 'proof of concept', 'weaponized'
        ])

        return {
            'cve_id': None,  # Will be filled if CVE extracted
            'cvss_score': 0.0,  # RSS feeds rarely include CVSS
            'severity': severity,
            'description': f"{title}\n\n{description}",
            'source': f"{self.SOURCE_NAME}_{feed_name}",
            'exploit_available': exploit_mentioned,
            'in_cisa_kev': False,
            'title': title,
            'link': link,
            'published_date': published_date,
            'feed_source': feed_name,
            'metadata': {
                'rss_link': link,
                'rss_title': title,
                'feed_name': feed_name
            }
        }

    def _extract_cves(self, entry: Dict) -> List[str]:
        """
        Extract CVE IDs from entry text.

        Args:
            entry: Parsed entry dictionary

        Returns:
            List[str]: List of CVE IDs found
        """
        text = f"{entry.get('title', '')} {entry.get('description', '')}"

        # Regex pattern for CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'

        cves = re.findall(cve_pattern, text, re.IGNORECASE)

        # Normalize to uppercase
        cves = list(set(cve.upper() for cve in cves))

        return cves


if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    collector = RSSCollector()
    entries = collector.collect()
    print(f"\nCollected {len(entries)} entries from RSS feeds")

    # Show entries with CVEs
    cve_entries = [e for e in entries if e.get('cve_id')]
    print(f"Entries with CVEs: {len(cve_entries)}")
