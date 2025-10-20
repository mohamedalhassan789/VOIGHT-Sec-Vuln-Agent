"""
CVEFeed.io Collector
Collects vulnerability data from CVEFeed.io RSS feeds
"""

import feedparser
import logging
import re
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
import time

logger = logging.getLogger(__name__)


class CVEFeedCollector:
    """
    Collects CVE data from CVEFeed.io RSS feeds.
    Tier 1 - Hot feed with 15-minute updates.

    Feeds:
    - critical-high: High and critical severity CVEs only
    - latest: All recent CVEs
    - newsroom: Cyber news with CVE correlation (adds media_coverage flag)
    """

    SOURCE_NAME = "CVEFeed.io"

    FEEDS = {
        'severity-high': {
            'url': 'https://cvefeed.io/rssfeed/severity/high.xml',
            'priority': 'high',
            'description': 'High and critical severity CVEs'
        },
        'latest': {
            'url': 'https://cvefeed.io/rssfeed/latest.xml',
            'priority': 'medium',
            'description': 'All recent CVEs (last 25, updated every 15 minutes)'
        },
        'newsroom': {
            'url': 'https://cvefeed.io/rssfeed/newsroom.xml',
            'priority': 'medium',
            'description': 'Cyber news from 100+ sources with CVE correlation'
        }
    }

    def __init__(self, config: Dict = None):
        """
        Initialize CVEFeed collector.

        Args:
            config: Configuration dictionary with enabled feeds
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)

        # Track newsroom CVEs for media coverage flag
        self.newsroom_cves = set()

        # Determine which feeds are enabled
        self.enabled_feeds = {}
        feeds_config = self.config.get('feeds', {})

        for feed_name, feed_info in self.FEEDS.items():
            feed_enabled = feeds_config.get(feed_name, {}).get('enabled', True)
            if feed_enabled:
                self.enabled_feeds[feed_name] = feed_info

        logger.debug(f"CVEFeed.io enabled feeds: {list(self.enabled_feeds.keys())}")

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect CVEs from CVEFeed.io feeds.

        Args:
            since: Only return CVEs since this datetime

        Returns:
            List[Dict]: List of CVE entries
        """
        all_cves = []

        # First pass: Collect newsroom CVEs to flag them
        if 'newsroom' in self.enabled_feeds:
            try:
                logger.info("Fetching CVEFeed.io newsroom feed for media coverage tracking")
                newsroom_entries = self._fetch_feed('newsroom', self.enabled_feeds['newsroom'], since)

                # Extract CVE IDs from newsroom
                for entry in newsroom_entries:
                    if entry.get('cve_id'):
                        self.newsroom_cves.add(entry['cve_id'])

                logger.debug(f"Found {len(self.newsroom_cves)} CVEs with media coverage")

                # Add newsroom entries to collection
                all_cves.extend(newsroom_entries)

                time.sleep(2)  # Rate limiting

            except Exception as e:
                logger.error(f"Failed to fetch newsroom feed: {e}")

        # Second pass: Collect CVE feeds
        for feed_name, feed_info in self.enabled_feeds.items():
            if feed_name == 'newsroom':
                continue  # Already processed

            try:
                logger.info(f"Fetching CVEFeed.io feed: {feed_name}")
                entries = self._fetch_feed(feed_name, feed_info, since)

                # Add media coverage flag if CVE was in newsroom
                for entry in entries:
                    if entry.get('cve_id') in self.newsroom_cves:
                        entry['media_coverage'] = True
                        entry['metadata']['media_coverage'] = True

                all_cves.extend(entries)

                # Rate limiting between feeds
                time.sleep(2)

            except Exception as e:
                logger.error(f"Failed to fetch CVEFeed.io feed {feed_name}: {e}")
                continue

        # Deduplicate by CVE ID (keep highest priority)
        unique_cves = {}
        for cve in all_cves:
            cve_id = cve.get('cve_id')
            if cve_id:
                if cve_id not in unique_cves:
                    unique_cves[cve_id] = cve
                else:
                    # Merge metadata if duplicate
                    existing = unique_cves[cve_id]
                    if cve.get('media_coverage') and not existing.get('media_coverage'):
                        existing['media_coverage'] = True
                        existing['metadata']['media_coverage'] = True

        logger.info(f"Collected {len(unique_cves)} unique CVEs from CVEFeed.io")
        return list(unique_cves.values())

    def _fetch_feed(self, feed_name: str, feed_info: Dict, since: Optional[datetime] = None) -> List[Dict]:
        """Fetch and parse a single CVEFeed.io RSS feed."""
        try:
            feed_url = feed_info['url']

            # Parse feed with custom agent
            feed = feedparser.parse(
                feed_url,
                agent='Mozilla/5.0 (VOIGHT SecVuln Agent/1.0)'
            )

            if feed.bozo:  # Error in feed
                logger.warning(f"CVEFeed.io feed {feed_name} has parsing errors: {feed.bozo_exception}")

            entries = []
            for entry in feed.entries[:100]:  # Limit to 100 most recent
                try:
                    parsed_entry = self._parse_entry(entry, feed_name)

                    # Filter by date if requested
                    if since and parsed_entry.get('published_date'):
                        try:
                            pub_date = datetime.fromisoformat(parsed_entry['published_date'])
                            if pub_date < since:
                                continue
                        except ValueError:
                            pass  # Include if date parsing fails

                    entries.append(parsed_entry)

                except Exception as e:
                    logger.debug(f"Failed to parse CVEFeed.io entry: {e}")
                    continue

            logger.debug(f"Parsed {len(entries)} entries from CVEFeed.io {feed_name}")
            return entries

        except Exception as e:
            logger.error(f"Failed to fetch CVEFeed.io feed {feed_url}: {e}")
            raise

    def _parse_entry(self, entry, feed_name: str) -> Dict:
        """Parse a CVEFeed.io RSS entry."""
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

        # Extract CVE ID from title (CVEFeed.io typically includes CVE ID in title)
        cve_id = self._extract_cve_id(title, description)

        # Extract CVSS score if present
        cvss_score = self._extract_cvss_score(description)

        # Determine severity
        severity = self._determine_severity(title, description, cvss_score, feed_name)

        # Check for exploit mentions
        text = f"{title} {description}".lower()
        exploit_mentioned = any(word in text for word in [
            'exploit', 'poc', 'proof of concept', 'weaponized', 'actively exploited',
            'in the wild', 'zero-day', '0-day'
        ])

        # Extract affected products/vendors if mentioned
        affected_products = self._extract_affected_products(title, description)

        # Build metadata
        metadata = {
            'source_url': link,
            'feed_name': feed_name,
            'feed_type': 'newsroom' if feed_name == 'newsroom' else 'cve',
            'cvefeed_link': link
        }

        if affected_products:
            metadata['affected_products'] = affected_products

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': exploit_mentioned,
            'in_cisa_kev': False,  # Will be cross-referenced by main system
            'media_coverage': feed_name == 'newsroom',  # Flag if from newsroom
            'title': title,
            'link': link,
            'published_date': published_date,
            'metadata': metadata
        }

    def _extract_cve_id(self, title: str, description: str) -> Optional[str]:
        """Extract CVE ID from title or description."""
        text = f"{title} {description}"

        # Regex pattern for CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'

        match = re.search(cve_pattern, text, re.IGNORECASE)
        if match:
            return match.group(0).upper()

        return None

    def _extract_cvss_score(self, text: str) -> float:
        """Extract CVSS score from text if present."""
        # Look for CVSS score patterns
        # Examples: "CVSS: 9.8", "CVSS Score: 7.5", "CVSS v3.1: 8.1"
        cvss_patterns = [
            r'CVSS\s*(?:v?3\.?[01])?\s*[:\-]\s*(\d+\.?\d*)',
            r'CVSS\s+Score\s*[:\-]\s*(\d+\.?\d*)',
            r'score\s+of\s+(\d+\.?\d*)',
        ]

        for pattern in cvss_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    score = float(match.group(1))
                    if 0.0 <= score <= 10.0:
                        return score
                except ValueError:
                    continue

        return 0.0

    def _determine_severity(self, title: str, description: str, cvss_score: float, feed_name: str) -> str:
        """Determine severity from CVSS score or keywords."""
        # If we have CVSS score, use standard mapping
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0.0:
            return 'LOW'

        # If from critical-high feed, default to HIGH
        if feed_name == 'critical-high':
            text = f"{title} {description}".lower()
            if 'critical' in text:
                return 'CRITICAL'
            return 'HIGH'

        # Otherwise, extract from keywords
        text = f"{title} {description}".lower()

        if any(word in text for word in ['critical', 'severe', 'dangerous', '9.', '10.']):
            return 'CRITICAL'
        elif any(word in text for word in ['high', 'important', 'serious', '7.', '8.']):
            return 'HIGH'
        elif any(word in text for word in ['medium', 'moderate', '4.', '5.', '6.']):
            return 'MEDIUM'
        elif any(word in text for word in ['low', 'minor', 'info']):
            return 'LOW'

        # Default to MEDIUM for unknown
        return 'MEDIUM'

    def _extract_affected_products(self, title: str, description: str) -> List[str]:
        """Extract affected products/vendors from text."""
        text = f"{title} {description}"

        # Common vendor patterns
        vendors = [
            'Microsoft', 'Cisco', 'VMware', 'Adobe', 'Oracle', 'Apple',
            'Google', 'Mozilla', 'Linux', 'Red Hat', 'Ubuntu', 'Debian',
            'Apache', 'nginx', 'PHP', 'WordPress', 'Drupal', 'Joomla',
            'Fortinet', 'Palo Alto', 'Juniper', 'F5', 'Citrix'
        ]

        found_products = []
        for vendor in vendors:
            if re.search(rf'\b{vendor}\b', text, re.IGNORECASE):
                found_products.append(vendor)

        return found_products[:5]  # Limit to 5 to avoid noise


if __name__ == "__main__":
    # Test the collector
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from utils.logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    config = {
        'feeds': {
            'critical-high': {'enabled': True},
            'newsroom': {'enabled': True}
        }
    }

    collector = CVEFeedCollector(config)
    cves = collector.collect()

    print(f"\nCollected {len(cves)} CVEs from CVEFeed.io")

    # Show sample CVEs
    for cve in cves[:5]:
        media = " [MEDIA COVERAGE]" if cve.get('media_coverage') else ""
        print(f"\n{cve['cve_id']} - {cve['severity']}{media}")
        print(f"  CVSS: {cve['cvss_score']}")
        print(f"  Title: {cve['title'][:80]}")
