"""
GitHub Security Advisories Collector
Fetches security advisories from GitHub's Security Advisory Database
Source: https://api.github.com/advisories
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class GitHubAdvisoriesCollector:
    """
    Collects security advisories from GitHub.
    Tier 1 hot feed - check every run.
    """

    SOURCE_NAME = "GitHub_Advisories"
    API_URL = "https://api.github.com/advisories"

    def __init__(self, config: Dict = None):
        """
        Initialize GitHub Advisories collector.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.max_results = self.config.get('max_results', 100)

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect advisories from GitHub.

        Args:
            since: Only return advisories updated since this datetime

        Returns:
            List[Dict]: List of CVE dictionaries
        """
        try:
            logger.info(f"Fetching GitHub Security Advisories")

            headers = {
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }

            params = {
                'per_page': min(self.max_results, 100),
                'sort': 'updated',
                'direction': 'desc'
            }

            # Add since parameter if provided
            if since:
                params['updated'] = f'>={since.strftime("%Y-%m-%d")}'

            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            advisories = response.json()
            logger.info(f"Retrieved {len(advisories)} advisories from GitHub")

            # Parse and normalize
            cves = []
            for advisory in advisories:
                try:
                    cve = self._parse_advisory(advisory)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    logger.warning(f"Failed to parse advisory: {e}")
                    continue

            logger.info(f"Processed {len(cves)} CVEs from GitHub Advisories")
            return cves

        except requests.RequestException as e:
            logger.error(f"Failed to fetch GitHub Advisories: {e}")
            raise
        except Exception as e:
            logger.error(f"Error processing GitHub Advisories: {e}")
            raise

    def _parse_advisory(self, advisory: Dict) -> Optional[Dict]:
        """Parse a GitHub advisory."""
        cve_id = advisory.get('cve_id')

        if not cve_id:
            # Some advisories don't have CVE IDs yet
            ghsa_id = advisory.get('ghsa_id', '')
            if ghsa_id:
                cve_id = f"GHSA-{ghsa_id.split('-', 1)[1]}" if '-' in ghsa_id else ghsa_id
            else:
                return None

        # Parse CVSS
        cvss = advisory.get('cvss', {})
        cvss_score = cvss.get('score', 0.0) if cvss else 0.0

        severity = advisory.get('severity', 'UNKNOWN').upper()

        description = advisory.get('summary', advisory.get('description', ''))

        # Vulnerabilities array contains affected packages
        vulnerabilities = advisory.get('vulnerabilities', [])

        # Check if exploit is mentioned
        exploit_available = 'exploit' in description.lower()

        metadata = {
            'ghsa_id': advisory.get('ghsa_id', ''),
            'published_at': advisory.get('published_at', ''),
            'updated_at': advisory.get('updated_at', ''),
            'withdrawn_at': advisory.get('withdrawn_at'),
            'author': advisory.get('author', {}).get('login', ''),
            'url': advisory.get('html_url', ''),
            'vulnerabilities': vulnerabilities,
            'references': advisory.get('references', [])
        }

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': exploit_available,
            'in_cisa_kev': False,
            'metadata': metadata
        }


if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    collector = GitHubAdvisoriesCollector()
    cves = collector.collect()
    print(f"\nCollected {len(cves)} advisories from GitHub")
