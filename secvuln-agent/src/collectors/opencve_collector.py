"""
OpenCVE Collector
Fetches recent CVEs from OpenCVE.io (updates every 2h)
Source: https://www.opencve.io/api/cve
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class OpenCVECollector:
    """
    Collects recent CVEs from OpenCVE.
    Tier 1 hot feed - updates every 2 hours.

    NOTE: OpenCVE now requires authentication. Free tier available at https://www.opencve.io/
    """

    SOURCE_NAME = "OpenCVE"
    API_URL = "https://www.opencve.io/api/cve"

    def __init__(self, config: Dict = None, api_key: str = None):
        """
        Initialize OpenCVE collector.

        Args:
            config: Configuration dictionary
            api_key: OpenCVE API key (optional, but required for access)
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.max_pages = self.config.get('max_pages', 3)
        self.api_key = api_key

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect CVEs from OpenCVE.

        Args:
            since: Only return CVEs since this datetime

        Returns:
            List[Dict]: List of CVE dictionaries
        """
        # Check if API key is available
        if not self.api_key:
            logger.warning("OpenCVE API key not configured. Skipping OpenCVE collection.")
            logger.info("To use OpenCVE, sign up at https://www.opencve.io/ and add your API key to secrets")
            return []

        try:
            logger.info(f"Fetching CVEs from OpenCVE")

            # Default to last 24 hours if not specified
            if not since:
                since = datetime.now() - timedelta(hours=24)

            cves = []
            page = 1

            while page <= self.max_pages:
                try:
                    params = {
                        'page': page,
                        'cvss': 0,  # Min CVSS score
                        'sort': 'updated_at',
                    }

                    headers = {
                        'Authorization': f'Bearer {self.api_key}'
                    }

                    response = requests.get(
                        self.API_URL,
                        params=params,
                        headers=headers,
                        timeout=self.timeout
                    )

                    # Handle 403 specifically
                    if response.status_code == 403:
                        logger.warning("OpenCVE API authentication failed (403). Please check your API key.")
                        return []

                    response.raise_for_status()

                    data = response.json()
                    page_cves = data if isinstance(data, list) else data.get('data', [])

                    if not page_cves:
                        break

                    for cve_data in page_cves:
                        try:
                            cve = self._parse_cve(cve_data)
                            if cve:
                                cves.append(cve)
                        except Exception as e:
                            logger.debug(f"Failed to parse OpenCVE entry: {e}")
                            continue

                    page += 1

                except requests.RequestException as e:
                    logger.warning(f"Failed to fetch page {page} from OpenCVE: {e}")
                    break

            logger.info(f"Collected {len(cves)} CVEs from OpenCVE")
            return cves

        except Exception as e:
            logger.error(f"Error collecting from OpenCVE: {e}")
            return []

    def _parse_cve(self, cve_data: Dict) -> Optional[Dict]:
        """Parse an OpenCVE entry."""
        cve_id = cve_data.get('id') or cve_data.get('cve_id')

        if not cve_id:
            return None

        # Extract CVSS score
        cvss_v3 = cve_data.get('cvss', {}).get('v3', 0.0)
        cvss_v2 = cve_data.get('cvss', {}).get('v2', 0.0)
        cvss_score = cvss_v3 or cvss_v2 or 0.0

        # Determine severity
        severity = cve_data.get('severity', 'MEDIUM').upper()

        description = cve_data.get('summary', '')

        return {
            'cve_id': cve_id,
            'cvss_score': float(cvss_score),
            'severity': severity,
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': False,  # Not provided by OpenCVE basic API
            'in_cisa_kev': False,
            'metadata': cve_data
        }


if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    collector = OpenCVECollector()
    cves = collector.collect()
    print(f"\nCollected {len(cves)} CVEs from OpenCVE")
