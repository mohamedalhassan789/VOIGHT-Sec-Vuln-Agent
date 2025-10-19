"""
NVD (National Vulnerability Database) Collector
Fetches CVEs from NVD using the official API 2.0
Source: https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import requests
import logging
import time
from typing import List, Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class NVDCollector:
    """
    Collects CVEs from NVD.
    Tier 3 - Official source, check every 6 hours.
    Rate limited: 5 requests per 30 seconds without API key.
    """

    SOURCE_NAME = "NVD"
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: Dict = None, api_key: Optional[str] = None):
        """
        Initialize NVD collector.

        Args:
            config: Configuration dictionary
            api_key: NVD API key (optional, increases rate limit)
        """
        self.config = config or {}
        self.api_key = api_key or self.config.get('api_key')
        self.timeout = self.config.get('timeout', 60)

        # Rate limiting
        self.rate_limit_delay = 6 if not self.api_key else 0.6  # seconds

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect CVEs from NVD.

        Args:
            since: Only return CVEs modified since this datetime

        Returns:
            List[Dict]: List of CVE dictionaries
        """
        try:
            logger.info(f"Fetching CVEs from NVD")

            # Default to last 7 days if not specified
            if not since:
                since = datetime.now() - timedelta(days=7)

            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            params = {
                'lastModStartDate': since.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'lastModEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 100
            }

            cves = []
            start_index = 0
            max_results = 500  # Limit to avoid excessive API calls

            while len(cves) < max_results:
                params['startIndex'] = start_index

                # Rate limiting
                time.sleep(self.rate_limit_delay)

                response = requests.get(
                    self.API_URL,
                    headers=headers,
                    params=params,
                    timeout=self.timeout
                )
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    try:
                        cve = self._parse_cve(vuln.get('cve', {}))
                        if cve:
                            cves.append(cve)
                    except Exception as e:
                        logger.debug(f"Failed to parse NVD entry: {e}")
                        continue

                # Check if more results available
                total_results = data.get('totalResults', 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break

                start_index += len(vulnerabilities)

            logger.info(f"Collected {len(cves)} CVEs from NVD")
            return cves

        except requests.RequestException as e:
            logger.error(f"Failed to fetch from NVD: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing NVD data: {e}")
            return []

    def _parse_cve(self, cve_data: Dict) -> Optional[Dict]:
        """Parse an NVD CVE entry."""
        cve_id = cve_data.get('id')

        if not cve_id:
            return None

        # Extract CVSS score (prefer v3, fall back to v2)
        cvss_score = 0.0
        severity = 'UNKNOWN'

        metrics = cve_data.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
        cvss_v2 = metrics.get('cvssMetricV2', [])

        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
        elif cvss_v2:
            cvss_data = cvss_v2[0].get('cvssData', {})
            cvss_score = cvss_data.get('baseScore', 0.0)
            # Map v2 score to severity
            if cvss_score >= 7.0:
                severity = 'HIGH'
            elif cvss_score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

        # Get description
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        return {
            'cve_id': cve_id,
            'cvss_score': float(cvss_score),
            'severity': severity.upper(),
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': False,  # NVD doesn't directly provide this
            'in_cisa_kev': False,
            'metadata': {
                'published': cve_data.get('published'),
                'lastModified': cve_data.get('lastModified'),
                'cpe': [ref.get('criteria') for ref in cve_data.get('configurations', {}).get('nodes', []) if ref.get('cpeMatch')]
            }
        }


if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    collector = NVDCollector()
    cves = collector.collect()
    print(f"\nCollected {len(cves)} CVEs from NVD")
