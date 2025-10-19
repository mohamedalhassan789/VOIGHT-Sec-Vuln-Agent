"""
VulnCheck Initial Access Collector
Fetches initial access vulnerabilities from VulnCheck API
Source: https://api.vulncheck.com/v3/index/initial-access
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class VulnCheckCollector:
    """
    Collects initial access vulnerabilities from VulnCheck.
    Tier 1 hot feed - requires API key.
    """

    SOURCE_NAME = "VulnCheck_KEV"
    API_URL = "https://api.vulncheck.com/v3/index/initial-access"

    def __init__(self, config: Dict = None, api_key: Optional[str] = None):
        """
        Initialize VulnCheck collector.

        Args:
            config: Configuration dictionary
            api_key: VulnCheck API key (optional, can be in config)
        """
        self.config = config or {}
        self.api_key = api_key or self.config.get('api_key')
        self.timeout = self.config.get('timeout', 30)

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect CVEs from VulnCheck.

        Args:
            since: Only return CVEs since this datetime

        Returns:
            List[Dict]: List of CVE dictionaries
        """
        if not self.api_key:
            logger.warning("VulnCheck API key not configured, skipping")
            return []

        try:
            logger.info(f"Fetching vulnerabilities from VulnCheck")

            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Accept': 'application/json'
            }

            response = requests.get(
                self.API_URL,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('data', [])

            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities from VulnCheck")

            cves = []
            for vuln in vulnerabilities:
                try:
                    cve = self._parse_vulnerability(vuln)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    logger.warning(f"Failed to parse VulnCheck entry: {e}")
                    continue

            logger.info(f"Processed {len(cves)} CVEs from VulnCheck")
            return cves

        except requests.RequestException as e:
            logger.error(f"Failed to fetch from VulnCheck: {e}")
            return []

    def _parse_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """Parse a VulnCheck vulnerability entry."""
        cve_id = vuln.get('cve_id') or vuln.get('cve')

        if not cve_id:
            return None

        cvss_score = float(vuln.get('cvss_score', 0.0))
        severity = vuln.get('severity', 'HIGH').upper()
        description = vuln.get('description', vuln.get('summary', ''))

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': True,  # VulnCheck focuses on exploitable vulns
            'in_cisa_kev': False,
            'metadata': vuln
        }


if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    # Note: Requires API key
    collector = VulnCheckCollector()
    cves = collector.collect()
    print(f"\nCollected {len(cves)} CVEs from VulnCheck")
