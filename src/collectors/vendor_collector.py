"""
Vendor-Specific Collectors
Collects security advisories from vendor-specific sources (Cisco, Microsoft, Red Hat)
Tier 4 - Conditional on device inventory
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class VendorCollector:
    """
    Base class for vendor-specific collectors.
    Tier 4 - Check only if vendor devices exist in inventory.
    """

    def __init__(self, config: Dict = None):
        """
        Initialize vendor collector.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)

    def should_collect(self, devices: List[Dict], vendor_name: str) -> bool:
        """
        Check if we should collect from this vendor based on inventory.

        Args:
            devices: List of devices from inventory
            vendor_name: Vendor name to check

        Returns:
            bool: True if vendor devices exist in inventory
        """
        for device in devices:
            if vendor_name.lower() in device.get('vendor', '').lower():
                return True
        return False


class CiscoCollector(VendorCollector):
    """Collects from Cisco PSIRT."""

    SOURCE_NAME = "Cisco_PSIRT"
    API_URL = "https://sec.cloudapps.cisco.com/security/center/publicationService.x"

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """Collect Cisco security advisories."""
        try:
            logger.info("Fetching Cisco PSIRT advisories")

            # Note: Cisco PSIRT API requires authentication
            # This is a simplified implementation
            # In production, you'd need to implement OAuth authentication

            logger.warning("Cisco PSIRT collector requires API authentication - not yet implemented")
            return []

        except Exception as e:
            logger.error(f"Failed to collect from Cisco PSIRT: {e}")
            return []


class MicrosoftCollector(VendorCollector):
    """Collects from Microsoft Security Response Center."""

    SOURCE_NAME = "Microsoft_MSRC"
    API_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf"

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """Collect Microsoft security advisories."""
        try:
            logger.info("Fetching Microsoft MSRC advisories")

            # MSRC API provides security updates
            # This is a simplified implementation

            logger.warning("Microsoft MSRC collector not yet fully implemented")
            return []

        except Exception as e:
            logger.error(f"Failed to collect from Microsoft MSRC: {e}")
            return []


class RedHatCollector(VendorCollector):
    """Collects from Red Hat Security Data."""

    SOURCE_NAME = "RedHat_CVE"
    API_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """Collect Red Hat CVEs."""
        try:
            logger.info("Fetching Red Hat CVEs")

            params = {
                'per_page': 100
            }

            response = requests.get(
                self.API_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            cves_data = response.json()

            cves = []
            for cve_data in cves_data[:50]:  # Limit to 50
                try:
                    cve = self._parse_cve(cve_data)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    logger.debug(f"Failed to parse Red Hat CVE: {e}")
                    continue

            logger.info(f"Collected {len(cves)} CVEs from Red Hat")
            return cves

        except Exception as e:
            logger.error(f"Failed to collect from Red Hat: {e}")
            return []

    def _parse_cve(self, cve_data: Dict) -> Optional[Dict]:
        """Parse a Red Hat CVE entry."""
        cve_id = cve_data.get('CVE')

        if not cve_id:
            return None

        cvss3_score = cve_data.get('cvss3_score', 0.0)
        cvss_score = float(cvss3_score) if cvss3_score else 0.0

        severity = cve_data.get('severity', 'MEDIUM').upper()
        description = cve_data.get('bugzilla_description', '')

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': False,
            'in_cisa_kev': False,
            'metadata': cve_data
        }


if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    collector = RedHatCollector()
    cves = collector.collect()
    print(f"\nCollected {len(cves)} CVEs from Red Hat")
