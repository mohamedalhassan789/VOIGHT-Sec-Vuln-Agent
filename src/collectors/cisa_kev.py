"""
CISA KEV (Known Exploited Vulnerabilities) Collector
Fetches vulnerabilities from CISA's Known Exploited Vulnerabilities catalog
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class CISAKEVCollector:
    """
    Collects vulnerabilities from CISA KEV catalog.
    This is a Tier 1 hot feed - check every run.
    """

    SOURCE_NAME = "CISA_KEV"
    API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, config: Dict = None):
        """
        Initialize CISA KEV collector.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect CVEs from CISA KEV catalog.

        Args:
            since: Only return CVEs added since this datetime (optional)

        Returns:
            List[Dict]: List of CVE dictionaries
        """
        try:
            logger.info(f"Fetching CISA KEV catalog from {self.API_URL}")

            response = requests.get(self.API_URL, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities from CISA KEV")

            # Parse and normalize CVE data
            cves = []
            for vuln in vulnerabilities:
                try:
                    cve = self._parse_vulnerability(vuln)

                    # Filter by date if requested
                    if since and cve.get('date_added'):
                        date_added = datetime.fromisoformat(cve['date_added'])
                        if date_added < since:
                            continue

                    cves.append(cve)

                except Exception as e:
                    logger.warning(f"Failed to parse vulnerability: {e}")
                    continue

            logger.info(f"Processed {len(cves)} CVEs from CISA KEV")
            return cves

        except requests.RequestException as e:
            logger.error(f"Failed to fetch CISA KEV catalog: {e}")
            raise
        except Exception as e:
            logger.error(f"Error processing CISA KEV data: {e}")
            raise

    def _parse_vulnerability(self, vuln: Dict) -> Dict:
        """
        Parse a CISA KEV vulnerability entry.

        Args:
            vuln: Raw vulnerability dictionary from CISA

        Returns:
            Dict: Normalized CVE dictionary
        """
        cve_id = vuln.get('cveID', 'Unknown')

        # CISA KEV doesn't always provide CVSS scores
        # We'll mark these as high severity by default since they're actively exploited
        cvss_score = 8.0  # Default high score for KEV entries

        # Determine severity
        severity = 'HIGH'  # All KEV entries are at least HIGH

        description = vuln.get('shortDescription', vuln.get('vulnerabilityName', ''))

        # Due date for remediation
        due_date = vuln.get('dueDate', '')

        # Vendor/Product info
        vendor_project = vuln.get('vendorProject', '')
        product = vuln.get('product', '')

        # Date added to KEV
        date_added = vuln.get('dateAdded', '')

        # Remediation guidance
        required_action = vuln.get('requiredAction', '')

        metadata = {
            'vendor_project': vendor_project,
            'product': product,
            'date_added': date_added,
            'due_date': due_date,
            'required_action': required_action,
            'vulnerability_name': vuln.get('vulnerabilityName', ''),
            'notes': vuln.get('notes', ''),
            'known_ransomware_use': vuln.get('knownRansomwareCampaignUse', 'Unknown')
        }

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': description,
            'source': self.SOURCE_NAME,
            'exploit_available': True,  # All CISA KEV entries have known exploits
            'in_cisa_kev': True,
            'date_added': date_added,
            'metadata': metadata
        }

    def get_statistics(self) -> Dict:
        """
        Get statistics about the CISA KEV catalog.

        Returns:
            Dict: Statistics dictionary
        """
        try:
            cves = self.collect()

            stats = {
                'total_vulnerabilities': len(cves),
                'source': self.SOURCE_NAME,
                'last_updated': datetime.now().isoformat()
            }

            # Count by vendor
            vendors = {}
            for cve in cves:
                vendor = cve.get('metadata', {}).get('vendor_project', 'Unknown')
                vendors[vendor] = vendors.get(vendor, 0) + 1

            stats['top_vendors'] = sorted(
                vendors.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            # Count ransomware-related
            ransomware_count = sum(
                1 for cve in cves
                if cve.get('metadata', {}).get('known_ransomware_use', 'Unknown').lower() == 'known'
            )
            stats['ransomware_related'] = ransomware_count

            return stats

        except Exception as e:
            logger.error(f"Failed to get CISA KEV statistics: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    from utils.logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    collector = CISAKEVCollector()

    # Fetch all CVEs
    cves = collector.collect()
    print(f"\nCollected {len(cves)} CVEs from CISA KEV")

    if cves:
        print("\nSample CVE:")
        import json
        print(json.dumps(cves[0], indent=2))

    # Get statistics
    stats = collector.get_statistics()
    print(f"\nCISA KEV Statistics:")
    print(f"Total: {stats.get('total_vulnerabilities', 0)}")
    print(f"Ransomware-related: {stats.get('ransomware_related', 0)}")
