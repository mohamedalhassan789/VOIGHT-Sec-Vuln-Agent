"""
CVE to Device Matcher
Matches CVE CPE strings to devices in inventory
"""

import re
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)


class DeviceMatcher:
    """
    Matches CVEs to devices based on vendor, product, and version information.
    Uses CPE (Common Platform Enumeration) matching.
    """

    def __init__(self, devices: List[Dict]):
        """
        Initialize matcher with device inventory.

        Args:
            devices: List of device dictionaries from devices.csv
        """
        self.devices = devices
        self._build_device_index()

    def _build_device_index(self):
        """Build indexes for faster matching."""
        self.vendor_index = {}
        self.product_index = {}

        for device in self.devices:
            vendor = device.get('vendor', '').lower()
            product = device.get('product', '').lower()

            # Index by vendor
            if vendor not in self.vendor_index:
                self.vendor_index[vendor] = []
            self.vendor_index[vendor].append(device)

            # Index by product
            if product not in self.product_index:
                self.product_index[product] = []
            self.product_index[product].append(device)

        logger.debug(f"Built device index: {len(self.vendor_index)} vendors, {len(self.product_index)} products")

    def match_cve_to_devices(self, cve_data: Dict) -> List[Tuple[Dict, float]]:
        """
        Match a CVE to devices in inventory.

        Args:
            cve_data: CVE data dictionary with CPE info

        Returns:
            List[Tuple[Dict, float]]: List of (device, confidence_score) tuples
        """
        matches = []

        # Extract CPE information from CVE data
        cpe_list = self._extract_cpe_from_cve(cve_data)

        if not cpe_list:
            # Try to match based on description
            matches.extend(self._match_by_description(cve_data))
        else:
            # Match based on CPE
            for cpe in cpe_list:
                device_matches = self._match_by_cpe(cpe)
                matches.extend(device_matches)

        # Remove duplicates and sort by confidence
        unique_matches = {}
        for device, confidence in matches:
            device_id = device['device_id']
            if device_id not in unique_matches or unique_matches[device_id][1] < confidence:
                unique_matches[device_id] = (device, confidence)

        sorted_matches = sorted(unique_matches.values(), key=lambda x: x[1], reverse=True)
        return sorted_matches

    def _extract_cpe_from_cve(self, cve_data: Dict) -> List[Dict]:
        """
        Extract CPE information from CVE data.

        Args:
            cve_data: CVE data dictionary

        Returns:
            List[Dict]: List of CPE dictionaries with vendor, product, version
        """
        cpe_list = []

        # Check for CPE in metadata
        metadata = cve_data.get('metadata', {})
        if isinstance(metadata, str):
            try:
                import json
                metadata = json.loads(metadata)
            except:
                metadata = {}

        # Look for CPE strings
        if 'cpe' in metadata:
            cpe_strings = metadata['cpe']
            if not isinstance(cpe_strings, list):
                cpe_strings = [cpe_strings]

            for cpe_str in cpe_strings:
                cpe_info = self._parse_cpe_string(cpe_str)
                if cpe_info:
                    cpe_list.append(cpe_info)

        # Look for affected products in metadata
        if 'affected_products' in metadata:
            for product in metadata['affected_products']:
                cpe_list.append({
                    'vendor': product.get('vendor', ''),
                    'product': product.get('product', ''),
                    'version': product.get('version', '')
                })

        return cpe_list

    def _parse_cpe_string(self, cpe_str: str) -> Dict:
        """
        Parse CPE 2.3 formatted string.
        Format: cpe:2.3:part:vendor:product:version:...

        Args:
            cpe_str: CPE string

        Returns:
            Dict: Parsed CPE components
        """
        if not cpe_str or not cpe_str.startswith('cpe:'):
            return {}

        parts = cpe_str.split(':')

        if len(parts) < 5:
            return {}

        return {
            'vendor': parts[3] if len(parts) > 3 else '',
            'product': parts[4] if len(parts) > 4 else '',
            'version': parts[5] if len(parts) > 5 else ''
        }

    def _match_by_cpe(self, cpe: Dict) -> List[Tuple[Dict, float]]:
        """
        Match devices based on CPE information.

        Args:
            cpe: CPE dictionary with vendor, product, version

        Returns:
            List[Tuple[Dict, float]]: List of (device, confidence) tuples
        """
        matches = []
        vendor = cpe.get('vendor', '').lower()
        product = cpe.get('product', '').lower()
        version = cpe.get('version', '').lower()

        # Look for vendor matches first
        candidate_devices = self.vendor_index.get(vendor, [])

        for device in candidate_devices:
            confidence = self._calculate_match_confidence(
                device, vendor, product, version
            )

            if confidence > 0.5:  # Only include matches with >50% confidence
                matches.append((device, confidence))

        return matches

    def _calculate_match_confidence(self, device: Dict, vendor: str,
                                     product: str, version: str) -> float:
        """
        Calculate confidence score for a device match.

        Args:
            device: Device dictionary
            vendor: CVE vendor
            product: CVE product
            version: CVE version

        Returns:
            float: Confidence score (0.0 - 1.0)
        """
        confidence = 0.0

        device_vendor = device.get('vendor', '').lower()
        device_product = device.get('product', '').lower()
        device_version = device.get('version', '').lower()

        # Vendor match (40% weight)
        if vendor and device_vendor:
            if vendor == device_vendor:
                confidence += 0.4
            elif vendor in device_vendor or device_vendor in vendor:
                confidence += 0.3

        # Product match (40% weight)
        if product and device_product:
            if product == device_product:
                confidence += 0.4
            elif product in device_product or device_product in product:
                confidence += 0.3
            elif self._fuzzy_match(product, device_product):
                confidence += 0.2

        # Version match (20% weight)
        if version and device_version and version != '*':
            if version == device_version:
                confidence += 0.2
            elif self._version_in_range(device_version, version):
                confidence += 0.15

        return min(confidence, 1.0)

    def _fuzzy_match(self, str1: str, str2: str) -> bool:
        """
        Perform fuzzy string matching.

        Args:
            str1: First string
            str2: Second string

        Returns:
            bool: True if strings are similar
        """
        # Remove common separators and compare
        clean1 = re.sub(r'[-_\s]', '', str1.lower())
        clean2 = re.sub(r'[-_\s]', '', str2.lower())

        return clean1 in clean2 or clean2 in clean1

    def _version_in_range(self, device_version: str, cve_version: str) -> bool:
        """
        Check if device version is affected by CVE version range.

        Args:
            device_version: Device version string
            cve_version: CVE version string (may include ranges)

        Returns:
            bool: True if version is in affected range
        """
        # Simple version comparison
        # This is a basic implementation - could be enhanced with version parsing libraries

        # Handle version ranges like "< 2.0", ">= 1.5"
        if any(op in cve_version for op in ['<', '>', '=']):
            return True  # Conservative: assume match if range specified

        # Direct version comparison
        try:
            device_parts = [int(x) for x in device_version.split('.') if x.isdigit()]
            cve_parts = [int(x) for x in cve_version.split('.') if x.isdigit()]

            # Pad to same length
            max_len = max(len(device_parts), len(cve_parts))
            device_parts += [0] * (max_len - len(device_parts))
            cve_parts += [0] * (max_len - len(cve_parts))

            # Check if versions match closely
            for i in range(max_len):
                if device_parts[i] != cve_parts[i]:
                    # Allow minor version differences
                    if i > 0:  # Major version must match
                        return True
                    return False

            return True

        except (ValueError, AttributeError):
            # If version parsing fails, be conservative
            return False

    def _match_by_description(self, cve_data: Dict) -> List[Tuple[Dict, float]]:
        """
        Match devices based on CVE description text.
        Used as fallback when CPE is not available.

        Args:
            cve_data: CVE data dictionary

        Returns:
            List[Tuple[Dict, float]]: List of (device, confidence) tuples
        """
        matches = []
        description = cve_data.get('description', '').lower()

        if not description:
            return matches

        for device in self.devices:
            vendor = device.get('vendor', '').lower()
            product = device.get('product', '').lower()

            confidence = 0.0

            # Check if vendor mentioned in description
            if vendor and vendor in description:
                confidence += 0.3

            # Check if product mentioned in description
            if product and product in description:
                confidence += 0.4

            # Check device type keywords
            device_type = device.get('device_type', '').lower()
            type_keywords = {
                'firewall': ['firewall', 'fw'],
                'router': ['router', 'routing'],
                'switch': ['switch', 'switching'],
                'database': ['database', 'db', 'sql'],
                'web_server': ['web server', 'apache', 'nginx', 'iis'],
            }

            if device_type in type_keywords:
                if any(kw in description for kw in type_keywords[device_type]):
                    confidence += 0.2

            if confidence > 0.5:
                matches.append((device, confidence))

        return matches

    def get_critical_device_matches(self, matches: List[Tuple[Dict, float]]) -> List[Tuple[Dict, float]]:
        """
        Filter matches to only critical devices.

        Args:
            matches: List of (device, confidence) tuples

        Returns:
            List[Tuple[Dict, float]]: Filtered matches
        """
        critical_matches = [
            (device, conf) for device, conf in matches
            if device.get('criticality', '').lower() in ['critical', 'high']
        ]

        return critical_matches


# Example usage
if __name__ == "__main__":
    from utils.logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    # Sample devices
    devices = [
        {
            'device_id': 'FW-001',
            'device_type': 'firewall',
            'vendor': 'Palo Alto',
            'product': 'PA-Series',
            'version': '10.2.3',
            'criticality': 'critical'
        },
        {
            'device_id': 'SW-001',
            'device_type': 'switch',
            'vendor': 'Cisco',
            'product': 'Catalyst 9300',
            'version': '17.6.4',
            'criticality': 'high'
        }
    ]

    matcher = DeviceMatcher(devices)

    # Sample CVE
    cve_data = {
        'cve_id': 'CVE-2024-1234',
        'description': 'Vulnerability in Palo Alto PA-Series firewalls',
        'metadata': {
            'cpe': ['cpe:2.3:h:paloaltonetworks:pa-series:10.2.0:*:*:*:*:*:*:*']
        }
    }

    matches = matcher.match_cve_to_devices(cve_data)
    print(f"\nFound {len(matches)} matches:")
    for device, confidence in matches:
        print(f"  {device['device_id']}: {confidence:.2%} confidence")
