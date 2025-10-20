"""
CVE to Device Matcher with Two-Stage Verification
Stage 1: Traditional CPE/vendor/product matching with normalization
Stage 2: AI-powered verification with strict privacy controls (optional)
"""

import re
import logging
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class DeviceMatcher:
    """
    Enhanced CVE to Device matcher with two-stage approach:
    - Stage 1: Traditional matching (CPE, vendor, product, version) with normalization
    - Stage 2: AI verification for ambiguous matches (0.5-0.7 confidence) - optional

    Security: Stage 2 never exposes device IDs, hostnames, IPs, or locations to AI.
    """

    # Comprehensive vendor aliases for normalization
    VENDOR_ALIASES = {
        'microsoft': ['microsoft', 'ms', 'msft', 'windows'],
        'cisco': ['cisco', 'cisco systems', 'cisco_systems'],
        'paloalto': ['palo alto', 'palo alto networks', 'paloaltonetworks', 'pan'],
        'fortinet': ['fortinet', 'fortigate', 'forti'],
        'vmware': ['vmware', 'vm ware'],
        'oracle': ['oracle', 'oracle corporation'],
        'redhat': ['red hat', 'redhat', 'red_hat'],
        'canonical': ['canonical', 'ubuntu'],
        'apache': ['apache', 'apache software foundation'],
        'nginx': ['nginx', 'nginx inc'],
        'juniper': ['juniper', 'juniper networks'],
        'dell': ['dell', 'dell emc', 'dell technologies'],
        'hp': ['hp', 'hewlett packard', 'hewlett-packard', 'hpe'],
        'huawei': ['huawei', 'huawei technologies'],
        'arista': ['arista', 'arista networks'],
        'f5': ['f5', 'f5 networks'],
        'checkpoint': ['check point', 'checkpoint', 'check_point'],
        'ibm': ['ibm', 'international business machines'],
        'centos': ['centos', 'cent os'],
        'debian': ['debian', 'debian gnu/linux'],
        'suse': ['suse', 'opensuse'],
    }

    # Product aliases and variations
    PRODUCT_ALIASES = {
        'windows_server': ['windows server', 'windows_server', 'windowsserver', 'server'],
        'windows': ['windows', 'win'],
        'sql_server': ['sql server', 'sql_server', 'sqlserver', 'mssql', 'ms sql'],
        'exchange': ['exchange', 'exchange server'],
        'iis': ['iis', 'internet information services'],
        'fortigate': ['fortigate', 'fortios', 'fg'],
        'fortinac': ['fortinac', 'nac'],
        'pa_series': ['pa-series', 'pa series', 'pan-os'],
        'catalyst': ['catalyst'],
        'nexus': ['nexus'],
        'asa': ['asa', 'adaptive security appliance'],
        'esxi': ['esxi', 'vsphere', 'vcenter'],
        'mysql': ['mysql', 'mariadb'],
        'postgresql': ['postgresql', 'postgres', 'pgsql'],
        'apache_httpd': ['apache', 'httpd', 'http server', 'apache http server'],
        'nginx': ['nginx'],
        'ubuntu': ['ubuntu', 'ubuntu linux'],
        'centos': ['centos'],
    }

    # Windows version mapping for cross-version matching
    WINDOWS_VERSIONS = {
        '21h2': ['21h2', '2022', 'server 2022'],
        '20h2': ['20h2', '2019', 'server 2019'],
        '1809': ['1809', '2019', 'server 2019'],
        '11': ['11', 'windows 11'],
        '10': ['10', 'windows 10'],
        '2022': ['2022', '21h2', 'server 2022'],
        '2019': ['2019', '1809', '20h2', 'server 2019'],
        '2016': ['2016', '1607', 'server 2016'],
        '2012': ['2012', 'server 2012', '2012 r2'],
    }

    def __init__(self, devices: List[Dict], ai_analyzer=None, config: Dict = None):
        """
        Initialize matcher with device inventory and optional AI verification.

        Args:
            devices: List of device dictionaries from devices.csv
            ai_analyzer: Optional AIAnalyzer for Stage 2 verification
            config: Configuration dict for AI matching settings
        """
        self.devices = devices
        self.ai_analyzer = ai_analyzer
        self.config = config or {}

        # AI verification settings
        self.ai_verification_enabled = self.config.get('ai', {}).get('matching_verification', {}).get('enabled', False)
        self.ai_confidence_min = self.config.get('ai', {}).get('matching_verification', {}).get('confidence_threshold_min', 0.5)
        self.ai_confidence_max = self.config.get('ai', {}).get('matching_verification', {}).get('confidence_threshold_max', 0.7)
        self.ai_max_queries = self.config.get('ai', {}).get('matching_verification', {}).get('max_queries_per_scan', 50)
        self.ai_cache_enabled = self.config.get('ai', {}).get('matching_verification', {}).get('cache_responses', True)

        # AI verification state
        self.ai_cache = {}
        self.ai_query_count = 0

        self._build_device_index()

        logger.info(f"DeviceMatcher initialized with {len(devices)} devices")
        if self.ai_verification_enabled and self.ai_analyzer:
            logger.info(f"AI verification enabled (queries: {self.ai_query_count}/{self.ai_max_queries})")
        else:
            logger.info("AI verification disabled (using traditional matching only)")

    def _build_device_index(self):
        """Build indexes for faster matching with normalization."""
        self.vendor_index = {}
        self.product_index = {}

        for device in self.devices:
            vendor = device.get('vendor', '').lower()
            product = device.get('product', '').lower()

            # Normalize and index by vendor
            normalized_vendor = self._normalize_vendor(vendor)

            if normalized_vendor not in self.vendor_index:
                self.vendor_index[normalized_vendor] = []
            self.vendor_index[normalized_vendor].append(device)

            # Also index by original vendor for exact matches
            if vendor != normalized_vendor:
                if vendor not in self.vendor_index:
                    self.vendor_index[vendor] = []
                self.vendor_index[vendor].append(device)

            # Normalize and index by product
            normalized_product = self._normalize_product(product)

            if normalized_product not in self.product_index:
                self.product_index[normalized_product] = []
            self.product_index[normalized_product].append(device)

        logger.debug(f"Built device index: {len(self.vendor_index)} vendor entries, {len(self.product_index)} product entries")

    def _normalize_vendor(self, vendor: str) -> str:
        """Normalize vendor name using aliases."""
        vendor_lower = vendor.lower().strip()
        for normalized, aliases in self.VENDOR_ALIASES.items():
            if vendor_lower in aliases:
                return normalized
        return vendor_lower

    def _normalize_product(self, product: str) -> str:
        """Normalize product name using aliases."""
        product_lower = product.lower().strip()
        for normalized, aliases in self.PRODUCT_ALIASES.items():
            if product_lower in aliases or any(alias in product_lower for alias in aliases):
                return normalized
        return product_lower

    def match_cve_to_devices(self, cve_data: Dict) -> List[Tuple[Dict, float]]:
        """
        Match a CVE to devices using two-stage approach.
        Stage 1: Traditional matching with normalization
        Stage 2: AI verification for ambiguous matches (optional)

        Args:
            cve_data: CVE data dictionary with CPE info

        Returns:
            List[Tuple[Dict, float]]: List of (device, confidence_score) tuples
        """
        cve_id = cve_data.get('cve_id', 'Unknown')
        logger.info(f"[Stage 1] Traditional matching for {cve_id}")

        matches = []

        # Stage 1: Enhanced Traditional Matching
        # Extract CPE information from ALL possible sources
        cpe_list = self._extract_cpe_from_cve(cve_data)

        if not cpe_list:
            logger.debug(f"{cve_id}: No CPE found, trying description-based matching")
            # Try to match based on description
            matches.extend(self._match_by_description(cve_data))
        else:
            logger.debug(f"{cve_id}: Found {len(cpe_list)} CPE entries")
            # Match based on CPE with enhanced logic
            for cpe in cpe_list:
                logger.debug(f"{cve_id}: Matching CPE - vendor={cpe.get('vendor')}, product={cpe.get('product')}, version={cpe.get('version')}")
                device_matches = self._match_by_cpe(cpe, cve_data)
                matches.extend(device_matches)

        # Remove duplicates and keep highest confidence
        unique_matches = {}
        for device, confidence in matches:
            device_id = device['device_id']
            if device_id not in unique_matches or unique_matches[device_id][1] < confidence:
                unique_matches[device_id] = (device, confidence)

        stage1_matches = list(unique_matches.values())
        logger.info(f"{cve_id}: Stage 1 found {len(stage1_matches)} matches")

        # Stage 2: AI Verification for ambiguous matches (optional)
        if self.ai_verification_enabled and self.ai_analyzer and self.ai_query_count < self.ai_max_queries:
            verified_matches = []

            for device, confidence in stage1_matches:
                # Only verify ambiguous matches (confidence between min and max thresholds)
                if self.ai_confidence_min <= confidence <= self.ai_confidence_max:
                    logger.info(f"[Stage 2] Verifying ambiguous match {device['device_id']} (confidence={confidence:.2f})")
                    ai_verified_conf = self._verify_match_with_ai(cve_data, device, confidence)
                    verified_matches.append((device, ai_verified_conf))
                else:
                    # High or low confidence, no AI verification needed
                    verified_matches.append((device, confidence))

            stage1_matches = verified_matches

        # Sort by confidence
        sorted_matches = sorted(stage1_matches, key=lambda x: x[1], reverse=True)

        logger.info(f"{cve_id}: Final {len(sorted_matches)} matches after all stages")
        return sorted_matches

    def _extract_cpe_from_cve(self, cve_data: Dict) -> List[Dict]:
        """
        Extract CPE information from ALL possible sources in CVE data.

        CVE data comes from multiple collectors with different structures:
        - CISA KEV: metadata.vendor_project, metadata.product
        - NVD: metadata.cpe, metadata.vendor_advisory_urls
        - GitHub: metadata.vulnerabilities array
        - OpenCVE: metadata has full CVE JSON with configurations

        Args:
            cve_data: CVE data dictionary

        Returns:
            List[Dict]: List of CPE dictionaries with vendor, product, version
        """
        cpe_list = []
        metadata = cve_data.get('metadata', {})

        # Handle string metadata (JSON serialized)
        if isinstance(metadata, str):
            try:
                import json
                metadata = json.loads(metadata)
            except:
                metadata = {}

        # Source 1: Direct CPE strings (NVD format)
        if 'cpe' in metadata:
            cpe_strings = metadata['cpe']
            if not isinstance(cpe_strings, list):
                cpe_strings = [cpe_strings]

            for cpe_str in cpe_strings:
                if cpe_str:
                    cpe_info = self._parse_cpe_string(cpe_str)
                    if cpe_info:
                        logger.debug(f"Extracted CPE from NVD: {cpe_info}")
                        cpe_list.append(cpe_info)

        # Source 2: CISA KEV format (vendor_project + product fields)
        if 'vendor_project' in metadata or 'product' in metadata:
            cpe_info = {
                'vendor': metadata.get('vendor_project', '').lower(),
                'product': metadata.get('product', '').lower(),
                'version': metadata.get('version', '*')
            }
            if cpe_info['vendor'] or cpe_info['product']:
                logger.debug(f"Extracted CPE from CISA KEV: {cpe_info}")
                cpe_list.append(cpe_info)

        # Source 3: GitHub vulnerabilities array
        if 'vulnerabilities' in metadata:
            vulnerabilities = metadata['vulnerabilities']
            if isinstance(vulnerabilities, list):
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        package = vuln.get('package', {})
                        if isinstance(package, dict):
                            cpe_info = {
                                'vendor': package.get('ecosystem', '').lower(),
                                'product': package.get('name', '').lower(),
                                'version': '*'
                            }
                            if cpe_info['vendor'] or cpe_info['product']:
                                logger.debug(f"Extracted CPE from GitHub: {cpe_info}")
                                cpe_list.append(cpe_info)

        # Source 4: OpenCVE full CVE JSON with configurations
        if 'configurations' in metadata:
            configs = metadata.get('configurations', {})
            if isinstance(configs, dict):
                nodes = configs.get('nodes', [])
                for node in nodes:
                    if isinstance(node, dict):
                        cpe_matches = node.get('cpeMatch', [])
                        for cpe_match in cpe_matches:
                            if isinstance(cpe_match, dict):
                                cpe_str = cpe_match.get('criteria', '')
                                if cpe_str:
                                    cpe_info = self._parse_cpe_string(cpe_str)
                                    if cpe_info:
                                        logger.debug(f"Extracted CPE from OpenCVE: {cpe_info}")
                                        cpe_list.append(cpe_info)

        # Source 5: Affected products array (legacy format)
        if 'affected_products' in metadata:
            for product in metadata['affected_products']:
                cpe_list.append({
                    'vendor': product.get('vendor', '').lower(),
                    'product': product.get('product', '').lower(),
                    'version': product.get('version', '*')
                })

        # Source 6: Parse from description if no CPE found
        if not cpe_list:
            desc_cpe = self._extract_from_description(cve_data.get('description', ''))
            if desc_cpe:
                logger.debug(f"Extracted CPE from description: {desc_cpe}")
                cpe_list.extend(desc_cpe)

        return cpe_list

    def _extract_from_description(self, description: str) -> List[Dict]:
        """
        Extract vendor/product info from CVE description.
        Used as last resort when CPE is not available.

        Args:
            description: CVE description text

        Returns:
            List[Dict]: List of extracted CPE info
        """
        cpe_list = []
        desc_lower = description.lower()

        # Windows patterns
        windows_pattern = r'(microsoft\s+)?windows\s+(server\s+)?(\d{4}|10|11|[\d\.]+\w*)'
        matches = re.finditer(windows_pattern, desc_lower)
        for match in matches:
            version = match.group(3)
            cpe_list.append({
                'vendor': 'microsoft',
                'product': 'windows server' if 'server' in match.group(0) else 'windows',
                'version': version
            })

        # Cisco patterns
        cisco_pattern = r'cisco\s+([\w\-]+)\s+([\d\.]+)'
        matches = re.finditer(cisco_pattern, desc_lower)
        for match in matches:
            cpe_list.append({
                'vendor': 'cisco',
                'product': match.group(1),
                'version': match.group(2)
            })

        return cpe_list

    def _parse_cpe_string(self, cpe_str: str) -> Optional[Dict]:
        """
        Parse both CPE 2.2 and 2.3 formatted strings.

        CPE 2.2 format: cpe:/part:vendor:product:version:...
        CPE 2.3 format: cpe:2.3:part:vendor:product:version:...

        Args:
            cpe_str: CPE string

        Returns:
            Dict: Parsed CPE components with vendor, product, version
        """
        if not cpe_str or not cpe_str.startswith('cpe'):
            return None

        parts = cpe_str.split(':')

        # CPE 2.3 format (cpe:2.3:...)
        if len(parts) >= 6 and parts[1] == '2.3':
            return {
                'vendor': parts[3].replace('_', ' ') if len(parts) > 3 else '',
                'product': parts[4].replace('_', ' ') if len(parts) > 4 else '',
                'version': parts[5] if len(parts) > 5 and parts[5] != '*' else ''
            }

        # CPE 2.2 format (cpe:/...)
        elif len(parts) >= 4:
            return {
                'vendor': parts[2].replace('_', ' ') if len(parts) > 2 else '',
                'product': parts[3].replace('_', ' ') if len(parts) > 3 else '',
                'version': parts[4] if len(parts) > 4 and parts[4] != '*' else ''
            }

        return None

    def _match_by_cpe(self, cpe: Dict, cve_data: Dict) -> List[Tuple[Dict, float]]:
        """
        Enhanced CPE-based matching with normalization.

        Args:
            cpe: CPE dictionary with vendor, product, version
            cve_data: Full CVE data for context

        Returns:
            List[Tuple[Dict, float]]: List of (device, confidence) tuples
        """
        matches = []
        vendor = cpe.get('vendor', '').lower()
        product = cpe.get('product', '').lower()
        version = cpe.get('version', '').lower()

        # Normalize vendor and product
        normalized_vendor = self._normalize_vendor(vendor)
        normalized_product = self._normalize_product(product)

        # Look for vendor matches (try both normalized and original)
        candidate_devices = []
        seen_device_ids = set()

        if normalized_vendor in self.vendor_index:
            for device in self.vendor_index[normalized_vendor]:
                device_id = device.get('device_id')
                if device_id not in seen_device_ids:
                    candidate_devices.append(device)
                    seen_device_ids.add(device_id)

        if vendor != normalized_vendor and vendor in self.vendor_index:
            for device in self.vendor_index[vendor]:
                device_id = device.get('device_id')
                if device_id not in seen_device_ids:
                    candidate_devices.append(device)
                    seen_device_ids.add(device_id)

        logger.debug(f"Found {len(candidate_devices)} candidate devices for vendor={normalized_vendor}")

        for device in candidate_devices:
            confidence = self._calculate_match_confidence(
                device, normalized_vendor, normalized_product, version, cve_data
            )

            if confidence > 0.4:  # Lower threshold to catch more potential matches
                logger.debug(f"Match: {device['device_id']} - confidence={confidence:.2f}")
                matches.append((device, confidence))

        return matches

    def _calculate_match_confidence(self, device: Dict, vendor: str,
                                     product: str, version: str, cve_data: Dict) -> float:
        """
        Enhanced confidence calculation with normalization and detailed logic.

        Args:
            device: Device dictionary
            vendor: Normalized CVE vendor
            product: Normalized CVE product
            version: CVE version
            cve_data: Full CVE data for context

        Returns:
            float: Confidence score (0.0 - 1.0)
        """
        confidence = 0.0

        device_vendor = self._normalize_vendor(device.get('vendor', '').lower())
        device_product = self._normalize_product(device.get('product', '').lower())
        device_version = device.get('version', '').lower()

        # Vendor match (35% weight)
        if vendor and device_vendor:
            if vendor == device_vendor:
                confidence += 0.35
                logger.debug(f"Vendor exact match: {vendor}")
            elif vendor in device_vendor or device_vendor in vendor:
                confidence += 0.25
                logger.debug(f"Vendor partial match: {vendor} ~ {device_vendor}")
            elif self._vendors_are_aliases(vendor, device_vendor):
                confidence += 0.30
                logger.debug(f"Vendor alias match: {vendor} = {device_vendor}")

        # Product match (45% weight)
        if product and device_product:
            if product == device_product:
                confidence += 0.45
                logger.debug(f"Product exact match: {product}")
            elif product in device_product or device_product in product:
                confidence += 0.35
                logger.debug(f"Product partial match: {product} ~ {device_product}")
            elif self._fuzzy_match(product, device_product):
                confidence += 0.25
                logger.debug(f"Product fuzzy match: {product} ~ {device_product}")
            elif self._products_are_aliases(product, device_product):
                confidence += 0.40
                logger.debug(f"Product alias match: {product} = {device_product}")

        # Version match (20% weight) - Enhanced with Windows-specific logic
        if version and device_version and version not in ['*', '']:
            version_match, version_reason = self._version_matches(
                device_version, version, device_vendor, device_product
            )
            if version_match:
                confidence += 0.20
                logger.debug(f"Version match: {version_reason}")
            else:
                # Version mismatch reduces confidence slightly
                confidence -= 0.05
                logger.debug(f"Version mismatch: {device_version} != {version}")

        return min(confidence, 1.0)

    def _vendors_are_aliases(self, vendor1: str, vendor2: str) -> bool:
        """Check if two vendors are aliases of each other."""
        for normalized, aliases in self.VENDOR_ALIASES.items():
            if vendor1 in aliases and vendor2 in aliases:
                return True
        return False

    def _products_are_aliases(self, product1: str, product2: str) -> bool:
        """Check if two products are aliases of each other."""
        for normalized, aliases in self.PRODUCT_ALIASES.items():
            if product1 in aliases and product2 in aliases:
                return True
        return False

    def _version_matches(self, device_version: str, cve_version: str,
                        vendor: str, product: str) -> Tuple[bool, str]:
        """
        Enhanced version matching with Windows-specific logic.

        Args:
            device_version: Device version
            cve_version: CVE version
            vendor: Vendor name (for context)
            product: Product name (for context)

        Returns:
            Tuple of (matches: bool, reason: str)
        """
        device_ver = device_version.lower().strip()
        cve_ver = cve_version.lower().strip()

        # Windows-specific version matching
        if vendor == 'microsoft' and 'windows' in product:
            return self._windows_version_matches(device_ver, cve_ver)

        # Handle version ranges
        if any(op in cve_ver for op in ['<', '>', '=', '-']):
            return True, f"range({cve_ver})"

        # Exact match
        if device_ver == cve_ver:
            return True, f"exact({device_ver})"

        # Version prefix match (e.g., 7.4 matches 7.4.1)
        if device_ver.startswith(cve_ver) or cve_ver.startswith(device_ver):
            return True, f"prefix({device_ver}~{cve_ver})"

        # Numeric version comparison
        try:
            device_parts = [int(x) for x in re.findall(r'\d+', device_ver)]
            cve_parts = [int(x) for x in re.findall(r'\d+', cve_ver)]

            if device_parts and cve_parts:
                # Major version must match
                if device_parts[0] == cve_parts[0]:
                    return True, f"major_match({device_parts[0]})"
        except:
            pass

        return False, f"mismatch({device_ver}!={cve_ver})"

    def _windows_version_matches(self, device_version: str, cve_version: str) -> Tuple[bool, str]:
        """
        Windows-specific version matching.
        Handles: Server 2019, Server 2022, 10, 11, 21H2, 20H2, etc.

        Args:
            device_version: Device Windows version
            cve_version: CVE Windows version

        Returns:
            Tuple of (matches: bool, reason: str)
        """
        device_ver = device_version.lower()
        cve_ver = cve_version.lower()

        # Exact match
        if device_ver == cve_ver:
            return True, f"exact({device_ver})"

        # Check Windows version aliases
        for version_key, aliases in self.WINDOWS_VERSIONS.items():
            device_in_aliases = any(alias in device_ver for alias in aliases)
            cve_in_aliases = any(alias in cve_ver for alias in aliases)

            if device_in_aliases and cve_in_aliases:
                return True, f"windows_alias({device_ver}={cve_ver})"

        # Version number comparison
        device_nums = re.findall(r'\d+', device_ver)
        cve_nums = re.findall(r'\d+', cve_ver)

        if device_nums and cve_nums:
            # Check if major versions overlap
            if device_nums[0] == cve_nums[0]:
                return True, f"windows_major({device_nums[0]})"

        return False, f"mismatch({device_ver}!={cve_ver})"

    def _fuzzy_match(self, str1: str, str2: str) -> bool:
        """Perform fuzzy string matching."""
        clean1 = re.sub(r'[-_\s]', '', str1.lower())
        clean2 = re.sub(r'[-_\s]', '', str2.lower())
        return clean1 in clean2 or clean2 in clean1

    def _match_by_description(self, cve_data: Dict) -> List[Tuple[Dict, float]]:
        """
        Enhanced description-based matching with normalization.
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

            normalized_vendor = self._normalize_vendor(vendor)
            normalized_product = self._normalize_product(product)

            confidence = 0.0

            # Check vendor in description
            if vendor and vendor in description:
                confidence += 0.25
            elif normalized_vendor != vendor and normalized_vendor in description:
                confidence += 0.25

            # Check product in description
            if product and product in description:
                confidence += 0.35
            elif normalized_product != product and normalized_product in description:
                confidence += 0.35

            # Check device type keywords (expanded)
            device_type = device.get('device_type', '').lower()
            type_keywords = {
                'firewall': ['firewall', 'fw', 'security gateway'],
                'router': ['router', 'routing'],
                'switch': ['switch', 'switching'],
                'database': ['database', 'db', 'sql', 'mysql', 'postgresql', 'oracle'],
                'webapp': ['web server', 'apache', 'nginx', 'iis', 'http server'],
                'server': ['server', 'windows server', 'linux server'],
            }

            if device_type in type_keywords:
                if any(kw in description for kw in type_keywords[device_type]):
                    confidence += 0.15

            if confidence > 0.4:  # Lower threshold
                matches.append((device, confidence))

        return matches

    def _verify_match_with_ai(self, cve_data: Dict, device: Dict, current_confidence: float) -> float:
        """
        Stage 2: AI verification for ambiguous matches.
        SECURITY: Only sends anonymized generic vendor/product/version to AI.
        NEVER sends device IDs, hostnames, IPs, locations, or infrastructure details.

        Args:
            cve_data: CVE data
            device: Device dictionary
            current_confidence: Current confidence from Stage 1

        Returns:
            float: Adjusted confidence score
        """
        if not self.ai_analyzer or not self.ai_analyzer.enabled:
            return current_confidence

        # Check query limit
        if self.ai_query_count >= self.ai_max_queries:
            logger.warning(f"AI verification query limit reached ({self.ai_max_queries})")
            return current_confidence

        # Anonymize device for AI query (SECURITY CRITICAL)
        anonymized_device = {
            'vendor': device.get('vendor', ''),
            'product': device.get('product', ''),
            'version': device.get('version', ''),
            # NO device_id, NO hostname, NO IP, NO location, NO criticality
        }

        # Check cache
        cache_key = f"{cve_data['cve_id']}_{anonymized_device['vendor']}_{anonymized_device['product']}_{anonymized_device['version']}"
        if self.ai_cache_enabled and cache_key in self.ai_cache:
            logger.debug(f"AI verification cache hit for {cache_key}")
            return self.ai_cache[cache_key]

        # Increment query count
        self.ai_query_count += 1

        try:
            # Create secure prompt
            description = cve_data.get('description', '')[:500]
            prompt = f"""You are a cybersecurity expert analyzing CVE applicability.

CVE: {cve_data.get('cve_id', 'Unknown')}
Severity: {cve_data.get('severity', 'Unknown')} (CVSS {cve_data.get('cvss_score', 0)})
Description: {description}

Question: Does this CVE affect a system with:
- Vendor: {anonymized_device['vendor']}
- Product: {anonymized_device['product']}
- Version: {anonymized_device['version']}

Consider:
1. Does the vendor/product match the affected products?
2. Does the version fall within the affected range?
3. Are there product variations or aliases that match?

Answer with one word: YES, NO, or MAYBE
Then provide brief reasoning (1-2 sentences max).

Format:
Answer: [YES/NO/MAYBE]
Reasoning: [Your reasoning]

Do not ask for additional information."""

            logger.info(f"AI verification query #{self.ai_query_count}: {cve_data['cve_id']} vs {anonymized_device['vendor']} {anonymized_device['product']}")

            # Call AI provider
            response = self._call_ai_for_verification(prompt)

            # Parse response
            adjusted_confidence = self._parse_ai_verification_response(response, current_confidence)

            # Cache result
            if self.ai_cache_enabled:
                self.ai_cache[cache_key] = adjusted_confidence

            logger.info(f"AI verification: {current_confidence:.2f} → {adjusted_confidence:.2f}")

            return adjusted_confidence

        except Exception as e:
            logger.error(f"AI verification failed: {e}")
            return current_confidence

    def _call_ai_for_verification(self, prompt: str) -> str:
        """Call AI provider for verification."""
        try:
            provider = self.ai_analyzer.provider

            if provider == 'anthropic':
                response = self.ai_analyzer.client.messages.create(
                    model=self.ai_analyzer.model,
                    max_tokens=300,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text

            elif provider == 'openai':
                response = self.ai_analyzer.client.chat.completions.create(
                    model=self.ai_analyzer.model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert analyzing CVE applicability. Be concise and factual."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=300,
                    temperature=0.1
                )
                return response.choices[0].message.content

            elif provider == 'google':
                response = self.ai_analyzer.client.generate_content(prompt)
                return response.text

            elif provider == 'ollama':
                payload = {
                    "model": self.ai_analyzer.model,
                    "prompt": prompt,
                    "stream": False
                }
                response = self.ai_analyzer.client.post(
                    f"{self.ai_analyzer.base_url}/api/generate",
                    json=payload,
                    timeout=30
                )
                response.raise_for_status()
                return response.json().get('response', '')

            else:
                return "MAYBE\nReasoning: Unknown AI provider"

        except Exception as e:
            logger.error(f"AI API call failed: {e}")
            return "MAYBE\nReasoning: AI call failed"

    def _parse_ai_verification_response(self, response: str, current_confidence: float) -> float:
        """Parse AI response and adjust confidence."""
        response_lower = response.lower()

        if 'answer: yes' in response_lower or response_lower.strip().startswith('yes'):
            # AI confirms match - boost confidence
            return min(current_confidence + 0.25, 1.0)

        elif 'answer: no' in response_lower or response_lower.strip().startswith('no'):
            # AI rejects match - reduce confidence
            return max(current_confidence - 0.20, 0.0)

        elif 'answer: maybe' in response_lower or response_lower.strip().startswith('maybe'):
            # AI is uncertain - small boost
            return min(current_confidence + 0.10, 1.0)

        else:
            # Can't parse response - no change
            logger.warning(f"Could not parse AI response: {response[:100]}")
            return current_confidence

    def reset_ai_query_count(self):
        """Reset AI query counter for new scan."""
        self.ai_query_count = 0
        logger.debug("AI query counter reset")

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
