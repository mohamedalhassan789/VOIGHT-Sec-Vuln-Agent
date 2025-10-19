"""
Risk Scorer for Vulnerabilities
Calculates risk scores based on multiple factors
"""

import logging
from typing import Dict, List, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Calculates comprehensive risk scores for vulnerabilities.
    Considers CVSS, exploitability, asset criticality, and other factors.
    """

    def __init__(self, config: Dict = None):
        """
        Initialize risk scorer.

        Args:
            config: Scoring configuration (optional)
        """
        self.config = config or {}
        self.weights = self.config.get('weights', {
            'cvss': 0.35,
            'exploitability': 0.25,
            'asset_criticality': 0.20,
            'kev_status': 0.15,
            'age': 0.05
        })

    def calculate_risk_score(self, cve_data: Dict, matched_devices: List[Tuple[Dict, float]] = None) -> Dict:
        """
        Calculate comprehensive risk score for a CVE.

        Args:
            cve_data: CVE data dictionary
            matched_devices: List of (device, confidence) tuples

        Returns:
            Dict: Risk scoring results
        """
        scores = {}

        # CVSS-based score
        scores['cvss_score'] = self._score_cvss(cve_data.get('cvss_score', 0))

        # Exploitability score
        scores['exploit_score'] = self._score_exploitability(cve_data)

        # Asset criticality score
        scores['asset_score'] = self._score_asset_criticality(matched_devices)

        # KEV status score
        scores['kev_score'] = self._score_kev_status(cve_data)

        # Age/recency score
        scores['age_score'] = self._score_age(cve_data)

        # Calculate weighted total
        total_score = sum(
            scores[f'{key}_score'] * self.weights[key]
            for key in ['cvss', 'exploitability', 'asset_criticality', 'kev_status', 'age']
            if f'{key}_score' in scores
        )

        # Determine priority level
        priority = self._determine_priority(total_score, cve_data, matched_devices)

        return {
            'total_score': round(total_score, 2),
            'component_scores': scores,
            'priority': priority,
            'severity': self._score_to_severity(total_score),
            'immediate_action_required': self._requires_immediate_action(cve_data, total_score)
        }

    def _score_cvss(self, cvss_score: float) -> float:
        """
        Score based on CVSS value.

        Args:
            cvss_score: CVSS score (0-10)

        Returns:
            float: Normalized score (0-100)
        """
        if cvss_score >= 9.0:
            return 100
        elif cvss_score >= 7.0:
            return 75
        elif cvss_score >= 4.0:
            return 50
        elif cvss_score > 0:
            return 25
        return 0

    def _score_exploitability(self, cve_data: Dict) -> float:
        """
        Score based on exploit availability and CISA KEV status.

        Args:
            cve_data: CVE data dictionary

        Returns:
            float: Exploitability score (0-100)
        """
        score = 0

        # Check if exploit is available
        if cve_data.get('exploit_available', False):
            score += 60

        # Check CISA KEV (Known Exploited Vulnerabilities)
        if cve_data.get('in_cisa_kev', False):
            score += 40

        # Check for weaponization keywords in description
        description = cve_data.get('description', '').lower()
        weaponization_keywords = [
            'exploit', 'weaponized', 'actively exploited',
            'in the wild', 'proof of concept', 'poc'
        ]

        if any(keyword in description for keyword in weaponization_keywords):
            score = min(score + 20, 100)

        return min(score, 100)

    def _score_asset_criticality(self, matched_devices: List[Tuple[Dict, float]]) -> float:
        """
        Score based on criticality of matched assets.

        Args:
            matched_devices: List of (device, confidence) tuples

        Returns:
            float: Asset criticality score (0-100)
        """
        if not matched_devices:
            return 0

        max_criticality = 0
        criticality_map = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }

        for device, confidence in matched_devices:
            criticality = device.get('criticality', 'low').lower()
            score = criticality_map.get(criticality, 25)

            # Weight by match confidence
            weighted_score = score * confidence

            max_criticality = max(max_criticality, weighted_score)

        return max_criticality

    def _score_kev_status(self, cve_data: Dict) -> float:
        """
        Score based on CISA KEV catalog inclusion.

        Args:
            cve_data: CVE data dictionary

        Returns:
            float: KEV status score (0-100)
        """
        return 100 if cve_data.get('in_cisa_kev', False) else 0

    def _score_age(self, cve_data: Dict) -> float:
        """
        Score based on vulnerability age (newer = higher score).

        Args:
            cve_data: CVE data dictionary

        Returns:
            float: Age score (0-100)
        """
        # Try to extract publication date
        first_seen = cve_data.get('first_seen')
        if not first_seen:
            metadata = cve_data.get('metadata', {})
            if isinstance(metadata, dict):
                first_seen = metadata.get('published_date')

        if not first_seen:
            return 50  # Default to middle score if unknown

        try:
            if isinstance(first_seen, str):
                pub_date = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            else:
                pub_date = first_seen

            days_old = (datetime.now() - pub_date.replace(tzinfo=None)).days

            # Score higher for newer vulnerabilities
            if days_old <= 7:
                return 100  # Last week
            elif days_old <= 30:
                return 80   # Last month
            elif days_old <= 90:
                return 60   # Last quarter
            elif days_old <= 180:
                return 40   # Last 6 months
            else:
                return 20   # Older

        except (ValueError, AttributeError, TypeError):
            return 50  # Default

    def _determine_priority(self, total_score: float, cve_data: Dict,
                            matched_devices: List[Tuple[Dict, float]]) -> str:
        """
        Determine priority level.

        Args:
            total_score: Calculated total risk score
            cve_data: CVE data
            matched_devices: Matched devices

        Returns:
            str: Priority level (P0-P3)
        """
        # P0: Critical - Immediate action
        if (cve_data.get('in_cisa_kev') and matched_devices) or total_score >= 90:
            return 'P0'

        # P1: High - Action required within 24h
        if total_score >= 75 or (cve_data.get('exploit_available') and matched_devices):
            return 'P1'

        # P2: Medium - Action required within 7 days
        if total_score >= 50:
            return 'P2'

        # P3: Low - Action required within 30 days
        return 'P3'

    def _score_to_severity(self, score: float) -> str:
        """
        Convert score to severity label.

        Args:
            score: Risk score

        Returns:
            str: Severity label
        """
        if score >= 90:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _requires_immediate_action(self, cve_data: Dict, total_score: float) -> bool:
        """
        Determine if immediate action is required.

        Args:
            cve_data: CVE data
            total_score: Total risk score

        Returns:
            bool: True if immediate action required
        """
        # Immediate action if:
        # 1. In CISA KEV catalog
        # 2. CVSS >= 9.0 with exploit available
        # 3. Total risk score >= 85

        if cve_data.get('in_cisa_kev'):
            return True

        if cve_data.get('cvss_score', 0) >= 9.0 and cve_data.get('exploit_available'):
            return True

        if total_score >= 85:
            return True

        return False

    def prioritize_cves(self, cve_list: List[Dict], matched_devices_map: Dict = None) -> List[Dict]:
        """
        Prioritize a list of CVEs by risk score.

        Args:
            cve_list: List of CVE dictionaries
            matched_devices_map: Dict mapping cve_id to matched devices

        Returns:
            List[Dict]: Sorted list with risk scores
        """
        matched_devices_map = matched_devices_map or {}

        scored_cves = []
        for cve in cve_list:
            cve_id = cve.get('cve_id')
            matched_devices = matched_devices_map.get(cve_id, [])

            risk_info = self.calculate_risk_score(cve, matched_devices)

            # Add risk info to CVE
            cve_with_risk = cve.copy()
            cve_with_risk['risk_score'] = risk_info['total_score']
            cve_with_risk['priority'] = risk_info['priority']
            cve_with_risk['severity'] = risk_info['severity']
            cve_with_risk['immediate_action'] = risk_info['immediate_action_required']

            scored_cves.append(cve_with_risk)

        # Sort by priority (P0 first) then by risk score
        priority_order = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3}

        sorted_cves = sorted(
            scored_cves,
            key=lambda x: (
                priority_order.get(x['priority'], 4),
                -x['risk_score']
            )
        )

        return sorted_cves


# Example usage
if __name__ == "__main__":
    from utils.logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    scorer = RiskScorer()

    # Test CVE
    cve = {
        'cve_id': 'CVE-2024-1234',
        'cvss_score': 9.8,
        'severity': 'CRITICAL',
        'description': 'Remote code execution with exploit available',
        'exploit_available': True,
        'in_cisa_kev': True,
        'first_seen': datetime.now().isoformat()
    }

    # Test matched devices
    matched_devices = [
        (
            {
                'device_id': 'FW-001',
                'criticality': 'critical'
            },
            0.95  # High confidence match
        )
    ]

    result = scorer.calculate_risk_score(cve, matched_devices)

    print("\nRisk Scoring Result:")
    print(f"Total Score: {result['total_score']}")
    print(f"Priority: {result['priority']}")
    print(f"Severity: {result['severity']}")
    print(f"Immediate Action: {result['immediate_action_required']}")
    print("\nComponent Scores:")
    for key, value in result['component_scores'].items():
        print(f"  {key}: {value}")
