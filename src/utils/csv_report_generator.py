"""
CSV Report Generator
Generates CSV reports of vulnerability scans with automatic cleanup
"""

import csv
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict

logger = logging.getLogger(__name__)


class CSVReportGenerator:
    """
    Generates CSV reports of vulnerability scans.
    Includes automatic cleanup of old reports.
    """

    def __init__(self, reports_dir: Path = None, retention_days: int = 30):
        """
        Initialize CSV report generator.

        Args:
            reports_dir: Directory to store reports (default: ./reports)
            retention_days: Number of days to keep reports (default: 30)
        """
        self.reports_dir = reports_dir or Path.cwd() / 'reports'
        self.retention_days = retention_days

        # Create reports directory if it doesn't exist
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"CSV reports directory: {self.reports_dir}")

    def generate_report(self, cves: List[Dict], scan_time: datetime = None) -> str:
        """
        Generate a CSV report of vulnerabilities.

        Args:
            cves: List of CVE dictionaries
            scan_time: Scan timestamp (default: now)

        Returns:
            str: Path to generated CSV file
        """
        if not cves:
            logger.warning("No CVEs to export to CSV")
            return None

        scan_time = scan_time or datetime.now()
        timestamp = scan_time.strftime('%Y%m%d_%H%M%S')
        filename = f'vulnerability_scan_{timestamp}.csv'
        filepath = self.reports_dir / filename

        try:
            # Define CSV columns
            fieldnames = [
                'CVE-ID',
                'CVSS Score',
                'Severity',
                'Description',
                'Affected Devices',
                'Source',
                'Exploit Available',
                'CISA KEV',
                'Published Date',
                'Priority',
                'Risk Score',
                'Matched Devices Count',
                'Reference Links'
            ]

            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for cve in cves:
                    # Get matched devices
                    matched_devices = cve.get('matched_devices', [])
                    device_list = []
                    for device, confidence in matched_devices:
                        device_id = device.get('device_id', 'Unknown')
                        device_type = device.get('type', 'Unknown')
                        vendor = device.get('vendor', 'Unknown')
                        product = device.get('product', 'Unknown')
                        version = device.get('version', 'Unknown')
                        device_list.append(f"{device_id} ({vendor} {product} {version})")

                    affected_devices_str = '; '.join(device_list) if device_list else 'None'

                    # Calculate severity from CVSS if not present (handle None)
                    cvss_score = cve.get('cvss_score')
                    if cvss_score is None:
                        cvss_score = 0.0
                    severity = cve.get('severity', self._get_severity_from_cvss(cvss_score))

                    # Get published date
                    published_date = cve.get('published_date', cve.get('metadata', {}).get('published_date', 'N/A'))
                    if isinstance(published_date, datetime):
                        published_date = published_date.strftime('%Y-%m-%d')

                    # Build reference links
                    cve_id = cve.get('cve_id', 'Unknown')
                    references = []
                    if cve_id and cve_id != 'Unknown':
                        references.append(f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}")
                        references.append(f"MITRE: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
                    reference_str = '; '.join(references) if references else 'N/A'

                    # Write row
                    writer.writerow({
                        'CVE-ID': cve_id,
                        'CVSS Score': f"{cvss_score:.1f}",
                        'Severity': severity,
                        'Description': cve.get('description', 'No description')[:500],  # Limit length
                        'Affected Devices': affected_devices_str,
                        'Source': cve.get('source', 'Unknown'),
                        'Exploit Available': 'Yes' if cve.get('exploit_available', False) else 'No',
                        'CISA KEV': 'Yes' if cve.get('in_cisa_kev', False) else 'No',
                        'Published Date': published_date,
                        'Priority': cve.get('priority', 'N/A'),
                        'Risk Score': f"{cve.get('risk_score', 0):.1f}",
                        'Matched Devices Count': len(matched_devices),
                        'Reference Links': reference_str
                    })

            logger.info(f"Generated CSV report: {filepath} ({len(cves)} CVEs)")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return None

    def cleanup_old_reports(self):
        """
        Remove CSV reports older than retention period.
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            deleted_count = 0

            for csv_file in self.reports_dir.glob('vulnerability_scan_*.csv'):
                try:
                    # Get file modification time
                    file_mtime = datetime.fromtimestamp(csv_file.stat().st_mtime)

                    if file_mtime < cutoff_date:
                        csv_file.unlink()
                        deleted_count += 1
                        logger.debug(f"Deleted old report: {csv_file.name}")

                except Exception as e:
                    logger.warning(f"Failed to delete {csv_file.name}: {e}")
                    continue

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old CSV reports (older than {self.retention_days} days)")

        except Exception as e:
            logger.error(f"Failed to cleanup old reports: {e}")

    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """
        Determine severity level from CVSS score.

        Args:
            cvss_score: CVSS score (0.0-10.0) or None

        Returns:
            str: Severity level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
        """
        # Handle None values
        if cvss_score is None:
            return 'NONE'

        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'NONE'

    def get_latest_report(self) -> str:
        """
        Get path to the most recent CSV report.

        Returns:
            str: Path to latest report, or None if no reports exist
        """
        try:
            reports = sorted(
                self.reports_dir.glob('vulnerability_scan_*.csv'),
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )

            if reports:
                return str(reports[0])

            return None

        except Exception as e:
            logger.error(f"Failed to get latest report: {e}")
            return None

    def get_report_count(self) -> int:
        """
        Get count of existing reports.

        Returns:
            int: Number of CSV reports
        """
        try:
            return len(list(self.reports_dir.glob('vulnerability_scan_*.csv')))
        except Exception as e:
            logger.error(f"Failed to count reports: {e}")
            return 0


# Example usage
if __name__ == "__main__":
    from utils.logger import setup_logger
    logger = setup_logger(log_level="DEBUG")

    # Create generator
    generator = CSVReportGenerator()

    # Example CVE data
    test_cves = [
        {
            'cve_id': 'CVE-2024-1234',
            'cvss_score': 9.8,
            'severity': 'CRITICAL',
            'description': 'Remote code execution vulnerability in example software',
            'source': 'NVD',
            'exploit_available': True,
            'in_cisa_kev': True,
            'published_date': '2024-01-15',
            'priority': 'P0',
            'risk_score': 95.0,
            'matched_devices': [
                ({'device_id': 'WEB-01', 'type': 'Server', 'vendor': 'Apache', 'product': 'HTTP Server', 'version': '2.4.48'}, 0.9),
                ({'device_id': 'WEB-02', 'type': 'Server', 'vendor': 'Apache', 'product': 'HTTP Server', 'version': '2.4.48'}, 0.9)
            ]
        },
        {
            'cve_id': 'CVE-2024-5678',
            'cvss_score': 7.5,
            'severity': 'HIGH',
            'description': 'SQL injection vulnerability in database interface',
            'source': 'GitHub Advisories',
            'exploit_available': False,
            'in_cisa_kev': False,
            'published_date': '2024-02-20',
            'priority': 'P1',
            'risk_score': 72.0,
            'matched_devices': []
        }
    ]

    # Generate report
    report_path = generator.generate_report(test_cves)
    print(f"\nGenerated report: {report_path}")

    # Show report count
    print(f"Total reports: {generator.get_report_count()}")

    # Cleanup old reports
    generator.cleanup_old_reports()
