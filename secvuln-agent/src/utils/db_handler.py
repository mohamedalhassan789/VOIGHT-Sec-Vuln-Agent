"""
Database Handler for SecVuln Agent
Manages SQLite database for deduplication and tracking
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
import logging

logger = logging.getLogger(__name__)


class DatabaseHandler:
    """
    Handles SQLite database operations for CVE tracking and deduplication.
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the database handler.

        Args:
            db_path: Path to SQLite database file
        """
        # Default database location
        if db_path is None:
            data_dir = Path(__file__).parent.parent.parent / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "secvuln.db"

        self.db_path = db_path
        self.conn = None
        self._initialize_database()

    def _initialize_database(self):
        """Create database tables if they don't exist."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row  # Enable column access by name

        cursor = self.conn.cursor()

        # CVE tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_tracking (
                cve_id TEXT PRIMARY KEY,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                source TEXT,
                exploit_available INTEGER DEFAULT 0,
                in_cisa_kev INTEGER DEFAULT 0,
                notified INTEGER DEFAULT 0,
                notification_count INTEGER DEFAULT 0,
                last_notified TIMESTAMP,
                metadata TEXT
            )
        ''')

        # Notification history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                channel TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT,
                message TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve_tracking(cve_id)
            )
        ''')

        # Source fetch tracking (for incremental updates)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS source_tracking (
                source_name TEXT PRIMARY KEY,
                last_fetch TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_successful_fetch TIMESTAMP,
                fetch_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0,
                last_error TEXT
            )
        ''')

        # Device matching table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                match_confidence REAL,
                matched_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES cve_tracking(cve_id)
            )
        ''')

        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_tracking(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_notified ON cve_tracking(notified)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_last_seen ON cve_tracking(last_seen)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_cve ON device_matches(cve_id)')

        self.conn.commit()
        logger.info(f"Database initialized at {self.db_path}")

    def record_cve(self, cve_id: str, cvss_score: float, severity: str,
                   description: str, source: str, exploit_available: bool = False,
                   in_cisa_kev: bool = False, metadata: Optional[Dict] = None) -> bool:
        """
        Record or update a CVE in the database.

        Args:
            cve_id: CVE identifier
            cvss_score: CVSS score
            severity: Severity level
            description: CVE description
            source: Data source
            exploit_available: Whether exploit is available
            in_cisa_kev: Whether in CISA KEV catalog
            metadata: Additional metadata as dictionary

        Returns:
            bool: True if new CVE, False if updated existing
        """
        cursor = self.conn.cursor()

        # Check if CVE exists
        cursor.execute('SELECT cve_id FROM cve_tracking WHERE cve_id = ?', (cve_id,))
        existing = cursor.fetchone()

        metadata_json = json.dumps(metadata) if metadata else None

        if existing:
            # Update existing record
            cursor.execute('''
                UPDATE cve_tracking
                SET last_seen = CURRENT_TIMESTAMP,
                    cvss_score = ?,
                    severity = ?,
                    description = ?,
                    source = ?,
                    exploit_available = ?,
                    in_cisa_kev = ?,
                    metadata = ?
                WHERE cve_id = ?
            ''', (cvss_score, severity, description, source,
                  int(exploit_available), int(in_cisa_kev), metadata_json, cve_id))

            self.conn.commit()
            logger.debug(f"Updated existing CVE: {cve_id}")
            return False
        else:
            # Insert new record
            cursor.execute('''
                INSERT INTO cve_tracking
                (cve_id, cvss_score, severity, description, source,
                 exploit_available, in_cisa_kev, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (cve_id, cvss_score, severity, description, source,
                  int(exploit_available), int(in_cisa_kev), metadata_json))

            self.conn.commit()
            logger.info(f"Recorded new CVE: {cve_id}")
            return True

    def is_cve_notified(self, cve_id: str) -> bool:
        """
        Check if a CVE has already been notified.

        Args:
            cve_id: CVE identifier

        Returns:
            bool: True if already notified
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT notified FROM cve_tracking WHERE cve_id = ?', (cve_id,))
        result = cursor.fetchone()

        if result:
            return bool(result['notified'])
        return False

    def mark_cve_notified(self, cve_id: str, channel: str, status: str = 'sent', message: str = ''):
        """
        Mark a CVE as notified and record notification history.

        Args:
            cve_id: CVE identifier
            channel: Notification channel (slack, teams, etc.)
            status: Notification status
            message: Additional message
        """
        cursor = self.conn.cursor()

        # Update CVE tracking
        cursor.execute('''
            UPDATE cve_tracking
            SET notified = 1,
                notification_count = notification_count + 1,
                last_notified = CURRENT_TIMESTAMP
            WHERE cve_id = ?
        ''', (cve_id,))

        # Record in notification history
        cursor.execute('''
            INSERT INTO notification_history (cve_id, channel, status, message)
            VALUES (?, ?, ?, ?)
        ''', (cve_id, channel, status, message))

        self.conn.commit()
        logger.debug(f"Marked CVE {cve_id} as notified via {channel}")

    def get_unnotified_cves(self, min_cvss: float = 0.0, severity: Optional[List[str]] = None,
                             limit: Optional[int] = None) -> List[Dict]:
        """
        Get CVEs that haven't been notified yet.

        Args:
            min_cvss: Minimum CVSS score
            severity: List of severity levels to filter
            limit: Maximum number of results

        Returns:
            List[Dict]: List of CVE records
        """
        cursor = self.conn.cursor()

        query = '''
            SELECT * FROM cve_tracking
            WHERE notified = 0 AND cvss_score >= ?
        '''
        params = [min_cvss]

        if severity:
            placeholders = ','.join('?' * len(severity))
            query += f' AND severity IN ({placeholders})'
            params.extend(severity)

        query += ' ORDER BY cvss_score DESC, in_cisa_kev DESC, exploit_available DESC'

        if limit:
            query += ' LIMIT ?'
            params.append(limit)

        cursor.execute(query, params)
        results = cursor.fetchall()

        return [dict(row) for row in results]

    def update_source_tracking(self, source_name: str, success: bool = True, error: str = None):
        """
        Update source fetch tracking.

        Args:
            source_name: Name of the data source
            success: Whether fetch was successful
            error: Error message if failed
        """
        cursor = self.conn.cursor()

        # Check if source exists
        cursor.execute('SELECT source_name FROM source_tracking WHERE source_name = ?', (source_name,))
        existing = cursor.fetchone()

        if existing:
            if success:
                cursor.execute('''
                    UPDATE source_tracking
                    SET last_fetch = CURRENT_TIMESTAMP,
                        last_successful_fetch = CURRENT_TIMESTAMP,
                        fetch_count = fetch_count + 1,
                        last_error = NULL
                    WHERE source_name = ?
                ''', (source_name,))
            else:
                cursor.execute('''
                    UPDATE source_tracking
                    SET last_fetch = CURRENT_TIMESTAMP,
                        error_count = error_count + 1,
                        last_error = ?
                    WHERE source_name = ?
                ''', (error, source_name))
        else:
            # Insert new source tracking
            cursor.execute('''
                INSERT INTO source_tracking
                (source_name, fetch_count, error_count, last_error, last_successful_fetch)
                VALUES (?, ?, ?, ?, ?)
            ''', (source_name, 1 if success else 0, 0 if success else 1,
                  None if success else error,
                  datetime.now() if success else None))

        self.conn.commit()

    def get_last_fetch_time(self, source_name: str) -> Optional[datetime]:
        """
        Get the last successful fetch time for a source.

        Args:
            source_name: Name of the data source

        Returns:
            datetime: Last fetch time or None
        """
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT last_successful_fetch FROM source_tracking WHERE source_name = ?',
            (source_name,)
        )
        result = cursor.fetchone()

        if result and result['last_successful_fetch']:
            return datetime.fromisoformat(result['last_successful_fetch'])
        return None

    def record_device_match(self, cve_id: str, device_id: str, confidence: float = 1.0):
        """
        Record a CVE-to-device match.

        Args:
            cve_id: CVE identifier
            device_id: Device identifier
            confidence: Match confidence score (0.0-1.0)
        """
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO device_matches (cve_id, device_id, match_confidence)
            VALUES (?, ?, ?)
        ''', (cve_id, device_id, confidence))

        self.conn.commit()
        logger.debug(f"Recorded match: {cve_id} -> {device_id} (confidence: {confidence})")

    def get_cve_statistics(self) -> Dict:
        """
        Get database statistics.

        Returns:
            Dict: Statistics about CVEs in database
        """
        cursor = self.conn.cursor()

        stats = {}

        # Total CVEs
        cursor.execute('SELECT COUNT(*) as count FROM cve_tracking')
        stats['total_cves'] = cursor.fetchone()['count']

        # Unnotified CVEs
        cursor.execute('SELECT COUNT(*) as count FROM cve_tracking WHERE notified = 0')
        stats['unnotified_cves'] = cursor.fetchone()['count']

        # By severity
        cursor.execute('SELECT severity, COUNT(*) as count FROM cve_tracking GROUP BY severity')
        stats['by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}

        # CISA KEV
        cursor.execute('SELECT COUNT(*) as count FROM cve_tracking WHERE in_cisa_kev = 1')
        stats['cisa_kev_count'] = cursor.fetchone()['count']

        # CVEs added in last 24h
        cursor.execute('''
            SELECT COUNT(*) as count FROM cve_tracking
            WHERE first_seen >= datetime('now', '-1 day')
        ''')
        stats['new_last_24h'] = cursor.fetchone()['count']

        return stats

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.debug("Database connection closed")


# Context manager support
class DatabaseContext:
    """Context manager for database operations."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path
        self.handler = None

    def __enter__(self) -> DatabaseHandler:
        self.handler = DatabaseHandler(self.db_path)
        return self.handler

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.handler:
            self.handler.close()


# Example usage
if __name__ == "__main__":
    from logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    with DatabaseContext() as db:
        # Record a test CVE
        db.record_cve(
            cve_id="CVE-2024-12345",
            cvss_score=9.8,
            severity="CRITICAL",
            description="Test vulnerability",
            source="test",
            in_cisa_kev=True
        )

        # Get statistics
        stats = db.get_cve_statistics()
        print("\nDatabase Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
