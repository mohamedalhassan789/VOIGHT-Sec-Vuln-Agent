# Contributing to SecVuln-Agent

Thank you for your interest in contributing to SecVuln-Agent! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Adding New Data Source Collectors](#adding-new-data-source-collectors)
- [Adding New Notification Channels](#adding-new-notification-channels)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, background, or identity.

### Expected Behavior

- Be respectful and considerate
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Accept responsibility for mistakes
- Prioritize security and user safety

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Malicious code or security vulnerabilities
- Other conduct inappropriate for a professional setting

## Ways to Contribute

### 🐛 Report Bugs

Found a bug? Help us fix it!

**Before reporting:**
- Check existing issues to avoid duplicates
- Test with the latest version
- Collect relevant logs and error messages

**What to include:**
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Relevant logs from `logs/secvuln-agent.log`

### 💡 Suggest New Features

Have an idea? We'd love to hear it!

**Good feature suggestions include:**
- Clear use case and problem being solved
- Proposed implementation approach
- Potential impact on existing functionality
- Alternative solutions considered

### 📝 Improve Documentation

Documentation is crucial!

**Areas to contribute:**
- Fix typos or unclear explanations
- Add examples and use cases
- Improve installation instructions
- Create tutorials or guides
- Translate documentation

### 🔧 Submit Pull Requests

Code contributions are welcome!

**Good candidates for PRs:**
- Bug fixes
- New features (discuss first in an issue)
- Performance improvements
- Code refactoring
- Test coverage improvements

### ⭐ Add New Data Source Collectors

Expand vulnerability coverage!

**Examples:**
- Vendor-specific security feeds
- Regional CERT advisories
- Exploit databases
- Threat intelligence platforms

### 🔌 Add New Notification Channels

Integrate with more tools!

**Examples:**
- Discord, Mattermost
- SIEM platforms (Splunk, QRadar)
- Ticketing systems (Jira, ServiceNow)
- Mobile push notifications

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, conda)
- Basic understanding of security concepts
- Familiarity with REST APIs (for collectors)

### Fork and Clone

1. **Fork the repository** on GitHub

2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/secvuln-agent.git
   cd secvuln-agent
   ```

3. **Add upstream remote:**
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/secvuln-agent.git
   ```

## Development Setup

### 1. Create Virtual Environment

```bash
# Using venv
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Or using conda
conda create -n secvuln python=3.10
conda activate secvuln
```

### 2. Install Dependencies

```bash
# Install all requirements including dev dependencies
pip install -r requirements.txt

# Install development tools (if you create requirements-dev.txt)
pip install pytest black flake8 mypy
```

### 3. Configure for Development

```bash
# Copy example config
cp config/config.example.yaml config/config.yaml

# Edit with your test credentials (use test accounts, not production!)
nano config/config.yaml
```

### 4. Run Tests

```bash
# Run the agent in test mode
python src/main.py

# Check logs
tail -f logs/secvuln-agent.log
```

## Reporting Bugs

### Create an Issue

Use the bug report template:

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Configure '...'
2. Run '...'
3. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.10.2]
- SecVuln-Agent Version: [e.g., 1.0.0]

**Logs:**
```
Paste relevant logs here
```

**Additional context**
Any other context about the problem.
```

### Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities!

Instead:
- Email security details privately to the maintainers
- Include "SECURITY" in the subject line
- Provide detailed reproduction steps
- Allow time for a fix before public disclosure

## Suggesting Features

### Create a Feature Request

Use the feature request template:

```markdown
**Is your feature request related to a problem?**
A clear description of the problem. Ex. I'm always frustrated when [...]

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Other solutions or features you've considered.

**Use case**
How would this feature be used? Who would benefit?

**Implementation ideas**
If you have thoughts on how to implement this, share them.

**Additional context**
Screenshots, mockups, or other context.
```

## Submitting Pull Requests

### Before You Start

1. **Check existing issues/PRs** to avoid duplicates
2. **Create an issue first** for significant changes
3. **Get feedback** on your approach before coding
4. **Keep changes focused** - one feature per PR

### Pull Request Process

#### 1. Create a Branch

```bash
# Update your fork
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
# Or for bug fixes
git checkout -b fix/bug-description
```

**Branch naming conventions:**
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/changes

#### 2. Make Your Changes

```bash
# Make changes
nano src/collectors/your_collector.py

# Test thoroughly
python src/main.py

# Check logs
tail -f logs/secvuln-agent.log
```

#### 3. Follow Code Style

```bash
# Format code with black
black src/

# Check linting
flake8 src/

# Type checking (optional but recommended)
mypy src/
```

#### 4. Write Tests

Create tests in `tests/` directory:

```python
# tests/test_your_collector.py
import pytest
from src.collectors.your_collector import YourCollector

def test_collector_initialization():
    collector = YourCollector()
    assert collector is not None

def test_collect_returns_list():
    collector = YourCollector()
    result = collector.collect()
    assert isinstance(result, list)
```

Run tests:
```bash
pytest tests/
```

#### 5. Update Documentation

- Add docstrings to all functions/classes
- Update README.md if adding features
- Create/update relevant guides
- Add examples to documentation

#### 6. Commit Your Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "Add XYZ collector for vulnerability data

- Implements XYZ API integration
- Adds rate limiting support
- Includes error handling
- Adds tests for collector

Fixes #123"
```

**Commit message guidelines:**
- Use present tense ("Add feature" not "Added feature")
- First line: brief summary (50 chars max)
- Blank line, then detailed description
- Reference issues/PRs with #number
- Explain WHY, not just WHAT

#### 7. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

#### 8. Create Pull Request

1. Go to your fork on GitHub
2. Click "New Pull Request"
3. Select your branch
4. Fill out the PR template:

```markdown
**Description**
Clear description of changes.

**Motivation and Context**
Why is this change needed? What problem does it solve?

**Related Issue**
Fixes #123

**Type of Change**
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that breaks existing functionality)
- [ ] Documentation update

**Testing**
- [ ] Tested locally
- [ ] Added unit tests
- [ ] All tests pass
- [ ] Manual testing completed

**Screenshots** (if applicable)

**Checklist**
- [ ] Code follows project style guidelines
- [ ] Self-reviewed my code
- [ ] Commented complex code sections
- [ ] Updated documentation
- [ ] No new warnings
- [ ] Added tests that prove fix/feature works
- [ ] New and existing tests pass
```

#### 9. Code Review Process

- Maintainers will review your PR
- Address feedback and requested changes
- Push updates to the same branch
- Once approved, maintainers will merge

## Adding New Data Source Collectors

### Collector Structure

Create a new file in `src/collectors/`:

```python
"""
Your Collector Name
Description of the data source
Source: https://example.com/api
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class YourCollector:
    """
    Collects vulnerabilities from [Source Name].
    Tier: [1/2/3] - [Description]
    Rate limit: [details if applicable]
    """

    SOURCE_NAME = "YOUR_SOURCE"
    API_URL = "https://api.example.com/vulnerabilities"

    def __init__(self, config: Dict = None, api_key: Optional[str] = None):
        """
        Initialize collector.

        Args:
            config: Configuration dictionary
            api_key: API key for authentication (optional)
        """
        self.config = config or {}
        self.api_key = api_key
        self.timeout = self.config.get('timeout', 30)

    def collect(self, since: Optional[datetime] = None) -> List[Dict]:
        """
        Collect CVEs from the source.

        Args:
            since: Only return CVEs modified since this datetime

        Returns:
            List[Dict]: List of CVE dictionaries in standard format
        """
        try:
            logger.info(f"Fetching CVEs from {self.SOURCE_NAME}")

            # Make API request
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'

            response = requests.get(
                self.API_URL,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            cves = []

            # Parse response
            for item in data.get('vulnerabilities', []):
                cve = self._parse_cve(item)
                if cve:
                    cves.append(cve)

            logger.info(f"Collected {len(cves)} CVEs from {self.SOURCE_NAME}")
            return cves

        except requests.RequestException as e:
            logger.error(f"Failed to fetch from {self.SOURCE_NAME}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing {self.SOURCE_NAME} data: {e}")
            return []

    def _parse_cve(self, raw_data: Dict) -> Optional[Dict]:
        """
        Parse a CVE entry into standard format.

        Args:
            raw_data: Raw CVE data from API

        Returns:
            Dict: Standardized CVE dictionary or None
        """
        try:
            # Extract required fields
            cve_id = raw_data.get('id')
            if not cve_id:
                return None

            # Return standardized format
            return {
                'cve_id': cve_id,
                'cvss_score': float(raw_data.get('cvss', 0)),
                'severity': raw_data.get('severity', 'UNKNOWN').upper(),
                'description': raw_data.get('description', ''),
                'source': self.SOURCE_NAME,
                'exploit_available': raw_data.get('exploit_exists', False),
                'in_cisa_kev': False,  # Update if source provides this
                'metadata': {
                    'published': raw_data.get('published_date'),
                    'modified': raw_data.get('modified_date'),
                    # Add source-specific fields
                    'vendor': raw_data.get('vendor'),
                    'product': raw_data.get('product'),
                }
            }

        except Exception as e:
            logger.debug(f"Failed to parse CVE: {e}")
            return None


# Example usage for testing
if __name__ == "__main__":
    from utils.logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    collector = YourCollector()
    cves = collector.collect()
    print(f"\nCollected {len(cves)} CVEs from {collector.SOURCE_NAME}")

    if cves:
        print("\nSample CVE:")
        import json
        print(json.dumps(cves[0], indent=2))
```

### Standard CVE Format

All collectors MUST return CVEs in this format:

```python
{
    'cve_id': str,           # Required: CVE-YYYY-NNNNN
    'cvss_score': float,     # Required: 0.0 to 10.0
    'severity': str,         # Required: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    'description': str,      # Required: Brief description
    'source': str,           # Required: Your SOURCE_NAME
    'exploit_available': bool,  # Required: True if exploit exists
    'in_cisa_kev': bool,     # Required: True if in CISA KEV catalog
    'metadata': {            # Optional: Source-specific data
        'published': str,     # ISO format date
        'modified': str,      # ISO format date
        # Add any source-specific fields
    }
}
```

### Collector Checklist

- [ ] Inherits or follows collector pattern
- [ ] Implements `collect(since)` method
- [ ] Returns standardized CVE format
- [ ] Handles errors gracefully
- [ ] Logs appropriately
- [ ] Respects rate limits
- [ ] Includes docstrings
- [ ] Has standalone test (`if __name__ == "__main__"`)
- [ ] Updated `src/main.py` to include new collector
- [ ] Updated configuration example
- [ ] Added documentation

### Integrate with Main Agent

Edit `src/main.py`:

```python
# Add import
from collectors.your_collector import YourCollector

# In _initialize_collectors():
if sources_config.get('your_source', {}).get('enabled', False):
    api_key = self.secrets.get_provider_key('your_source')
    collectors.append(('Your Source', YourCollector(api_key=api_key), 'tier2'))
```

Update `config/config.yaml`:

```yaml
sources:
  custom_sources:
    your_source:
      enabled: true
      api_key_required: true  # or false
```

## Adding New Notification Channels

### Notifier Structure

Create a new file in `src/notifiers/`:

```python
"""
Your Notifier Name
Sends notifications via [Service Name]
"""

import requests
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class YourNotifier:
    """
    Sends notifications via [Service Name].
    Supports: alerts, digests, [other features]
    """

    def __init__(self, config: Dict):
        """
        Initialize notifier.

        Args:
            config: Notification configuration
        """
        self.config = config
        self.webhook_url = config.get('webhook_url')  # Or other auth
        self.timeout = config.get('timeout', 30)

    def send_alert(self, cve_data: Dict, matched_devices: List[Dict] = None,
                   ai_analysis: Dict = None) -> bool:
        """
        Send immediate alert for critical vulnerability.

        Args:
            cve_data: CVE data dictionary
            matched_devices: List of matched devices
            ai_analysis: AI analysis results

        Returns:
            bool: True if sent successfully
        """
        try:
            # Format message
            message = self._format_alert(cve_data, matched_devices, ai_analysis)

            # Send via API
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            response.raise_for_status()

            logger.info(f"Sent alert to {self.__class__.__name__}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            return False

    def send_digest(self, cves: List[Dict], summary: Dict) -> bool:
        """
        Send digest summary of vulnerabilities.

        Args:
            cves: List of CVE dictionaries
            summary: Summary statistics

        Returns:
            bool: True if sent successfully
        """
        try:
            # Format digest
            message = self._format_digest(cves, summary)

            # Send via API
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            response.raise_for_status()

            logger.info(f"Sent digest to {self.__class__.__name__}")
            return True

        except Exception as e:
            logger.error(f"Failed to send digest: {e}")
            return False

    def _format_alert(self, cve_data: Dict, matched_devices: List[Dict],
                      ai_analysis: Dict) -> Dict:
        """
        Format alert message for the service.

        Args:
            cve_data: CVE data
            matched_devices: Matched devices
            ai_analysis: AI analysis

        Returns:
            Dict: Formatted message payload
        """
        cve_id = cve_data.get('cve_id', 'Unknown')
        cvss = cve_data.get('cvss_score', 0)
        severity = cve_data.get('severity', 'UNKNOWN')

        # Format according to service's API requirements
        return {
            'title': f'🚨 {cve_id} - {severity}',
            'text': f'CVSS {cvss}: {cve_data.get("description", "")}',
            # Add service-specific formatting
        }

    def _format_digest(self, cves: List[Dict], summary: Dict) -> Dict:
        """
        Format digest message for the service.

        Args:
            cves: List of CVEs
            summary: Summary stats

        Returns:
            Dict: Formatted message payload
        """
        return {
            'title': f'📊 Daily Security Digest',
            'text': f'Found {summary.get("total", 0)} vulnerabilities',
            # Add service-specific formatting
        }

    def test_connection(self) -> bool:
        """
        Test connection to the service.

        Returns:
            bool: True if connection successful
        """
        try:
            # Send test message
            test_message = {'text': 'SecVuln-Agent test'}
            response = requests.post(
                self.webhook_url,
                json=test_message,
                timeout=self.timeout
            )
            response.raise_for_status()
            return True

        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False


# Example usage
if __name__ == "__main__":
    config = {
        'webhook_url': 'https://your-service.com/webhook/...'
    }

    notifier = YourNotifier(config)
    print(f"Testing {notifier.__class__.__name__}...")

    if notifier.test_connection():
        print("✅ Connection successful")
    else:
        print("❌ Connection failed")
```

### Notifier Checklist

- [ ] Implements `send_alert()` method
- [ ] Implements `send_digest()` method
- [ ] Implements `test_connection()` method
- [ ] Handles errors gracefully
- [ ] Logs appropriately
- [ ] Includes docstrings
- [ ] Has standalone test
- [ ] Updated `notification_manager.py`
- [ ] Updated configuration example
- [ ] Added documentation

### Integrate with Notification Manager

Edit `src/notifiers/notification_manager.py`:

```python
# In _initialize_notifiers():
if channels.get('your_service', {}).get('enabled', False):
    webhook_url = channels['your_service'].get('webhook_url')
    if webhook_url:
        from .your_notifier import YourNotifier
        self.notifiers['your_service'] = YourNotifier({'webhook_url': webhook_url})
        logger.info("Initialized Your Service notifier")
```

Update `config/config.yaml`:

```yaml
notifications:
  channels:
    your_service:
      enabled: false
      webhook_url: ''
```

## Code Style Guidelines

### Python Style

- Follow **PEP 8** style guide
- Use **Black** for automatic formatting
- Maximum line length: 100 characters
- Use type hints where helpful

```python
def process_cve(cve_data: Dict, config: Optional[Dict] = None) -> bool:
    """
    Process a CVE with configuration.

    Args:
        cve_data: CVE information dictionary
        config: Optional configuration

    Returns:
        bool: True if processing succeeded
    """
    pass
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `CISAKEVCollector`)
- **Functions**: `snake_case` (e.g., `collect_vulnerabilities`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `API_URL`)
- **Private methods**: `_leading_underscore` (e.g., `_parse_cve`)

### Imports

Order imports by:
1. Standard library
2. Third-party packages
3. Local application

```python
import logging
from typing import Dict, List
from datetime import datetime

import requests
import yaml

from utils.logger import setup_logger
from processors.matcher import DeviceMatcher
```

### Docstrings

Use Google-style docstrings:

```python
def complex_function(param1: str, param2: int = 0) -> Dict:
    """
    Brief description of function.

    Longer description if needed, explaining behavior,
    edge cases, or important notes.

    Args:
        param1: Description of param1
        param2: Description of param2 (default: 0)

    Returns:
        Dict: Description of return value

    Raises:
        ValueError: When param1 is invalid
        RequestException: When API call fails

    Example:
        >>> result = complex_function("test", 5)
        >>> print(result['status'])
        'success'
    """
    pass
```

### Error Handling

```python
try:
    # Attempt operation
    result = risky_operation()
except SpecificException as e:
    # Handle specific error
    logger.error(f"Operation failed: {e}")
    return default_value
except Exception as e:
    # Catch unexpected errors
    logger.exception(f"Unexpected error: {e}")
    raise
finally:
    # Cleanup
    cleanup_resources()
```

### Logging

```python
import logging

logger = logging.getLogger(__name__)

# Use appropriate log levels
logger.debug("Detailed debugging information")
logger.info("General information")
logger.warning("Warning: potential issue")
logger.error("Error occurred")
logger.critical("Critical system failure")

# Include context
logger.info(f"Processing CVE {cve_id} from {source}")
logger.error(f"Failed to connect to {api_url}: {error}")
```

## Testing Guidelines

### Test Structure

Create tests in `tests/` directory:

```
tests/
├── __init__.py
├── conftest.py              # Shared fixtures
├── test_collectors/
│   ├── test_nvd_collector.py
│   └── test_cisa_kev.py
├── test_processors/
│   ├── test_matcher.py
│   └── test_ai_analyzer.py
└── test_notifiers/
    ├── test_email_notifier.py
    └── test_slack_notifier.py
```

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch
from src.collectors.your_collector import YourCollector


class TestYourCollector:
    """Test suite for YourCollector"""

    @pytest.fixture
    def collector(self):
        """Create a collector instance for testing"""
        return YourCollector()

    @pytest.fixture
    def sample_cve_data(self):
        """Sample CVE data for testing"""
        return {
            'cve_id': 'CVE-2024-1234',
            'cvss_score': 9.8,
            'severity': 'CRITICAL'
        }

    def test_initialization(self, collector):
        """Test collector initializes correctly"""
        assert collector is not None
        assert collector.SOURCE_NAME == "YOUR_SOURCE"

    def test_collect_returns_list(self, collector):
        """Test collect returns a list"""
        result = collector.collect()
        assert isinstance(result, list)

    @patch('requests.get')
    def test_collect_with_mock_api(self, mock_get, collector):
        """Test collect with mocked API response"""
        # Mock API response
        mock_response = Mock()
        mock_response.json.return_value = {
            'vulnerabilities': [
                {'id': 'CVE-2024-1234', 'cvss': 9.8}
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Test
        result = collector.collect()
        assert len(result) > 0
        assert result[0]['cve_id'] == 'CVE-2024-1234'

    def test_parse_cve(self, collector, sample_cve_data):
        """Test CVE parsing"""
        parsed = collector._parse_cve(sample_cve_data)
        assert parsed['cve_id'] == 'CVE-2024-1234'
        assert parsed['cvss_score'] == 9.8

    def test_error_handling(self, collector):
        """Test error handling with invalid data"""
        invalid_data = {'invalid': 'data'}
        result = collector._parse_cve(invalid_data)
        assert result is None
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_collectors/test_your_collector.py

# Run with coverage
pytest --cov=src tests/

# Run with verbose output
pytest -v

# Run specific test
pytest tests/test_collectors/test_your_collector.py::TestYourCollector::test_initialization
```

## Documentation Guidelines

### README Updates

When adding features, update the main README.md:

- Add to feature list
- Update configuration examples
- Add usage examples
- Update screenshots if UI changed

### Inline Documentation

```python
class YourCollector:
    """
    Brief one-line description.

    Longer description explaining:
    - What the collector does
    - What data source it uses
    - Any special requirements
    - Rate limiting or authentication needs

    Attributes:
        SOURCE_NAME: Name of the data source
        API_URL: Base URL for the API

    Example:
        >>> collector = YourCollector(api_key="xxx")
        >>> cves = collector.collect()
        >>> print(f"Found {len(cves)} CVEs")
    """
```

### Creating Guides

When adding major features:

1. Create a dedicated markdown file (e.g., `YOUR_FEATURE.md`)
2. Include:
   - Overview and purpose
   - Configuration instructions
   - Usage examples
   - Troubleshooting tips
   - FAQ section

## Questions or Need Help?

- **General questions:** Open a GitHub Discussion
- **Bug reports:** Create an issue with the bug template
- **Feature requests:** Create an issue with the feature template
- **Security issues:** Email maintainers privately
- **Code questions:** Comment on relevant PRs or issues

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

## Thank You!

Your contributions make SecVuln-Agent better for everyone. Thank you for taking the time to contribute!

---

**Happy Contributing! 🎉**
