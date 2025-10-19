"""
Configuration Loader for SecVuln Agent
Handles loading, validation, and parsing of config.yaml and devices.csv
"""

import yaml
import csv
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ConfigLoader:
    """
    Loads and validates configuration from YAML and CSV files.
    """

    def __init__(self, config_path: Optional[Path] = None, devices_path: Optional[Path] = None):
        """
        Initialize the configuration loader.

        Args:
            config_path: Path to config.yaml file
            devices_path: Path to devices.csv file
        """
        # Default paths
        project_root = Path(__file__).parent.parent.parent
        self.config_path = config_path or project_root / "config" / "config.yaml"
        self.devices_path = devices_path or project_root / "config" / "devices.csv"

        self.config = None
        self.devices = []

    def load_config(self) -> Dict:
        """
        Load and parse the YAML configuration file.

        Returns:
            Dict: Parsed configuration dictionary

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If YAML is invalid
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)

            logger.info(f"Loaded configuration from {self.config_path}")
            self._validate_config()
            return self.config

        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML configuration: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise

    def _validate_config(self):
        """
        Validate the configuration structure.

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.config:
            raise ValueError("Configuration is empty")

        # Check required sections
        required_sections = ['agent', 'sources', 'filters', 'notifications']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")

        # Validate agent section
        if 'interval_hours' not in self.config['agent']:
            raise ValueError("Missing 'interval_hours' in agent configuration")

        # Validate filters
        if 'min_cvss_score' in self.config['filters']:
            score = self.config['filters']['min_cvss_score']
            if not (0.0 <= score <= 10.0):
                raise ValueError(f"Invalid min_cvss_score: {score}. Must be between 0.0 and 10.0")

        logger.debug("Configuration validation passed")

    def load_devices(self) -> List[Dict]:
        """
        Load and parse the devices CSV file.

        Returns:
            List[Dict]: List of device dictionaries

        Raises:
            FileNotFoundError: If devices file doesn't exist
        """
        if not self.devices_path.exists():
            logger.warning(f"Devices file not found: {self.devices_path}")
            return []

        try:
            with open(self.devices_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.devices = [row for row in reader]

            logger.info(f"Loaded {len(self.devices)} devices from {self.devices_path}")
            self._validate_devices()
            return self.devices

        except Exception as e:
            logger.error(f"Failed to load devices: {e}")
            raise

    def _validate_devices(self):
        """
        Validate the devices data.

        Raises:
            ValueError: If devices data is invalid
        """
        required_fields = ['device_id', 'device_type', 'vendor', 'product', 'version']

        for idx, device in enumerate(self.devices):
            for field in required_fields:
                if field not in device or not device[field].strip():
                    raise ValueError(
                        f"Device at row {idx + 2} missing required field: {field}"
                    )

        logger.debug(f"Devices validation passed for {len(self.devices)} devices")

    def get_config(self) -> Dict:
        """
        Get the loaded configuration.

        Returns:
            Dict: Configuration dictionary
        """
        if self.config is None:
            self.load_config()
        return self.config

    def get_devices(self) -> List[Dict]:
        """
        Get the loaded devices.

        Returns:
            List[Dict]: List of device dictionaries
        """
        if not self.devices:
            self.load_devices()
        return self.devices

    def get_agent_config(self) -> Dict:
        """Get agent configuration section."""
        return self.get_config().get('agent', {})

    def get_sources_config(self) -> Dict:
        """Get sources configuration section."""
        return self.get_config().get('sources', {})

    def get_filters_config(self) -> Dict:
        """Get filters configuration section."""
        return self.get_config().get('filters', {})

    def get_notifications_config(self) -> Dict:
        """Get notifications configuration section."""
        return self.get_config().get('notifications', {})

    def get_ai_config(self) -> Dict:
        """Get AI configuration section."""
        return self.get_config().get('ai', {})

    def get_advanced_config(self) -> Dict:
        """Get advanced configuration section."""
        return self.get_config().get('advanced', {})

    def reload(self):
        """Reload both configuration and devices."""
        self.load_config()
        self.load_devices()
        logger.info("Configuration and devices reloaded")

    def save_config(self, config: Dict):
        """
        Save configuration to YAML file.

        Args:
            config: Configuration dictionary to save
        """
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

            self.config = config
            logger.info(f"Configuration saved to {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise

    def save_devices(self, devices: List[Dict]):
        """
        Save devices to CSV file.

        Args:
            devices: List of device dictionaries to save
        """
        if not devices:
            logger.warning("No devices to save")
            return

        try:
            fieldnames = devices[0].keys()
            with open(self.devices_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(devices)

            self.devices = devices
            logger.info(f"Saved {len(devices)} devices to {self.devices_path}")

        except Exception as e:
            logger.error(f"Failed to save devices: {e}")
            raise


def load_configuration(config_path: Optional[Path] = None) -> Dict:
    """
    Convenience function to load configuration.

    Args:
        config_path: Path to config.yaml file

    Returns:
        Dict: Loaded configuration
    """
    loader = ConfigLoader(config_path)
    return loader.load_config()


def load_device_inventory(devices_path: Optional[Path] = None) -> List[Dict]:
    """
    Convenience function to load devices.

    Args:
        devices_path: Path to devices.csv file

    Returns:
        List[Dict]: Loaded devices
    """
    loader = ConfigLoader(devices_path=devices_path)
    return loader.load_devices()


# Example usage
if __name__ == "__main__":
    from logger import setup_logger

    logger = setup_logger(log_level="DEBUG")

    try:
        loader = ConfigLoader()
        config = loader.load_config()
        devices = loader.load_devices()

        print(f"Configuration loaded: {config.get('agent', {}).get('name', 'Unknown')}")
        print(f"Devices loaded: {len(devices)}")

    except Exception as e:
        print(f"Error: {e}")
