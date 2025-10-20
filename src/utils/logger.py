"""
Logging Configuration for SecVuln Agent
Provides structured logging with file rotation and console output
"""

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
import sys

class AgentLogger:
    """
    Configures and manages logging for the SecVuln Agent.
    Provides both file and console logging with proper formatting.
    """

    def __init__(self, name: str = "secvuln-agent", log_dir: Path = None, log_level: str = "INFO"):
        """
        Initialize the logger.

        Args:
            name: Name of the logger
            log_dir: Directory for log files (defaults to ./logs)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.name = name
        self.log_dir = log_dir or Path(__file__).parent.parent.parent / "logs"
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)

        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Set up the logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)

        # Prevent duplicate handlers if logger is reinitialized
        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """Set up file and console handlers with formatters."""

        # Create formatters
        detailed_formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        simple_formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )

        # File handler - detailed logs with rotation
        log_file = self.log_dir / f"{self.name}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(file_handler)

        # Error file handler - only errors and critical
        error_log_file = self.log_dir / f"{self.name}_errors.log"
        error_file_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
            encoding='utf-8'
        )
        error_file_handler.setLevel(logging.ERROR)
        error_file_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(error_file_handler)

        # Console handler - simple format
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(simple_formatter)
        self.logger.addHandler(console_handler)

    def get_logger(self) -> logging.Logger:
        """
        Get the configured logger instance.

        Returns:
            logging.Logger: Configured logger
        """
        return self.logger

    def set_level(self, level: str):
        """
        Change the logging level.

        Args:
            level: New logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        new_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(new_level)
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(new_level)


def setup_logger(name: str = "secvuln-agent", log_dir: Path = None, log_level: str = "INFO") -> logging.Logger:
    """
    Convenience function to set up and get a logger.

    Args:
        name: Name of the logger
        log_dir: Directory for log files
        log_level: Logging level

    Returns:
        logging.Logger: Configured logger instance
    """
    agent_logger = AgentLogger(name, log_dir, log_level)
    return agent_logger.get_logger()


def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        module_name: Name of the module (__name__)

    Returns:
        logging.Logger: Logger instance for the module
    """
    return logging.getLogger(module_name)


# Example usage
if __name__ == "__main__":
    # Set up main logger
    logger = setup_logger(log_level="DEBUG")

    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")

    print(f"\nLogs are stored in: {Path(__file__).parent.parent.parent / 'logs'}")
