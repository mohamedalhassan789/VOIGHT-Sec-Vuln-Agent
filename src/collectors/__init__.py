"""
Collectors package for vulnerability data sources
"""

from .cisa_kev import CISAKEVCollector

__all__ = [
    'CISAKEVCollector',
]
