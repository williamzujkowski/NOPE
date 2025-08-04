"""
NOPE Core Module

This module provides core functionality for the NOPE platform,
including configuration, exceptions, logging, and base classes.
"""

from nope.core.config import Settings, get_settings
from nope.core.exceptions import NOPEException

__all__ = [
    "Settings",
    "get_settings", 
    "NOPEException",
]