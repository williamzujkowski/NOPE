"""
NOPE: Network Operations Predictive Engine

A comprehensive CVE intelligence platform leveraging machine learning
and agent-based architecture for vulnerability prediction and analysis.
"""

__version__ = "0.1.0"
__author__ = "NOPE Team"
__email__ = "team@nope.security"
__license__ = "MIT"

# Core imports
from nope.core.config import Settings
from nope.core.exceptions import NOPEException

# Agent imports
from nope.agents.base import BaseAgent
from nope.agents.data_collection import DataCollectionAgent
from nope.agents.analysis import AnalysisAgent
from nope.agents.correlation import CorrelationAgent

# Model imports
from nope.models.ensemble import EnsembleModel
from nope.models.predictor import CVEPredictor

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "Settings",
    "NOPEException",
    "BaseAgent",
    "DataCollectionAgent",
    "AnalysisAgent",
    "CorrelationAgent",
    "EnsembleModel",
    "CVEPredictor",
]