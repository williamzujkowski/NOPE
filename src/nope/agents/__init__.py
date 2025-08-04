"""
NOPE Agents Module

This module provides the agent-based architecture for the NOPE platform,
including base agent classes and specialized agent implementations.
"""

from nope.agents.base import BaseAgent
from nope.agents.data_collection import DataCollectionAgent
from nope.agents.analysis import AnalysisAgent
from nope.agents.correlation import CorrelationAgent

__all__ = [
    "BaseAgent",
    "DataCollectionAgent", 
    "AnalysisAgent",
    "CorrelationAgent",
]