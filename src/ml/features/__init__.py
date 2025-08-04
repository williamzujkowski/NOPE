"""
Feature Extraction Module

This package contains feature extractors for the ML ensemble system.
Each extractor prepares features for specific models while maintaining
consistency across the ensemble.
"""

from .feature_extractor import FeatureExtractor

__all__ = ['FeatureExtractor']