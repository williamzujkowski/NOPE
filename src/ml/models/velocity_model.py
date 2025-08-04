"""
Velocity Model

Analyzes the speed of attack development and exploitation patterns.
Tracks how quickly vulnerabilities transition from disclosure to active exploitation.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import roc_auc_score
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import joblib


class VelocityModel:
    """
    Velocity model that analyzes:
    - Time-to-exploitation patterns
    - Attack development velocity indicators
    - Proof-of-concept to exploit progression speed
    - Community activity acceleration patterns
    - Threat actor behavior velocity
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            min_samples_split=20,
            min_samples_leaf=10,
            subsample=0.8,
            random_state=random_state
        )
        self.scaler = RobustScaler()
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Expected features for velocity analysis
        self.expected_features = [
            'disclosure_to_poc_days', 'poc_to_exploit_days', 'disclosure_to_exploit_days',
            'twitter_mentions_velocity', 'github_activity_velocity', 'blog_posts_velocity',
            'exploit_releases_per_day', 'patch_to_exploit_days',
            'vulnerability_age_days', 'first_seen_wild_days',
            'security_advisories_velocity', 'cve_updates_velocity',
            'researcher_interest_score', 'bounty_program_interest',
            'technical_analysis_posts', 'technical_difficulty_score',
            'similar_vulns_exploited_count', 'vendor_response_speed',
            'affected_software_popularity', 'exploit_code_complexity',
            'attack_surface_size', 'required_user_interaction',
            'network_accessibility', 'authentication_required',
            'payload_delivery_methods', 'evasion_techniques_count'
        ]
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare velocity-specific features"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Velocity feature engineering
        X_prepared['total_development_velocity'] = (
            1.0 / (X_prepared['disclosure_to_exploit_days'] + 1)
        )
        
        X_prepared['poc_acceleration'] = np.where(
            X_prepared['disclosure_to_poc_days'] > 0,
            X_prepared['poc_to_exploit_days'] / X_prepared['disclosure_to_poc_days'],
            0.0
        )
        
        X_prepared['community_buzz_velocity'] = (
            X_prepared['twitter_mentions_velocity'] * 0.3 +
            X_prepared['github_activity_velocity'] * 0.4 +
            X_prepared['blog_posts_velocity'] * 0.3
        )
        
        X_prepared['technical_momentum'] = (
            X_prepared['technical_analysis_posts'] * 
            (1.0 / (X_prepared['technical_difficulty_score'] + 1))
        )
        
        X_prepared['exploit_readiness_score'] = (
            X_prepared['exploit_releases_per_day'] * 0.4 +
            X_prepared['payload_delivery_methods'] * 0.3 +
            X_prepared['evasion_techniques_count'] * 0.3
        )
        
        X_prepared['urgency_indicator'] = np.where(
            X_prepared['patch_to_exploit_days'] < 7, 1.0,
            np.where(X_prepared['patch_to_exploit_days'] < 30, 0.7, 0.3)
        )
        
        # Time-based velocity features
        X_prepared['aging_acceleration'] = np.where(
            X_prepared['vulnerability_age_days'] > 0,
            X_prepared['community_buzz_velocity'] / np.log(X_prepared['vulnerability_age_days'] + 1),
            0.0
        )
        
        X_prepared['exploitation_pressure'] = (
            X_prepared['similar_vulns_exploited_count'] * 0.3 +
            X_prepared['bounty_program_interest'] * 0.2 +
            X_prepared['researcher_interest_score'] * 0.5
        )
        
        # Select engineered features
        feature_columns = self.expected_features + [
            'total_development_velocity', 'poc_acceleration', 'community_buzz_velocity',
            'technical_momentum', 'exploit_readiness_score', 'urgency_indicator',
            'aging_acceleration', 'exploitation_pressure'
        ]
        
        return X_prepared[feature_columns]
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'VelocityModel':
        """Train the velocity model"""
        X_prepared = self._prepare_features(X)
        
        # Handle infinite and NaN values
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan)
        X_prepared = X_prepared.fillna(0)
        
        # Scale features (robust to outliers)
        X_scaled = self.scaler.fit_transform(X_prepared)
        
        # Train model
        self.model.fit(X_scaled, y)
        
        # Store feature importance
        self.feature_importance_ = dict(zip(
            X_prepared.columns,
            self.model.feature_importances_
        ))
        
        self.is_fitted = True
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Make binary predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        return self.model.predict(X_scaled)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        return self.model.predict_proba(X_scaled)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate confidence based on velocity indicators quality
        """
        if not self.is_fitted:
            return 0.0
        
        X_prepared = self._prepare_features(X)
        
        # Confidence factors
        data_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Velocity-specific confidence indicators
        timing_data_quality = np.where(
            (X_prepared['disclosure_to_exploit_days'] > 0) & 
            (X_prepared['vulnerability_age_days'] > 0),
            1.0, 0.5
        )
        
        community_signal_strength = np.clip(
            (X_prepared['community_buzz_velocity'] + 
             X_prepared['technical_momentum']) / 2.0,
            0.0, 1.0
        )
        
        # Combined confidence
        confidence = (
            data_completeness * 0.4 +
            timing_data_quality * 0.3 +
            community_signal_strength * 0.3
        )
        
        return float(np.mean(confidence))
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_fitted:
            return {}
        return self.feature_importance_.copy()
    
    def get_sklearn_model(self):
        """Get the underlying scikit-learn model"""
        return self.model
    
    def analyze_velocity_patterns(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze velocity patterns in the data
        """
        X_prepared = self._prepare_features(X)
        
        analysis = {
            'average_disclosure_to_exploit_days': float(X_prepared['disclosure_to_exploit_days'].mean()),
            'median_disclosure_to_exploit_days': float(X_prepared['disclosure_to_exploit_days'].median()),
            'fast_exploitation_percentage': float(
                (X_prepared['disclosure_to_exploit_days'] <= 7).mean() * 100
            ),
            'average_community_velocity': float(X_prepared['community_buzz_velocity'].mean()),
            'high_velocity_indicators': [],
            'velocity_distribution_stats': {}
        }
        
        # Identify high-velocity patterns
        high_velocity_threshold = X_prepared['total_development_velocity'].quantile(0.8)
        high_velocity_samples = X_prepared[
            X_prepared['total_development_velocity'] > high_velocity_threshold
        ]
        
        if len(high_velocity_samples) > 0:
            analysis['high_velocity_indicators'] = [
                f"High POC acceleration: {high_velocity_samples['poc_acceleration'].mean():.2f}",
                f"Strong community buzz: {high_velocity_samples['community_buzz_velocity'].mean():.2f}",
                f"High technical momentum: {high_velocity_samples['technical_momentum'].mean():.2f}"
            ]
        
        # Velocity distribution statistics
        for feature in ['total_development_velocity', 'community_buzz_velocity', 'technical_momentum']:
            if feature in X_prepared.columns:
                analysis['velocity_distribution_stats'][feature] = {
                    'mean': float(X_prepared[feature].mean()),
                    'std': float(X_prepared[feature].std()),
                    'q25': float(X_prepared[feature].quantile(0.25)),
                    'q75': float(X_prepared[feature].quantile(0.75))
                }
        
        return analysis
    
    def predict_time_to_exploitation(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict time to exploitation in days based on velocity indicators
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        
        # Use velocity features to estimate timing
        base_time = 21  # Default 3 weeks
        
        # Adjust based on velocity indicators
        velocity_factor = X_prepared['total_development_velocity']
        community_factor = X_prepared['community_buzz_velocity']
        urgency_factor = X_prepared['urgency_indicator']
        
        # Combined velocity adjustment
        speed_multiplier = (
            velocity_factor * 0.4 +
            community_factor * 0.3 +
            urgency_factor * 0.3
        )
        
        # Calculate estimated days
        estimated_days = base_time * (1.0 - speed_multiplier * 0.8)
        estimated_days = np.clip(estimated_days, 1, 90)  # Clamp between 1-90 days
        
        return estimated_days.values
    
    def get_velocity_risk_factors(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Get velocity-specific risk factors for a sample
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        risk_factors = {
            'overall_velocity_risk': 'LOW',
            'time_pressure_factors': [],
            'community_momentum_factors': [],
            'technical_readiness_factors': [],
            'estimated_time_to_exploitation': 21
        }
        
        # Overall velocity assessment
        velocity_score = (
            sample['total_development_velocity'] * 0.3 +
            sample['community_buzz_velocity'] * 0.3 +
            sample['exploit_readiness_score'] * 0.4
        )
        
        if velocity_score > 0.7:
            risk_factors['overall_velocity_risk'] = 'HIGH'
        elif velocity_score > 0.4:
            risk_factors['overall_velocity_risk'] = 'MEDIUM'
        
        # Time pressure factors
        if sample['disclosure_to_exploit_days'] <= 7:
            risk_factors['time_pressure_factors'].append("Historically fast exploitation (≤7 days)")
        
        if sample['patch_to_exploit_days'] <= 3:
            risk_factors['time_pressure_factors'].append("Very short patch-to-exploit window")
        
        if sample['urgency_indicator'] > 0.7:
            risk_factors['time_pressure_factors'].append("High urgency indicators detected")
        
        # Community momentum
        if sample['community_buzz_velocity'] > 0.6:
            risk_factors['community_momentum_factors'].append("High community discussion velocity")
        
        if sample['technical_analysis_posts'] > 5:
            risk_factors['community_momentum_factors'].append("Multiple technical analyses published")
        
        if sample['researcher_interest_score'] > 0.7:
            risk_factors['community_momentum_factors'].append("Strong researcher interest")
        
        # Technical readiness
        if sample['exploit_readiness_score'] > 0.6:
            risk_factors['technical_readiness_factors'].append("High exploit readiness score")
        
        if sample['payload_delivery_methods'] > 2:
            risk_factors['technical_readiness_factors'].append("Multiple delivery methods available")
        
        # Estimated time to exploitation
        estimated_time = self.predict_time_to_exploitation(X.iloc[[sample_idx]])
        risk_factors['estimated_time_to_exploitation'] = int(estimated_time[0])
        
        return risk_factors