"""
Temporal Model

Analyzes time-based patterns, seasonal trends, and temporal exploitation behaviors.
Predicts exploitation likelihood based on timing patterns and cyclical behaviors.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import calendar
import joblib


class TemporalModel:
    """
    Temporal model that analyzes:
    - Seasonal exploitation patterns
    - Day-of-week and time-of-day patterns
    - Holiday and event-based timing
    - Disclosure timing patterns
    - Patch cycle and maintenance window exploitation
    - Geopolitical event correlations
    - Academic calendar correlations (research disclosure timing)
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.15,
            max_depth=6,
            min_samples_split=25,
            min_samples_leaf=15,
            subsample=0.9,
            random_state=random_state
        )
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=10, random_state=random_state)
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Expected features for temporal analysis
        self.expected_features = [
            'disclosure_month', 'disclosure_day_of_week', 'disclosure_hour',
            'disclosure_quarter', 'days_since_disclosure', 'days_to_patch_tuesday',
            'is_holiday_period', 'is_summer_vacation', 'is_end_of_quarter',
            'conference_season_proximity', 'academic_semester_timing',
            'geopolitical_tension_level', 'cyber_awareness_month',
            'black_friday_proximity', 'election_period_proximity',
            'vulnerability_age_weeks', 'patch_cycle_position',
            'maintenance_window_proximity', 'weekend_disclosure',
            'business_hours_disclosure', 'after_hours_activity',
            'time_zone_coordination_factor', 'working_days_since_disclosure',
            'security_conference_timing', 'earnings_season_proximity'
        ]
        
        # Temporal pattern weights
        self.seasonal_weights = {
            'spring': 1.1,    # Conference season, increased activity
            'summer': 0.8,    # Vacation period, reduced activity
            'fall': 1.2,      # Back to work, increased activity
            'winter': 0.9     # Holiday period, mixed activity
        }
        
        self.day_weights = {
            'Monday': 1.0,
            'Tuesday': 1.2,   # Patch Tuesday influence
            'Wednesday': 1.1,
            'Thursday': 1.1,
            'Friday': 0.9,    # End of week, less activity
            'Saturday': 0.7,  # Weekend, reduced activity
            'Sunday': 0.6     # Weekend, minimal activity
        }
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare temporal-specific features"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Temporal feature engineering
        
        # Cyclical encoding for time features
        X_prepared['month_sin'] = np.sin(2 * np.pi * X_prepared['disclosure_month'] / 12)
        X_prepared['month_cos'] = np.cos(2 * np.pi * X_prepared['disclosure_month'] / 12)
        X_prepared['day_sin'] = np.sin(2 * np.pi * X_prepared['disclosure_day_of_week'] / 7)
        X_prepared['day_cos'] = np.cos(2 * np.pi * X_prepared['disclosure_day_of_week'] / 7)
        X_prepared['hour_sin'] = np.sin(2 * np.pi * X_prepared['disclosure_hour'] / 24)
        X_prepared['hour_cos'] = np.cos(2 * np.pi * X_prepared['disclosure_hour'] / 24)
        
        # Season-based features
        X_prepared['is_spring'] = ((X_prepared['disclosure_month'] >= 3) & 
                                  (X_prepared['disclosure_month'] <= 5)).astype(float)
        X_prepared['is_summer'] = ((X_prepared['disclosure_month'] >= 6) & 
                                  (X_prepared['disclosure_month'] <= 8)).astype(float)
        X_prepared['is_fall'] = ((X_prepared['disclosure_month'] >= 9) & 
                                (X_prepared['disclosure_month'] <= 11)).astype(float)
        X_prepared['is_winter'] = ((X_prepared['disclosure_month'] == 12) | 
                                  (X_prepared['disclosure_month'] <= 2)).astype(float)
        
        # Weighted seasonal risk
        X_prepared['seasonal_risk_weight'] = (
            X_prepared['is_spring'] * self.seasonal_weights['spring'] +
            X_prepared['is_summer'] * self.seasonal_weights['summer'] +
            X_prepared['is_fall'] * self.seasonal_weights['fall'] +
            X_prepared['is_winter'] * self.seasonal_weights['winter']
        )
        
        # Day-of-week risk patterns
        day_risk_mapping = {i: weight for i, weight in enumerate(self.day_weights.values())}
        X_prepared['day_risk_weight'] = X_prepared['disclosure_day_of_week'].map(day_risk_mapping).fillna(1.0)
        
        # Time pressure indicators
        X_prepared['high_time_pressure'] = (
            (X_prepared['days_to_patch_tuesday'] <= 3) |
            (X_prepared['is_end_of_quarter'] > 0.5) |
            (X_prepared['maintenance_window_proximity'] > 0.7)
        ).astype(float)
        
        # Activity timing patterns
        X_prepared['optimal_attack_timing'] = (
            X_prepared['business_hours_disclosure'] * 0.3 +
            X_prepared['working_days_since_disclosure'] * 0.1 +
            (1.0 - X_prepared['weekend_disclosure']) * 0.2 +
            X_prepared['after_hours_activity'] * 0.4
        )
        
        # Conference and event proximity impact
        X_prepared['event_driven_risk'] = (
            X_prepared['conference_season_proximity'] * 0.4 +
            X_prepared['security_conference_timing'] * 0.6
        )
        
        # Age-based temporal decay
        X_prepared['temporal_decay_factor'] = np.exp(-X_prepared['vulnerability_age_weeks'] / 12.0)
        
        # Holiday and special period risk adjustments
        X_prepared['special_period_risk'] = (
            X_prepared['is_holiday_period'] * 0.6 +  # Reduced during holidays
            X_prepared['cyber_awareness_month'] * 1.4 +  # Increased during awareness periods
            X_prepared['black_friday_proximity'] * 1.3 +  # Increased during shopping season
            X_prepared['election_period_proximity'] * 1.5  # Increased during political events
        ) / 4.0
        
        # Academic and research timing
        X_prepared['research_timing_factor'] = (
            X_prepared['academic_semester_timing'] * 0.7 +
            X_prepared['conference_season_proximity'] * 0.3
        )
        
        # Geopolitical timing correlation
        X_prepared['geopolitical_timing_risk'] = (
            X_prepared['geopolitical_tension_level'] * 
            X_prepared['seasonal_risk_weight'] * 
            X_prepared['day_risk_weight']
        )
        
        # Combined temporal risk score
        X_prepared['temporal_risk_composite'] = (
            X_prepared['seasonal_risk_weight'] * 0.2 +
            X_prepared['day_risk_weight'] * 0.15 +
            X_prepared['high_time_pressure'] * 0.25 +
            X_prepared['optimal_attack_timing'] * 0.15 +
            X_prepared['event_driven_risk'] * 0.1 +
            X_prepared['special_period_risk'] * 0.1 +
            X_prepared['temporal_decay_factor'] * 0.05
        )
        
        # Select features
        feature_columns = self.expected_features + [
            'month_sin', 'month_cos', 'day_sin', 'day_cos', 'hour_sin', 'hour_cos',
            'is_spring', 'is_summer', 'is_fall', 'is_winter',
            'seasonal_risk_weight', 'day_risk_weight', 'high_time_pressure',
            'optimal_attack_timing', 'event_driven_risk', 'temporal_decay_factor',
            'special_period_risk', 'research_timing_factor', 'geopolitical_timing_risk',
            'temporal_risk_composite'
        ]
        
        return X_prepared[feature_columns]
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'TemporalModel':
        """Train the temporal model"""
        X_prepared = self._prepare_features(X)
        
        # Handle missing values
        X_prepared = X_prepared.fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_prepared)
        
        # Apply PCA for dimensionality reduction
        X_pca = self.pca.fit_transform(X_scaled)
        
        # Train model
        self.model.fit(X_pca, y)
        
        # Store feature importance (mapped back to original features)
        pca_importance = self.model.feature_importances_
        original_importance = np.abs(self.pca.components_).T @ pca_importance
        
        self.feature_importance_ = dict(zip(
            X_prepared.columns,
            original_importance
        ))
        
        self.is_fitted = True
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Make binary predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_pca = self.pca.transform(X_scaled)
        
        return self.model.predict(X_pca)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_pca = self.pca.transform(X_scaled)
        
        return self.model.predict_proba(X_pca)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate confidence based on temporal pattern clarity
        """
        if not self.is_fitted:
            return 0.0
        
        X_prepared = self._prepare_features(X)
        
        # Confidence factors
        data_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Temporal pattern strength
        pattern_strength = np.clip(
            (X_prepared['temporal_risk_composite'] + 
             X_prepared['seasonal_risk_weight'] +
             X_prepared['event_driven_risk']) / 3.0,
            0.0, 1.0
        )
        
        # Time data quality
        time_data_quality = np.where(
            (X_prepared['days_since_disclosure'] > 0) & 
            (X_prepared['vulnerability_age_weeks'] > 0),
            1.0, 0.5
        )
        
        # Combined confidence
        confidence = (
            data_completeness * 0.4 +
            pattern_strength * 0.4 +
            time_data_quality * 0.2
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
    
    def analyze_temporal_patterns(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze temporal patterns in the vulnerability data
        """
        X_prepared = self._prepare_features(X)
        
        analysis = {
            'seasonal_distribution': {},
            'day_of_week_patterns': {},
            'time_of_day_patterns': {},
            'special_period_correlations': {},
            'timing_risk_factors': {}
        }
        
        # Seasonal distribution
        for season in ['spring', 'summer', 'fall', 'winter']:
            season_col = f'is_{season}'
            if season_col in X_prepared.columns:
                analysis['seasonal_distribution'][season] = {
                    'count': int(X_prepared[season_col].sum()),
                    'percentage': float(X_prepared[season_col].mean() * 100),
                    'average_risk_weight': float(X_prepared[X_prepared[season_col] == 1]['seasonal_risk_weight'].mean())
                }
        
        # Day of week patterns
        if 'disclosure_day_of_week' in X_prepared.columns:
            for day_idx, day_name in enumerate(['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']):
                day_mask = X_prepared['disclosure_day_of_week'] == day_idx
                analysis['day_of_week_patterns'][day_name] = {
                    'count': int(day_mask.sum()),
                    'percentage': float(day_mask.mean() * 100),
                    'risk_weight': self.day_weights[day_name]
                }
        
        # Time patterns
        if 'disclosure_hour' in X_prepared.columns:
            business_hours = (X_prepared['disclosure_hour'] >= 9) & (X_prepared['disclosure_hour'] <= 17)
            analysis['time_of_day_patterns'] = {
                'business_hours_percentage': float(business_hours.mean() * 100),
                'after_hours_percentage': float((~business_hours).mean() * 100),
                'average_disclosure_hour': float(X_prepared['disclosure_hour'].mean())
            }
        
        # Special period correlations
        special_periods = ['is_holiday_period', 'cyber_awareness_month', 'conference_season_proximity']
        for period in special_periods:
            if period in X_prepared.columns:
                analysis['special_period_correlations'][period] = float(X_prepared[period].mean())
        
        # Timing risk factors
        analysis['timing_risk_factors'] = {
            'high_time_pressure_percentage': float((X_prepared['high_time_pressure'] > 0.5).mean() * 100),
            'optimal_attack_timing_avg': float(X_prepared['optimal_attack_timing'].mean()),
            'temporal_decay_avg': float(X_prepared['temporal_decay_factor'].mean()),
            'composite_temporal_risk_avg': float(X_prepared['temporal_risk_composite'].mean())
        }
        
        return analysis
    
    def predict_optimal_timing(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Predict optimal timing for exploitation attempts
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predictions")
        
        X_prepared = self._prepare_features(X)
        
        timing_predictions = {
            'recommended_timing_windows': [],
            'seasonal_preferences': {},
            'day_preferences': {},
            'special_event_considerations': []
        }
        
        # Analyze each sample
        for idx in range(len(X_prepared)):
            sample = X_prepared.iloc[idx]
            
            # Seasonal preference
            season_scores = {
                'spring': sample['is_spring'] * self.seasonal_weights['spring'],
                'summer': sample['is_summer'] * self.seasonal_weights['summer'],
                'fall': sample['is_fall'] * self.seasonal_weights['fall'],
                'winter': sample['is_winter'] * self.seasonal_weights['winter']
            }
            preferred_season = max(season_scores.keys(), key=lambda k: season_scores[k])
            
            # Day preference
            preferred_day = max(self.day_weights.keys(), key=lambda k: self.day_weights[k])
            
            # Time window recommendation
            if sample['high_time_pressure'] > 0.5:
                window = "Immediate (high time pressure detected)"
            elif sample['optimal_attack_timing'] > 0.7:
                window = "Within 7 days (optimal timing conditions)"
            elif sample['temporal_decay_factor'] > 0.8:
                window = "Within 14 days (before temporal decay)"
            else:
                window = "Within 21 days (standard window)"
            
            timing_predictions['recommended_timing_windows'].append(window)
        
        # Aggregate preferences
        timing_predictions['seasonal_preferences'] = {
            season: float(X_prepared[f'is_{season}'].mean()) 
            for season in ['spring', 'summer', 'fall', 'winter']
        }
        
        timing_predictions['day_preferences'] = self.day_weights.copy()
        
        # Special event considerations
        if X_prepared['conference_season_proximity'].mean() > 0.5:
            timing_predictions['special_event_considerations'].append("Conference season - increased security awareness")
        
        if X_prepared['is_holiday_period'].mean() > 0.3:
            timing_predictions['special_event_considerations'].append("Holiday period - reduced monitoring")
        
        if X_prepared['cyber_awareness_month'].mean() > 0.5:
            timing_predictions['special_event_considerations'].append("Cyber awareness period - heightened vigilance")
        
        return timing_predictions
    
    def get_temporal_risk_score(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Get detailed temporal risk assessment for a sample
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        risk_assessment = {
            'overall_temporal_risk': 'LOW',
            'seasonal_factors': {},
            'timing_factors': {},
            'event_correlations': {},
            'recommendations': []
        }
        
        # Overall risk level
        composite_risk = sample['temporal_risk_composite']
        if composite_risk > 0.7:
            risk_assessment['overall_temporal_risk'] = 'HIGH'
        elif composite_risk > 0.4:
            risk_assessment['overall_temporal_risk'] = 'MEDIUM'
        
        # Seasonal factors
        risk_assessment['seasonal_factors'] = {
            'current_season_weight': float(sample['seasonal_risk_weight']),
            'seasonal_appropriateness': 'High' if sample['seasonal_risk_weight'] > 1.0 else 'Low'
        }
        
        # Timing factors
        risk_assessment['timing_factors'] = {
            'day_of_week_risk': float(sample['day_risk_weight']),
            'time_pressure_level': 'High' if sample['high_time_pressure'] > 0.5 else 'Low',
            'attack_timing_optimality': float(sample['optimal_attack_timing']),
            'vulnerability_age_factor': float(sample['temporal_decay_factor'])
        }
        
        # Event correlations
        risk_assessment['event_correlations'] = {
            'conference_proximity': float(sample['event_driven_risk']),
            'special_period_risk': float(sample['special_period_risk']),
            'geopolitical_timing': float(sample['geopolitical_timing_risk'])
        }
        
        # Recommendations
        if sample['high_time_pressure'] > 0.5:
            risk_assessment['recommendations'].append("High time pressure detected - accelerated response recommended")
        
        if sample['seasonal_risk_weight'] > 1.1:
            risk_assessment['recommendations'].append("High-risk season - increased monitoring recommended")
        
        if sample['event_driven_risk'] > 0.6:
            risk_assessment['recommendations'].append("Security event proximity - heightened awareness needed")
        
        if sample['temporal_decay_factor'] < 0.5:
            risk_assessment['recommendations'].append("Vulnerability aging - priority may be decreasing")
        
        return risk_assessment