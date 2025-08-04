"""
EPSS Enhanced Model

Combines CVSS scores, EPSS scores, and additional vulnerability features
to predict exploitation probability. This model serves as the baseline
and primary risk assessment component.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
from typing import Dict, List, Optional, Any
import joblib
from datetime import datetime


class EPSSEnhancedModel:
    """
    Enhanced EPSS model that combines:
    - CVSS base score and temporal metrics
    - EPSS probability scores
    - Vulnerability characteristics (CWE, attack vector, complexity)
    - Affected software ecosystem indicators
    - Patch availability and timing
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=random_state,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Expected features for this model
        self.expected_features = [
            'cvss_base_score', 'cvss_temporal_score', 'cvss_exploitability',
            'epss_score', 'epss_percentile',
            'attack_vector_network', 'attack_vector_adjacent', 'attack_vector_local', 'attack_vector_physical',
            'attack_complexity_low', 'attack_complexity_high',
            'privileges_required_none', 'privileges_required_low', 'privileges_required_high',
            'user_interaction_none', 'user_interaction_required',
            'scope_unchanged', 'scope_changed',
            'confidentiality_impact_high', 'confidentiality_impact_low', 'confidentiality_impact_none',
            'integrity_impact_high', 'integrity_impact_low', 'integrity_impact_none',
            'availability_impact_high', 'availability_impact_low', 'availability_impact_none',
            'cwe_buffer_overflow', 'cwe_sql_injection', 'cwe_xss', 'cwe_rce', 'cwe_directory_traversal',
            'vendor_count', 'product_count', 'version_count',
            'has_patch', 'patch_available_days', 'patch_complexity_low',
            'references_count', 'exploitdb_entries', 'metasploit_modules'
        ]
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare and validate features for the EPSS enhanced model"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Feature engineering
        X_prepared['cvss_epss_combined'] = (
            X_prepared['cvss_base_score'] * 0.6 + 
            X_prepared['epss_score'] * 10 * 0.4
        )
        
        X_prepared['high_impact_combo'] = (
            (X_prepared['confidentiality_impact_high'] + 
             X_prepared['integrity_impact_high'] + 
             X_prepared['availability_impact_high']) / 3
        )
        
        X_prepared['network_exploitable'] = (
            X_prepared['attack_vector_network'] * 
            X_prepared['attack_complexity_low'] *
            X_prepared['privileges_required_none']
        )
        
        X_prepared['patch_delay_risk'] = np.where(
            X_prepared['patch_available_days'] > 30, 1.0,
            np.where(X_prepared['patch_available_days'] > 0, 
                    X_prepared['patch_available_days'] / 30, 0.5)
        )
        
        # Select only the features we need
        feature_columns = self.expected_features + [
            'cvss_epss_combined', 'high_impact_combo', 
            'network_exploitable', 'patch_delay_risk'
        ]
        
        return X_prepared[feature_columns]
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'EPSSEnhancedModel':
        """Train the EPSS enhanced model"""
        X_prepared = self._prepare_features(X)
        
        # Scale features
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
        X_scaled = self.scaler.transform(X_prepared)
        return self.model.predict(X_scaled)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_scaled = self.scaler.transform(X_prepared)
        return self.model.predict_proba(X_scaled)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate prediction confidence based on:
        - Proximity to decision boundary
        - Feature quality and completeness
        - Model certainty
        """
        if not self.is_fitted:
            return 0.0
        
        probabilities = self.predict_proba(X)
        
        # Calculate confidence from probability distribution
        max_prob = np.max(probabilities, axis=1)
        confidence = 2 * np.abs(max_prob - 0.5)  # Distance from uncertainty
        
        # Adjust for feature completeness
        X_prepared = self._prepare_features(X)
        feature_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Combined confidence
        combined_confidence = confidence * feature_completeness
        
        return float(np.mean(combined_confidence))
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_fitted:
            return {}
        return self.feature_importance_.copy()
    
    def get_sklearn_model(self):
        """Get the underlying scikit-learn model for cross-validation"""
        return self.model
    
    def get_top_features(self, n: int = 10) -> List[tuple]:
        """Get top N most important features"""
        if not self.feature_importance_:
            return []
        
        sorted_features = sorted(
            self.feature_importance_.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        return sorted_features[:n]
    
    def explain_prediction(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Explain a specific prediction using feature contributions
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before explaining predictions")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        # Get prediction
        prediction_proba = self.predict_proba(X_prepared.iloc[[sample_idx]])[0]
        
        # Calculate feature contributions (simplified SHAP-like approach)
        feature_contributions = {}
        
        for feature, importance in self.feature_importance_.items():
            if feature in sample.index:
                # Normalize feature value and multiply by importance
                feature_value = sample[feature]
                contribution = feature_value * importance
                feature_contributions[feature] = contribution
        
        # Sort by absolute contribution
        sorted_contributions = sorted(
            feature_contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )
        
        return {
            'prediction_probability': prediction_proba[1],
            'prediction_class': int(prediction_proba[1] > 0.5),
            'top_positive_contributors': [
                (feat, contrib) for feat, contrib in sorted_contributions[:5] if contrib > 0
            ],
            'top_negative_contributors': [
                (feat, contrib) for feat, contrib in sorted_contributions[-5:] if contrib < 0
            ],
            'feature_values': sample.to_dict()
        }
    
    def validate_features(self, X: pd.DataFrame) -> Dict[str, Any]:
        """Validate input features and return quality metrics"""
        X_prepared = self._prepare_features(X)
        
        validation_results = {
            'total_features': len(X_prepared.columns),
            'missing_features': len([f for f in self.expected_features if f not in X.columns]),
            'feature_completeness': 1.0 - (X_prepared.isnull().sum().sum() / X_prepared.size),
            'data_quality_score': 0.0,
            'warnings': []
        }
        
        # Data quality checks
        if 'cvss_base_score' in X_prepared.columns:
            cvss_valid = ((X_prepared['cvss_base_score'] >= 0) & 
                         (X_prepared['cvss_base_score'] <= 10)).all()
            if not cvss_valid:
                validation_results['warnings'].append("CVSS scores outside valid range (0-10)")
        
        if 'epss_score' in X_prepared.columns:
            epss_valid = ((X_prepared['epss_score'] >= 0) & 
                         (X_prepared['epss_score'] <= 1)).all()
            if not epss_valid:
                validation_results['warnings'].append("EPSS scores outside valid range (0-1)")
        
        # Calculate overall data quality score
        base_score = validation_results['feature_completeness']
        if validation_results['missing_features'] == 0:
            base_score += 0.2
        if len(validation_results['warnings']) == 0:
            base_score += 0.1
        
        validation_results['data_quality_score'] = min(1.0, base_score)
        
        return validation_results