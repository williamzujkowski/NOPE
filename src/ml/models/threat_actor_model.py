"""
Threat Actor Model

Analyzes threat actor behavior, capabilities, and interest patterns.
Predicts exploitation based on threat actor profiles and historical behavior.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from typing import Dict, List, Optional, Any
import joblib


class ThreatActorModel:
    """
    Threat Actor model that analyzes:
    - Threat actor capability levels
    - Historical exploitation patterns by actor type
    - Geopolitical and financial motivations
    - Attack sophistication requirements
    - Actor-specific vulnerability preferences
    - Timing patterns and operational behaviors
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=120,
            max_depth=12,
            min_samples_split=15,
            min_samples_leaf=8,
            random_state=random_state,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.actor_clusterer = KMeans(n_clusters=5, random_state=random_state)
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Expected features for threat actor analysis
        self.expected_features = [
            'nation_state_interest', 'criminal_group_interest', 'hacktivist_interest',
            'insider_threat_potential', 'script_kiddie_accessible',
            'required_skill_level', 'required_resources_level', 'operational_complexity',
            'financial_motivation_score', 'espionage_value_score', 'disruption_value_score',
            'geopolitical_relevance', 'target_industry_attractiveness',
            'attack_attribution_difficulty', 'forensic_evasion_potential',
            'supply_chain_impact_potential', 'lateral_movement_potential',
            'persistence_mechanisms_available', 'c2_infrastructure_complexity',
            'payload_sophistication_required', 'anti_analysis_techniques',
            'zero_day_broker_interest', 'apt_campaign_alignment',
            'ransomware_potential', 'data_exfiltration_value',
            'critical_infrastructure_target', 'high_value_target_relevance'
        ]
        
        # Threat actor profiles
        self.actor_profiles = {
            'nation_state': {
                'sophistication_level': 0.9,
                'resource_availability': 0.95,
                'patience_level': 0.8,
                'stealth_requirement': 0.9,
                'target_selectivity': 0.85
            },
            'criminal_group': {
                'sophistication_level': 0.7,
                'resource_availability': 0.6,
                'patience_level': 0.4,
                'stealth_requirement': 0.6,
                'target_selectivity': 0.3
            },
            'hacktivist': {
                'sophistication_level': 0.5,
                'resource_availability': 0.4,
                'patience_level': 0.2,
                'stealth_requirement': 0.3,
                'target_selectivity': 0.7
            },
            'insider': {
                'sophistication_level': 0.3,
                'resource_availability': 0.8,
                'patience_level': 0.9,
                'stealth_requirement': 0.95,
                'target_selectivity': 0.9
            },
            'script_kiddie': {
                'sophistication_level': 0.2,
                'resource_availability': 0.2,
                'patience_level': 0.1,
                'stealth_requirement': 0.1,
                'target_selectivity': 0.1
            }
        }
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare threat actor specific features"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Threat actor feature engineering
        X_prepared['total_actor_interest'] = (
            X_prepared['nation_state_interest'] * 0.3 +
            X_prepared['criminal_group_interest'] * 0.25 +
            X_prepared['hacktivist_interest'] * 0.2 +
            X_prepared['insider_threat_potential'] * 0.15 +
            X_prepared['script_kiddie_accessible'] * 0.1
        )
        
        X_prepared['sophistication_barrier'] = (
            X_prepared['required_skill_level'] * 0.4 +
            X_prepared['required_resources_level'] * 0.3 +
            X_prepared['operational_complexity'] * 0.3
        )
        
        X_prepared['motivation_alignment'] = (
            X_prepared['financial_motivation_score'] * 0.35 +
            X_prepared['espionage_value_score'] * 0.35 +
            X_prepared['disruption_value_score'] * 0.3
        )
        
        X_prepared['stealth_capability_match'] = (
            X_prepared['attack_attribution_difficulty'] * 0.5 +
            X_prepared['forensic_evasion_potential'] * 0.5
        )
        
        X_prepared['high_value_target_score'] = (
            X_prepared['critical_infrastructure_target'] * 0.4 +
            X_prepared['high_value_target_relevance'] * 0.3 +
            X_prepared['supply_chain_impact_potential'] * 0.3
        )
        
        # Actor-specific capability scores
        for actor_type, profile in self.actor_profiles.items():
            capability_match = 0.0
            
            if actor_type == 'nation_state':
                capability_match = (
                    X_prepared['nation_state_interest'] * profile['sophistication_level'] +
                    X_prepared['geopolitical_relevance'] * profile['target_selectivity'] +
                    X_prepared['stealth_capability_match'] * profile['stealth_requirement']
                ) / 3.0
            elif actor_type == 'criminal_group':
                capability_match = (
                    X_prepared['criminal_group_interest'] * profile['sophistication_level'] +
                    X_prepared['financial_motivation_score'] * 0.8 +
                    X_prepared['ransomware_potential'] * 0.7
                ) / 3.0
            elif actor_type == 'hacktivist':
                capability_match = (
                    X_prepared['hacktivist_interest'] * profile['sophistication_level'] +
                    X_prepared['disruption_value_score'] * 0.8 +
                    (1.0 - X_prepared['sophistication_barrier']) * 0.6
                ) / 3.0
            elif actor_type == 'insider':
                capability_match = (
                    X_prepared['insider_threat_potential'] * profile['sophistication_level'] +
                    X_prepared['lateral_movement_potential'] * profile['resource_availability'] +
                    X_prepared['persistence_mechanisms_available'] * profile['patience_level']
                ) / 3.0
            elif actor_type == 'script_kiddie':
                capability_match = (
                    X_prepared['script_kiddie_accessible'] * (1.0 - profile['sophistication_level']) +
                    (1.0 - X_prepared['sophistication_barrier']) * 0.8 +
                    X_prepared['payload_sophistication_required'] * 0.2  # Inverse relationship
                ) / 3.0
            
            X_prepared[f'{actor_type}_capability_match'] = capability_match
        
        # Market and ecosystem factors
        X_prepared['underground_market_appeal'] = (
            X_prepared['zero_day_broker_interest'] * 0.6 +
            X_prepared['data_exfiltration_value'] * 0.4
        )
        
        X_prepared['campaign_alignment_score'] = (
            X_prepared['apt_campaign_alignment'] * 0.7 +
            X_prepared['target_industry_attractiveness'] * 0.3
        )
        
        # Select features
        feature_columns = self.expected_features + [
            'total_actor_interest', 'sophistication_barrier', 'motivation_alignment',
            'stealth_capability_match', 'high_value_target_score', 'underground_market_appeal',
            'campaign_alignment_score'
        ]
        
        # Add actor capability matches
        for actor_type in self.actor_profiles.keys():
            feature_columns.append(f'{actor_type}_capability_match')
        
        return X_prepared[feature_columns]
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'ThreatActorModel':
        """Train the threat actor model"""
        X_prepared = self._prepare_features(X)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_prepared)
        
        # Fit actor clustering (unsupervised)
        self.actor_clusterer.fit(X_scaled)
        
        # Add cluster features
        cluster_features = self.actor_clusterer.predict(X_scaled)
        X_with_clusters = np.column_stack([X_scaled, cluster_features])
        
        # Train main model
        self.model.fit(X_with_clusters, y)
        
        # Store feature importance
        feature_names = list(X_prepared.columns) + ['actor_cluster']
        self.feature_importance_ = dict(zip(
            feature_names,
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
        cluster_features = self.actor_clusterer.predict(X_scaled)
        X_with_clusters = np.column_stack([X_scaled, cluster_features])
        
        return self.model.predict(X_with_clusters)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_scaled = self.scaler.transform(X_prepared)
        cluster_features = self.actor_clusterer.predict(X_scaled)
        X_with_clusters = np.column_stack([X_scaled, cluster_features])
        
        return self.model.predict_proba(X_with_clusters)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate confidence based on threat actor intelligence quality
        """
        if not self.is_fitted:
            return 0.0
        
        X_prepared = self._prepare_features(X)
        
        # Confidence factors
        data_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Intelligence quality indicators
        intelligence_quality = np.clip(
            (X_prepared['total_actor_interest'] + 
             X_prepared['motivation_alignment'] +
             X_prepared['campaign_alignment_score']) / 3.0,
            0.0, 1.0
        )
        
        # Actor clustering confidence (distance to cluster center)
        X_scaled = self.scaler.transform(X_prepared)
        cluster_distances = self.actor_clusterer.transform(X_scaled)
        min_distances = np.min(cluster_distances, axis=1)
        max_distance = np.max(self.actor_clusterer.transform(self.scaler.transform(X_prepared)))
        cluster_confidence = 1.0 - (min_distances / max_distance)
        
        # Combined confidence
        confidence = (
            data_completeness * 0.4 +
            intelligence_quality * 0.4 +
            cluster_confidence * 0.2
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
    
    def analyze_threat_actor_profile(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Analyze threat actor profile for a specific vulnerability
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        # Determine most likely actor types
        actor_scores = {}
        for actor_type in self.actor_profiles.keys():
            capability_feature = f'{actor_type}_capability_match'
            if capability_feature in sample.index:
                actor_scores[actor_type] = sample[capability_feature]
        
        # Sort by score
        sorted_actors = sorted(actor_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Get cluster assignment
        X_scaled = self.scaler.transform(X_prepared.iloc[[sample_idx]])
        cluster = self.actor_clusterer.predict(X_scaled)[0]
        
        profile = {
            'most_likely_actor_types': sorted_actors[:3],
            'actor_cluster': int(cluster),
            'sophistication_requirement': float(sample['sophistication_barrier']),
            'motivation_alignment': float(sample['motivation_alignment']),
            'stealth_capability_needed': float(sample['stealth_capability_match']),
            'high_value_target_attractiveness': float(sample['high_value_target_score']),
            'underground_market_appeal': float(sample['underground_market_appeal']),
            'risk_factors': []
        }
        
        # Identify risk factors
        if sample['nation_state_interest'] > 0.7:
            profile['risk_factors'].append("High nation-state interest detected")
        
        if sample['criminal_group_interest'] > 0.6:
            profile['risk_factors'].append("Strong criminal group interest")
        
        if sample['zero_day_broker_interest'] > 0.5:
            profile['risk_factors'].append("Zero-day broker interest present")
        
        if sample['apt_campaign_alignment'] > 0.6:
            profile['risk_factors'].append("Aligns with known APT campaign patterns")
        
        if sample['critical_infrastructure_target'] > 0.7:
            profile['risk_factors'].append("Critical infrastructure targeting potential")
        
        return profile
    
    def predict_actor_attribution(self, X: pd.DataFrame) -> Dict[str, List[str]]:
        """
        Predict most likely threat actor types for vulnerabilities
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predictions")
        
        X_prepared = self._prepare_features(X)
        attributions = {}
        
        for idx in range(len(X_prepared)):
            sample = X_prepared.iloc[idx]
            
            # Calculate scores for each actor type
            actor_scores = {}
            for actor_type in self.actor_profiles.keys():
                capability_feature = f'{actor_type}_capability_match'
                if capability_feature in sample.index:
                    actor_scores[actor_type] = sample[capability_feature]
            
            # Sort and get top actors
            sorted_actors = sorted(actor_scores.items(), key=lambda x: x[1], reverse=True)
            top_actors = [actor for actor, score in sorted_actors if score > 0.3][:3]
            
            vuln_id = f"vuln_{idx}"
            if 'vulnerability_id' in X.columns:
                vuln_id = str(X.iloc[idx]['vulnerability_id'])
            
            attributions[vuln_id] = top_actors
        
        return attributions
    
    def get_actor_targeting_trends(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze targeting trends across different actor types
        """
        X_prepared = self._prepare_features(X)
        
        trends = {
            'actor_interest_distribution': {},
            'sophistication_trends': {},
            'motivation_patterns': {},
            'target_preferences': {}
        }
        
        # Actor interest distribution
        for actor_type in self.actor_profiles.keys():
            interest_col = f'{actor_type}_interest'
            if interest_col in X_prepared.columns:
                trends['actor_interest_distribution'][actor_type] = {
                    'mean_interest': float(X_prepared[interest_col].mean()),
                    'high_interest_count': int((X_prepared[interest_col] > 0.6).sum()),
                    'percentage_interested': float((X_prepared[interest_col] > 0.3).mean() * 100)
                }
        
        # Sophistication trends
        trends['sophistication_trends'] = {
            'average_required_skill': float(X_prepared['required_skill_level'].mean()),
            'high_complexity_percentage': float((X_prepared['sophistication_barrier'] > 0.7).mean() * 100),
            'low_skill_accessible_percentage': float((X_prepared['script_kiddie_accessible'] > 0.5).mean() * 100)
        }
        
        # Motivation patterns
        trends['motivation_patterns'] = {
            'financial_motivation_avg': float(X_prepared['financial_motivation_score'].mean()),
            'espionage_value_avg': float(X_prepared['espionage_value_score'].mean()),
            'disruption_value_avg': float(X_prepared['disruption_value_score'].mean())
        }
        
        # Target preferences
        trends['target_preferences'] = {
            'critical_infrastructure_targeting': float((X_prepared['critical_infrastructure_target'] > 0.5).mean() * 100),
            'high_value_target_preference': float((X_prepared['high_value_target_relevance'] > 0.6).mean() * 100),
            'supply_chain_potential': float((X_prepared['supply_chain_impact_potential'] > 0.5).mean() * 100)
        }
        
        return trends