"""
Pattern Model

Analyzes historical exploitation patterns and recognizes similar vulnerability characteristics.
Uses pattern matching and sequence analysis to predict exploitation likelihood.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.decomposition import PCA
from typing import Dict, List, Optional, Any, Tuple
import joblib
from collections import defaultdict


class PatternModel:
    """
    Pattern model that analyzes:
    - Historical exploitation patterns and sequences
    - Vulnerability characteristic clustering
    - Attack vector evolution patterns
    - Temporal exploitation sequences
    - Similar vulnerability exploitation histories
    - Attack campaign patterns
    - Exploit kit integration patterns
    - Zero-day to N-day transition patterns
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=20,
            min_samples_leaf=10,
            random_state=random_state,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.pattern_clusterer = KMeans(n_clusters=8, random_state=random_state)
        self.pca = PCA(n_components=20, random_state=random_state)
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Pattern analysis components
        self.exploitation_patterns = {}
        self.vulnerability_clusters = {}
        self.sequence_patterns = {}
        
        # Expected features for pattern analysis
        self.expected_features = [
            'cve_year', 'disclosure_month', 'vulnerability_type', 'attack_vector_type',
            'affected_software_type', 'vendor_type', 'cvss_score_range',
            'similar_cves_exploited_count', 'same_vendor_exploited_count', 'same_product_exploited_count',
            'same_vulnerability_type_exploited', 'same_attack_vector_exploited',
            'historical_exploitation_rate', 'vendor_patch_speed_history', 'product_exploitation_history',
            'zero_day_history', 'campaign_association_score', 'exploit_kit_integration_history',
            'apt_group_preference_score', 'criminal_group_preference_score',
            'exploitation_timeline_similarity', 'attack_complexity_pattern', 'payload_type_pattern',
            'persistence_method_pattern', 'lateral_movement_pattern', 'data_exfiltration_pattern',
            'geographic_targeting_pattern', 'industry_targeting_pattern', 'victim_size_pattern',
            'seasonal_exploitation_pattern', 'day_of_week_pattern', 'time_of_day_pattern'
        ]
        
        # Pattern weights for different types
        self.pattern_type_weights = {
            'temporal': 0.15,
            'technical': 0.25,
            'behavioral': 0.20,
            'targeting': 0.15,
            'similarity': 0.25
        }
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare pattern-specific features"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Historical similarity patterns
        X_prepared['historical_similarity_score'] = (
            X_prepared['similar_cves_exploited_count'] * 0.3 +
            X_prepared['same_vendor_exploited_count'] * 0.25 +
            X_prepared['same_product_exploited_count'] * 0.25 +
            X_prepared['same_vulnerability_type_exploited'] * 0.2
        )
        
        # Attack pattern consistency
        X_prepared['attack_pattern_consistency'] = (
            X_prepared['same_attack_vector_exploited'] * 0.4 +
            X_prepared['attack_complexity_pattern'] * 0.3 +
            X_prepared['payload_type_pattern'] * 0.3
        )
        
        # Exploitation timeline patterns
        X_prepared['timeline_pattern_strength'] = (
            X_prepared['exploitation_timeline_similarity'] * 0.4 +
            X_prepared['seasonal_exploitation_pattern'] * 0.3 +
            X_prepared['day_of_week_pattern'] * 0.15 +
            X_prepared['time_of_day_pattern'] * 0.15
        )
        
        # Campaign and actor patterns
        X_prepared['actor_pattern_alignment'] = (
            X_prepared['campaign_association_score'] * 0.3 +
            X_prepared['apt_group_preference_score'] * 0.35 +
            X_prepared['criminal_group_preference_score'] * 0.35
        )
        
        # Technical exploitation patterns
        X_prepared['technical_pattern_match'] = (
            X_prepared['persistence_method_pattern'] * 0.25 +
            X_prepared['lateral_movement_pattern'] * 0.25 +
            X_prepared['data_exfiltration_pattern'] * 0.25 +
            X_prepared['exploit_kit_integration_history'] * 0.25
        )
        
        # Targeting pattern consistency
        X_prepared['targeting_pattern_consistency'] = (
            X_prepared['geographic_targeting_pattern'] * 0.33 +
            X_prepared['industry_targeting_pattern'] * 0.33 +
            X_prepared['victim_size_pattern'] * 0.34
        )
        
        # Vendor and product risk patterns
        X_prepared['vendor_product_risk_pattern'] = (
            X_prepared['vendor_patch_speed_history'] * 0.4 +
            X_prepared['product_exploitation_history'] * 0.35 +
            X_prepared['zero_day_history'] * 0.25
        )
        
        # Age and maturity patterns
        current_year = 2025  # Adjust as needed
        X_prepared['vulnerability_age_pattern'] = np.clip(
            (current_year - X_prepared['cve_year']) / 10.0,  # Normalize to decades
            0, 1
        )
        
        # Seasonal and temporal encoding
        X_prepared['month_cyclical'] = np.sin(2 * np.pi * X_prepared['disclosure_month'] / 12)
        X_prepared['seasonal_risk_pattern'] = np.where(
            X_prepared['seasonal_exploitation_pattern'] > 0.5,
            X_prepared['month_cyclical'] * X_prepared['seasonal_exploitation_pattern'],
            0.0
        )
        
        # Exploitation velocity pattern
        X_prepared['exploitation_velocity_pattern'] = (
            X_prepared['historical_exploitation_rate'] * 0.6 +
            (1.0 - X_prepared['vulnerability_age_pattern']) * 0.4  # Newer vulns have higher velocity
        )
        
        # Pattern composite scores by category
        X_prepared['temporal_pattern_score'] = (
            X_prepared['timeline_pattern_strength'] * 0.6 +
            X_prepared['seasonal_risk_pattern'] * 0.4
        )
        
        X_prepared['technical_pattern_score'] = (
            X_prepared['attack_pattern_consistency'] * 0.5 +
            X_prepared['technical_pattern_match'] * 0.5
        )
        
        X_prepared['behavioral_pattern_score'] = (
            X_prepared['actor_pattern_alignment'] * 0.6 +
            X_prepared['targeting_pattern_consistency'] * 0.4
        )
        
        X_prepared['similarity_pattern_score'] = (
            X_prepared['historical_similarity_score'] * 0.7 +
            X_prepared['vendor_product_risk_pattern'] * 0.3
        )
        
        # Overall pattern recognition score
        X_prepared['pattern_recognition_composite'] = (
            X_prepared['temporal_pattern_score'] * self.pattern_type_weights['temporal'] +
            X_prepared['technical_pattern_score'] * self.pattern_type_weights['technical'] +
            X_prepared['behavioral_pattern_score'] * self.pattern_type_weights['behavioral'] +
            X_prepared['targeting_pattern_consistency'] * self.pattern_type_weights['targeting'] +
            X_prepared['similarity_pattern_score'] * self.pattern_type_weights['similarity']
        )
        
        # Pattern strength indicators
        X_prepared['strong_pattern_indicators'] = (
            (X_prepared['historical_similarity_score'] > 0.7).astype(float) * 0.3 +
            (X_prepared['actor_pattern_alignment'] > 0.6).astype(float) * 0.3 +
            (X_prepared['technical_pattern_match'] > 0.5).astype(float) * 0.4
        )
        
        # Select features
        feature_columns = self.expected_features + [
            'historical_similarity_score', 'attack_pattern_consistency', 'timeline_pattern_strength',
            'actor_pattern_alignment', 'technical_pattern_match', 'targeting_pattern_consistency',
            'vendor_product_risk_pattern', 'vulnerability_age_pattern', 'month_cyclical',
            'seasonal_risk_pattern', 'exploitation_velocity_pattern', 'temporal_pattern_score',
            'technical_pattern_score', 'behavioral_pattern_score', 'similarity_pattern_score',
            'pattern_recognition_composite', 'strong_pattern_indicators'
        ]
        
        return X_prepared[feature_columns]
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'PatternModel':
        """Train the pattern model"""
        X_prepared = self._prepare_features(X)
        
        # Handle missing values and infinities
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_prepared)
        
        # Apply PCA to reduce dimensionality while preserving patterns
        X_pca = self.pca.fit_transform(X_scaled)
        
        # Fit pattern clustering
        self.pattern_clusterer.fit(X_pca)
        
        # Add cluster features to training data
        cluster_labels = self.pattern_clusterer.predict(X_pca)
        X_with_clusters = np.column_stack([X_pca, cluster_labels])
        
        # Train main model
        self.model.fit(X_with_clusters, y)
        
        # Store feature importance (mapped back through PCA)
        pca_importance = self.model.feature_importances_[:-1]  # Exclude cluster feature
        cluster_importance = self.model.feature_importances_[-1]
        
        # Map PCA importance back to original features
        original_importance = np.abs(self.pca.components_).T @ pca_importance
        
        self.feature_importance_ = dict(zip(
            X_prepared.columns,
            original_importance
        ))
        self.feature_importance_['pattern_cluster'] = cluster_importance
        
        # Learn exploitation patterns from training data
        self._learn_exploitation_patterns(X_prepared, y, cluster_labels)
        
        self.is_fitted = True
        return self
    
    def _learn_exploitation_patterns(self, X: pd.DataFrame, y: pd.Series, clusters: np.ndarray):
        """Learn historical exploitation patterns from training data"""
        
        # Pattern analysis by cluster
        for cluster_id in np.unique(clusters):
            cluster_mask = clusters == cluster_id
            cluster_data = X[cluster_mask]
            cluster_labels = y[cluster_mask]
            
            self.exploitation_patterns[cluster_id] = {
                'exploitation_rate': float(cluster_labels.mean()),
                'sample_count': int(cluster_mask.sum()),
                'avg_similarity_score': float(cluster_data['historical_similarity_score'].mean()),
                'avg_actor_alignment': float(cluster_data['actor_pattern_alignment'].mean()),
                'avg_technical_match': float(cluster_data['technical_pattern_match'].mean()),
                'dominant_patterns': self._identify_dominant_patterns(cluster_data)
            }
        
        # Vulnerability type patterns
        if 'vulnerability_type' in X.columns:
            vuln_types = X['vulnerability_type'].unique()
            for vuln_type in vuln_types:
                type_mask = X['vulnerability_type'] == vuln_type
                type_labels = y[type_mask]
                if len(type_labels) > 5:  # Minimum sample size
                    self.vulnerability_clusters[vuln_type] = {
                        'exploitation_rate': float(type_labels.mean()),
                        'sample_count': int(type_mask.sum())
                    }
        
        # Sequence patterns (simplified)
        self.sequence_patterns = {
            'high_similarity_exploitation_rate': float(
                y[X['historical_similarity_score'] > 0.7].mean()
            ) if (X['historical_similarity_score'] > 0.7).any() else 0.0,
            'strong_actor_pattern_rate': float(
                y[X['actor_pattern_alignment'] > 0.6].mean()
            ) if (X['actor_pattern_alignment'] > 0.6).any() else 0.0,
            'consistent_technical_pattern_rate': float(
                y[X['technical_pattern_match'] > 0.5].mean()
            ) if (X['technical_pattern_match'] > 0.5).any() else 0.0
        }
    
    def _identify_dominant_patterns(self, cluster_data: pd.DataFrame) -> Dict[str, float]:
        """Identify dominant patterns within a cluster"""
        patterns = {}
        
        # Top pattern categories
        pattern_features = {
            'temporal_dominance': 'temporal_pattern_score',
            'technical_dominance': 'technical_pattern_score',
            'behavioral_dominance': 'behavioral_pattern_score',
            'similarity_dominance': 'similarity_pattern_score'
        }
        
        for pattern_name, feature in pattern_features.items():
            if feature in cluster_data.columns:
                patterns[pattern_name] = float(cluster_data[feature].mean())
        
        return patterns
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Make binary predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_pca = self.pca.transform(X_scaled)
        
        # Add cluster predictions
        cluster_labels = self.pattern_clusterer.predict(X_pca)
        X_with_clusters = np.column_stack([X_pca, cluster_labels])
        
        return self.model.predict(X_with_clusters)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_pca = self.pca.transform(X_scaled)
        
        # Add cluster predictions
        cluster_labels = self.pattern_clusterer.predict(X_pca)
        X_with_clusters = np.column_stack([X_pca, cluster_labels])
        
        return self.model.predict_proba(X_with_clusters)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate confidence based on pattern recognition strength
        """
        if not self.is_fitted:
            return 0.0
        
        X_prepared = self._prepare_features(X)
        
        # Confidence factors
        data_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Pattern strength indicators
        pattern_strength = X_prepared['strong_pattern_indicators']
        
        # Historical data availability
        historical_data_quality = (
            (X_prepared['similar_cves_exploited_count'] > 0).astype(float) * 0.3 +
            (X_prepared['historical_exploitation_rate'] > 0).astype(float) * 0.4 +
            (X_prepared['vendor_product_risk_pattern'] > 0).astype(float) * 0.3
        )
        
        # Pattern recognition score
        pattern_recognition = np.clip(
            X_prepared['pattern_recognition_composite'],
            0.0, 1.0
        )
        
        # Combined confidence
        confidence = (
            data_completeness * 0.25 +
            pattern_strength * 0.25 +
            historical_data_quality * 0.25 +
            pattern_recognition * 0.25
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
    
    def find_similar_vulnerabilities(self, X: pd.DataFrame, sample_idx: int = 0, 
                                   top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Find vulnerabilities with similar exploitation patterns
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        target_sample = X_prepared.iloc[sample_idx:sample_idx+1]
        
        # Calculate similarity scores
        similarities = []
        
        for idx in range(len(X_prepared)):
            if idx == sample_idx:
                continue
                
            comparison_sample = X_prepared.iloc[idx:idx+1]
            
            # Calculate pattern similarity
            pattern_similarity = self._calculate_pattern_similarity(target_sample, comparison_sample)
            
            similarities.append({
                'index': idx,
                'similarity_score': pattern_similarity,
                'historical_similarity': float(comparison_sample['historical_similarity_score'].iloc[0]),
                'actor_alignment': float(comparison_sample['actor_pattern_alignment'].iloc[0]),
                'technical_match': float(comparison_sample['technical_pattern_match'].iloc[0])
            })
        
        # Sort by similarity and return top K
        similarities.sort(key=lambda x: x['similarity_score'], reverse=True)
        return similarities[:top_k]
    
    def _calculate_pattern_similarity(self, sample1: pd.DataFrame, sample2: pd.DataFrame) -> float:
        """Calculate pattern similarity between two samples"""
        
        # Key pattern features for similarity calculation
        pattern_features = [
            'historical_similarity_score', 'attack_pattern_consistency',
            'actor_pattern_alignment', 'technical_pattern_match',
            'temporal_pattern_score', 'behavioral_pattern_score'
        ]
        
        similarities = []
        for feature in pattern_features:
            if feature in sample1.columns and feature in sample2.columns:
                val1 = sample1[feature].iloc[0]
                val2 = sample2[feature].iloc[0]
                
                # Calculate normalized similarity
                if val1 == 0 and val2 == 0:
                    sim = 1.0
                else:
                    sim = 1.0 - abs(val1 - val2) / (max(abs(val1), abs(val2)) + 1e-8)
                
                similarities.append(sim)
        
        return np.mean(similarities) if similarities else 0.0
    
    def analyze_exploitation_patterns(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Analyze exploitation patterns for a specific vulnerability
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        # Get cluster assignment
        X_scaled = self.scaler.transform(X_prepared.iloc[[sample_idx]])
        X_pca = self.pca.transform(X_scaled)
        cluster_id = self.pattern_clusterer.predict(X_pca)[0]
        
        pattern_analysis = {
            'pattern_cluster': int(cluster_id),
            'cluster_exploitation_rate': 0.0,
            'pattern_scores': {},
            'historical_indicators': {},
            'similarity_analysis': {},
            'pattern_strength': 'WEAK',
            'key_pattern_factors': []
        }
        
        # Cluster information
        if cluster_id in self.exploitation_patterns:
            cluster_info = self.exploitation_patterns[cluster_id]
            pattern_analysis['cluster_exploitation_rate'] = cluster_info['exploitation_rate']
            
            if cluster_info['exploitation_rate'] > 0.7:
                pattern_analysis['pattern_strength'] = 'VERY_STRONG'
            elif cluster_info['exploitation_rate'] > 0.5:
                pattern_analysis['pattern_strength'] = 'STRONG'
            elif cluster_info['exploitation_rate'] > 0.3:
                pattern_analysis['pattern_strength'] = 'MODERATE'
        
        # Pattern scores
        pattern_analysis['pattern_scores'] = {
            'temporal_pattern': float(sample['temporal_pattern_score']),
            'technical_pattern': float(sample['technical_pattern_score']),
            'behavioral_pattern': float(sample['behavioral_pattern_score']),
            'similarity_pattern': float(sample['similarity_pattern_score']),
            'overall_pattern_recognition': float(sample['pattern_recognition_composite'])
        }
        
        # Historical indicators
        pattern_analysis['historical_indicators'] = {
            'similar_cves_exploited': float(sample['similar_cves_exploited_count']),
            'same_vendor_history': float(sample['same_vendor_exploited_count']),
            'same_product_history': float(sample['same_product_exploited_count']),
            'vulnerability_type_history': float(sample['same_vulnerability_type_exploited']),
            'overall_historical_rate': float(sample['historical_exploitation_rate'])
        }
        
        # Similarity analysis
        pattern_analysis['similarity_analysis'] = {
            'historical_similarity_score': float(sample['historical_similarity_score']),
            'attack_pattern_consistency': float(sample['attack_pattern_consistency']),
            'actor_pattern_alignment': float(sample['actor_pattern_alignment']),
            'technical_pattern_match': float(sample['technical_pattern_match'])
        }
        
        # Key pattern factors
        if sample['historical_similarity_score'] > 0.7:
            pattern_analysis['key_pattern_factors'].append("High similarity to previously exploited vulnerabilities")
        
        if sample['actor_pattern_alignment'] > 0.6:
            pattern_analysis['key_pattern_factors'].append("Strong alignment with known threat actor patterns")
        
        if sample['technical_pattern_match'] > 0.5:
            pattern_analysis['key_pattern_factors'].append("Consistent technical exploitation patterns detected")
        
        if sample['vendor_product_risk_pattern'] > 0.6:
            pattern_analysis['key_pattern_factors'].append("Vendor/product has history of exploitation")
        
        if sample['exploitation_velocity_pattern'] > 0.5:
            pattern_analysis['key_pattern_factors'].append("Matches fast exploitation velocity patterns")
        
        return pattern_analysis
    
    def get_pattern_trends(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze overall pattern trends in the dataset
        """
        X_prepared = self._prepare_features(X)
        
        trends = {
            'cluster_distribution': {},
            'pattern_type_prevalence': {},
            'historical_pattern_strength': {},
            'temporal_trends': {}
        }
        
        # Cluster distribution
        if self.is_fitted:
            X_scaled = self.scaler.transform(X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0))
            X_pca = self.pca.transform(X_scaled)
            cluster_labels = self.pattern_clusterer.predict(X_pca)
            
            unique_clusters, counts = np.unique(cluster_labels, return_counts=True)
            for cluster_id, count in zip(unique_clusters, counts):
                trends['cluster_distribution'][f'cluster_{cluster_id}'] = {
                    'count': int(count),
                    'percentage': float(count / len(cluster_labels) * 100)
                }
                
                if cluster_id in self.exploitation_patterns:
                    trends['cluster_distribution'][f'cluster_{cluster_id}']['exploitation_rate'] = \
                        self.exploitation_patterns[cluster_id]['exploitation_rate']
        
        # Pattern type prevalence
        pattern_types = ['temporal_pattern_score', 'technical_pattern_score', 
                        'behavioral_pattern_score', 'similarity_pattern_score']
        
        for pattern_type in pattern_types:
            if pattern_type in X_prepared.columns:
                trends['pattern_type_prevalence'][pattern_type] = {
                    'mean_score': float(X_prepared[pattern_type].mean()),
                    'strong_pattern_percentage': float((X_prepared[pattern_type] > 0.6).mean() * 100),
                    'weak_pattern_percentage': float((X_prepared[pattern_type] < 0.3).mean() * 100)
                }
        
        # Historical pattern strength
        trends['historical_pattern_strength'] = {
            'high_similarity_rate': float((X_prepared['historical_similarity_score'] > 0.7).mean() * 100),
            'strong_actor_alignment_rate': float((X_prepared['actor_pattern_alignment'] > 0.6).mean() * 100),
            'consistent_technical_patterns': float((X_prepared['technical_pattern_match'] > 0.5).mean() * 100),
            'overall_pattern_recognition_avg': float(X_prepared['pattern_recognition_composite'].mean())
        }
        
        # Temporal trends
        if 'vulnerability_age_pattern' in X_prepared.columns:
            trends['temporal_trends'] = {
                'newer_vulnerabilities_percentage': float((X_prepared['vulnerability_age_pattern'] < 0.2).mean() * 100),
                'seasonal_pattern_strength': float(X_prepared['seasonal_risk_pattern'].mean()),
                'exploitation_velocity_avg': float(X_prepared['exploitation_velocity_pattern'].mean())
            }
        
        return trends