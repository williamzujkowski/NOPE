"""
Practicality Model

Analyzes the technical practicality and exploitation barriers for vulnerabilities.
Evaluates how feasible it is to develop and deploy exploits in real-world scenarios.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif
from typing import Dict, List, Optional, Any
import joblib


class PracticalityModel:
    """
    Practicality model that analyzes:
    - Technical difficulty and complexity barriers
    - Required expertise and resources
    - Exploitation reliability and success rates
    - Environmental constraints and prerequisites
    - Defensive countermeasures effectiveness
    - Attack surface accessibility
    - Payload development complexity
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=10,
            min_samples_split=20,
            min_samples_leaf=10,
            random_state=random_state,
            class_weight='balanced',
            bootstrap=True
        )
        self.scaler = RobustScaler()
        self.feature_selector = SelectKBest(f_classif, k=30)
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Expected features for practicality analysis
        self.expected_features = [
            'technical_difficulty_score', 'required_skill_level', 'development_time_estimate',
            'exploitation_reliability', 'success_rate_estimate', 'payload_complexity',
            'required_tools_availability', 'specialized_knowledge_needed',
            'environmental_constraints', 'network_requirements', 'system_requirements',
            'user_interaction_complexity', 'social_engineering_required',
            'multiple_stage_attack', 'persistence_difficulty', 'detection_avoidance_complexity',
            'forensic_cleanup_difficulty', 'attribution_difficulty',
            'defensive_countermeasures_present', 'waf_bypass_required', 'ids_evasion_needed',
            'antivirus_evasion_required', 'sandbox_evasion_needed',
            'exploit_portability', 'target_specificity', 'version_dependency',
            'hardware_dependency', 'architecture_dependency',
            'timing_sensitivity', 'race_condition_exploitation',
            'memory_corruption_complexity', 'code_execution_reliability',
            'privilege_escalation_difficulty', 'lateral_movement_potential'
        ]
        
        # Complexity scoring weights
        self.complexity_weights = {
            'technical': 0.25,
            'operational': 0.20,
            'environmental': 0.15,
            'defensive': 0.20,
            'reliability': 0.20
        }
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare practicality-specific features"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Technical complexity composite
        X_prepared['technical_complexity_composite'] = (
            X_prepared['technical_difficulty_score'] * 0.3 +
            X_prepared['payload_complexity'] * 0.25 +
            X_prepared['development_time_estimate'] / 100.0 * 0.2 +  # Normalize time estimate
            X_prepared['required_skill_level'] * 0.25
        )
        
        # Operational complexity
        X_prepared['operational_complexity'] = (
            X_prepared['multiple_stage_attack'] * 0.25 +
            X_prepared['user_interaction_complexity'] * 0.2 +
            X_prepared['social_engineering_required'] * 0.2 +
            X_prepared['timing_sensitivity'] * 0.15 +
            X_prepared['persistence_difficulty'] * 0.2
        )
        
        # Environmental barriers
        X_prepared['environmental_barriers'] = (
            X_prepared['environmental_constraints'] * 0.2 +
            X_prepared['network_requirements'] * 0.2 +
            X_prepared['system_requirements'] * 0.2 +
            X_prepared['hardware_dependency'] * 0.2 +
            X_prepared['architecture_dependency'] * 0.2
        )
        
        # Defensive complexity
        X_prepared['defensive_complexity'] = (
            X_prepared['defensive_countermeasures_present'] * 0.2 +
            X_prepared['waf_bypass_required'] * 0.15 +
            X_prepared['ids_evasion_needed'] * 0.15 +
            X_prepared['antivirus_evasion_required'] * 0.25 +
            X_prepared['sandbox_evasion_needed'] * 0.25
        )
        
        # Reliability factors
        X_prepared['reliability_factors'] = (
            X_prepared['exploitation_reliability'] * 0.4 +
            X_prepared['success_rate_estimate'] * 0.3 +
            X_prepared['code_execution_reliability'] * 0.3
        )
        
        # Overall practicality score (inverse - higher means less practical)
        X_prepared['practicality_barrier_score'] = (
            X_prepared['technical_complexity_composite'] * self.complexity_weights['technical'] +
            X_prepared['operational_complexity'] * self.complexity_weights['operational'] +
            X_prepared['environmental_barriers'] * self.complexity_weights['environmental'] +
            X_prepared['defensive_complexity'] * self.complexity_weights['defensive'] +
            (1.0 - X_prepared['reliability_factors']) * self.complexity_weights['reliability']
        )
        
        # Exploitation feasibility (inverse of barriers)
        X_prepared['exploitation_feasibility'] = 1.0 - X_prepared['practicality_barrier_score']
        
        # Specialized requirements complexity
        X_prepared['specialized_requirements'] = (
            X_prepared['specialized_knowledge_needed'] * 0.3 +
            X_prepared['required_tools_availability'] * 0.25 +
            X_prepared['target_specificity'] * 0.25 +
            X_prepared['version_dependency'] * 0.2
        )
        
        # Attack sophistication index
        X_prepared['attack_sophistication_index'] = (
            X_prepared['memory_corruption_complexity'] * 0.3 +
            X_prepared['race_condition_exploitation'] * 0.2 +
            X_prepared['privilege_escalation_difficulty'] * 0.25 +
            X_prepared['detection_avoidance_complexity'] * 0.25
        )
        
        # Portability and reusability
        X_prepared['exploit_reusability'] = (
            X_prepared['exploit_portability'] * 0.4 +
            (1.0 - X_prepared['target_specificity']) * 0.3 +
            (1.0 - X_prepared['version_dependency']) * 0.3
        )
        
        # Resource requirement index
        X_prepared['resource_requirement_index'] = (
            X_prepared['required_skill_level'] * 0.3 +
            X_prepared['development_time_estimate'] / 100.0 * 0.3 +
            X_prepared['specialized_requirements'] * 0.4
        )
        
        # Stealth and evasion complexity
        X_prepared['stealth_complexity'] = (
            X_prepared['detection_avoidance_complexity'] * 0.25 +
            X_prepared['forensic_cleanup_difficulty'] * 0.2 +
            X_prepared['attribution_difficulty'] * 0.15 +
            X_prepared['antivirus_evasion_required'] * 0.2 +
            X_prepared['sandbox_evasion_needed'] * 0.2
        )
        
        # Success probability composite
        X_prepared['success_probability'] = (
            X_prepared['exploitation_reliability'] * 0.4 +
            X_prepared['success_rate_estimate'] * 0.4 +
            X_prepared['code_execution_reliability'] * 0.2
        )
        
        # Select features
        feature_columns = self.expected_features + [
            'technical_complexity_composite', 'operational_complexity', 'environmental_barriers',
            'defensive_complexity', 'reliability_factors', 'practicality_barrier_score',
            'exploitation_feasibility', 'specialized_requirements', 'attack_sophistication_index',
            'exploit_reusability', 'resource_requirement_index', 'stealth_complexity',
            'success_probability'
        ]
        
        return X_prepared[feature_columns]
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'PracticalityModel':
        """Train the practicality model"""
        X_prepared = self._prepare_features(X)
        
        # Handle missing values and infinities
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_prepared)
        
        # Feature selection
        X_selected = self.feature_selector.fit_transform(X_scaled, y)
        
        # Train model
        self.model.fit(X_selected, y)
        
        # Store feature importance for selected features
        selected_features = self.feature_selector.get_support()
        selected_feature_names = X_prepared.columns[selected_features]
        
        self.feature_importance_ = dict(zip(
            selected_feature_names,
            self.model.feature_importances_
        ))
        
        # Add zero importance for non-selected features
        for feature in X_prepared.columns:
            if feature not in self.feature_importance_:
                self.feature_importance_[feature] = 0.0
        
        self.is_fitted = True
        return self
    
    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Make binary predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_selected = self.feature_selector.transform(X_scaled)
        
        return self.model.predict(X_selected)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_selected = self.feature_selector.transform(X_scaled)
        
        return self.model.predict_proba(X_selected)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate confidence based on practicality assessment quality
        """
        if not self.is_fitted:
            return 0.0
        
        X_prepared = self._prepare_features(X)
        
        # Confidence factors
        data_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Assessment quality based on key indicators
        key_indicators_available = (
            (X_prepared['technical_difficulty_score'] > 0).astype(float) * 0.25 +
            (X_prepared['exploitation_reliability'] > 0).astype(float) * 0.25 +
            (X_prepared['success_rate_estimate'] > 0).astype(float) * 0.25 +
            (X_prepared['defensive_countermeasures_present'] >= 0).astype(float) * 0.25
        )
        
        # Practicality signal strength
        signal_strength = np.clip(
            np.abs(X_prepared['exploitation_feasibility'] - 0.5) * 2,  # Distance from neutral
            0.0, 1.0
        )
        
        # Consistency check
        consistency = 1.0 - np.abs(
            X_prepared['success_probability'] - X_prepared['exploitation_feasibility']
        )
        consistency = np.clip(consistency, 0.0, 1.0)
        
        # Combined confidence
        confidence = (
            data_completeness * 0.3 +
            key_indicators_available * 0.3 +
            signal_strength * 0.2 +
            consistency * 0.2
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
    
    def analyze_practicality_barriers(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Analyze practicality barriers for a specific vulnerability
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        barriers_analysis = {
            'overall_practicality': 'UNKNOWN',
            'barrier_breakdown': {},
            'complexity_factors': {},
            'resource_requirements': {},
            'success_factors': {},
            'mitigation_factors': {},
            'recommendations': []
        }
        
        # Overall practicality assessment
        feasibility = sample['exploitation_feasibility']
        if feasibility > 0.7:
            barriers_analysis['overall_practicality'] = 'HIGH_FEASIBILITY'
        elif feasibility > 0.4:
            barriers_analysis['overall_practicality'] = 'MODERATE_FEASIBILITY'
        else:
            barriers_analysis['overall_practicality'] = 'LOW_FEASIBILITY'
        
        # Barrier breakdown
        barriers_analysis['barrier_breakdown'] = {
            'technical_complexity': float(sample['technical_complexity_composite']),
            'operational_complexity': float(sample['operational_complexity']),
            'environmental_barriers': float(sample['environmental_barriers']),
            'defensive_complexity': float(sample['defensive_complexity']),
            'reliability_concerns': float(1.0 - sample['reliability_factors'])
        }
        
        # Complexity factors
        barriers_analysis['complexity_factors'] = {
            'attack_sophistication_required': float(sample['attack_sophistication_index']),
            'specialized_knowledge_needed': float(sample['specialized_requirements']),
            'stealth_requirements': float(sample['stealth_complexity']),
            'multi_stage_complexity': float(sample.get('multiple_stage_attack', 0))
        }
        
        # Resource requirements
        barriers_analysis['resource_requirements'] = {
            'skill_level_required': float(sample['required_skill_level']),
            'development_time_estimate': float(sample['development_time_estimate']),
            'tool_availability': float(sample['required_tools_availability']),
            'overall_resource_index': float(sample['resource_requirement_index'])
        }
        
        # Success factors
        barriers_analysis['success_factors'] = {
            'exploitation_reliability': float(sample['exploitation_reliability']),
            'estimated_success_rate': float(sample['success_rate_estimate']),
            'code_execution_reliability': float(sample['code_execution_reliability']),
            'overall_success_probability': float(sample['success_probability'])
        }
        
        # Mitigation factors
        barriers_analysis['mitigation_factors'] = {
            'defensive_measures_present': float(sample['defensive_countermeasures_present']),
            'waf_protection': float(sample['waf_bypass_required']),
            'ids_protection': float(sample['ids_evasion_needed']),
            'av_protection': float(sample['antivirus_evasion_required']),
            'sandbox_protection': float(sample['sandbox_evasion_needed'])
        }
        
        # Generate recommendations
        if sample['technical_complexity_composite'] > 0.7:
            barriers_analysis['recommendations'].append("High technical complexity - specialized expertise required")
        
        if sample['defensive_complexity'] > 0.6:
            barriers_analysis['recommendations'].append("Multiple defensive layers detected - evasion techniques needed")
        
        if sample['success_probability'] < 0.4:
            barriers_analysis['recommendations'].append("Low success probability - exploitation may be unreliable")
        
        if sample['exploit_reusability'] < 0.3:
            barriers_analysis['recommendations'].append("Low exploit reusability - target-specific development needed")
        
        if sample['resource_requirement_index'] > 0.7:
            barriers_analysis['recommendations'].append("High resource requirements - significant investment needed")
        
        return barriers_analysis
    
    def assess_exploitation_difficulty(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Assess overall exploitation difficulty across all samples
        """
        X_prepared = self._prepare_features(X)
        
        difficulty_assessment = {
            'difficulty_distribution': {},
            'barrier_statistics': {},
            'complexity_trends': {},
            'feasibility_factors': {}
        }
        
        # Difficulty distribution
        feasibility_scores = X_prepared['exploitation_feasibility']
        difficulty_assessment['difficulty_distribution'] = {
            'very_easy': float((feasibility_scores > 0.8).mean() * 100),
            'easy': float(((feasibility_scores > 0.6) & (feasibility_scores <= 0.8)).mean() * 100),
            'moderate': float(((feasibility_scores > 0.4) & (feasibility_scores <= 0.6)).mean() * 100),
            'difficult': float(((feasibility_scores > 0.2) & (feasibility_scores <= 0.4)).mean() * 100),
            'very_difficult': float((feasibility_scores <= 0.2).mean() * 100)
        }
        
        # Barrier statistics
        barriers = ['technical_complexity_composite', 'operational_complexity', 
                   'environmental_barriers', 'defensive_complexity']
        for barrier in barriers:
            if barrier in X_prepared.columns:
                difficulty_assessment['barrier_statistics'][barrier] = {
                    'mean': float(X_prepared[barrier].mean()),
                    'std': float(X_prepared[barrier].std()),
                    'high_barrier_percentage': float((X_prepared[barrier] > 0.7).mean() * 100)
                }
        
        # Complexity trends
        difficulty_assessment['complexity_trends'] = {
            'average_sophistication_index': float(X_prepared['attack_sophistication_index'].mean()),
            'high_stealth_requirements': float((X_prepared['stealth_complexity'] > 0.6).mean() * 100),
            'specialized_knowledge_needed': float((X_prepared['specialized_requirements'] > 0.5).mean() * 100),
            'multi_stage_attacks': float((X_prepared.get('multiple_stage_attack', 0) > 0.5).mean() * 100)
        }
        
        # Feasibility factors
        difficulty_assessment['feasibility_factors'] = {
            'average_success_probability': float(X_prepared['success_probability'].mean()),
            'high_reliability_exploits': float((X_prepared['exploitation_reliability'] > 0.7).mean() * 100),
            'portable_exploits': float((X_prepared['exploit_reusability'] > 0.6).mean() * 100),
            'low_resource_exploits': float((X_prepared['resource_requirement_index'] < 0.4).mean() * 100)
        }
        
        return difficulty_assessment
    
    def predict_development_effort(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict development effort required (in person-days)
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predictions")
        
        X_prepared = self._prepare_features(X)
        
        # Base effort estimate
        base_effort = 5  # days
        
        # Adjust based on complexity factors
        complexity_multiplier = (
            X_prepared['technical_complexity_composite'] * 2.0 +
            X_prepared['operational_complexity'] * 1.5 +
            X_prepared['attack_sophistication_index'] * 2.5 +
            X_prepared['stealth_complexity'] * 1.8
        ) / 4.0
        
        # Adjust based on defensive requirements
        defensive_multiplier = 1.0 + X_prepared['defensive_complexity'] * 1.5
        
        # Adjust based on reliability requirements
        reliability_multiplier = 1.0 + (1.0 - X_prepared['success_probability']) * 1.0
        
        # Calculate total effort
        total_effort = (
            base_effort * 
            (1.0 + complexity_multiplier) * 
            defensive_multiplier * 
            reliability_multiplier
        )
        
        # Clamp between reasonable bounds
        total_effort = np.clip(total_effort, 1, 180)  # 1 day to 6 months
        
        return total_effort.values