"""
Model Utilities

Utilities for model versioning, validation, and management.
"""

import os
import json
import pickle
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, precision_recall_curve, classification_report
from loguru import logger


class ModelVersionManager:
    """
    Manages model versioning, persistence, and metadata tracking
    """
    
    def __init__(self, model_dir: str):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.model_dir / "model_registry.json"
        self.load_registry()
    
    def load_registry(self):
        """Load model registry from disk"""
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r') as f:
                self.registry = json.load(f)
        else:
            self.registry = {
                'models': {},
                'ensembles': {},
                'created_at': datetime.now().isoformat()
            }
    
    def save_registry(self):
        """Save model registry to disk"""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.registry, f, indent=2, default=str)
    
    def register_model(self, model_name: str, model_path: str, 
                      metadata: Dict[str, Any]) -> str:
        """
        Register a new model version
        
        Args:
            model_name: Name of the model
            model_path: Path to the saved model file
            metadata: Model metadata (performance, training info, etc.)
            
        Returns:
            Version ID of the registered model
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        version_id = f"{model_name}_v{timestamp}"
        
        # Calculate model hash for integrity checking
        model_hash = self._calculate_file_hash(model_path)
        
        model_info = {
            'version_id': version_id,
            'model_name': model_name,
            'model_path': model_path,
            'model_hash': model_hash,
            'created_at': datetime.now().isoformat(),
            'metadata': metadata
        }
        
        if model_name not in self.registry['models']:
            self.registry['models'][model_name] = []
        
        self.registry['models'][model_name].append(model_info)
        self.save_registry()
        
        logger.info(f"Registered model {version_id}")
        return version_id
    
    def register_ensemble(self, ensemble_name: str, model_versions: Dict[str, str],
                         ensemble_metadata: Dict[str, Any]) -> str:
        """
        Register an ensemble configuration
        
        Args:
            ensemble_name: Name of the ensemble
            model_versions: Dictionary mapping model names to version IDs
            ensemble_metadata: Ensemble performance and configuration data
            
        Returns:
            Ensemble version ID
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ensemble_version = f"{ensemble_name}_v{timestamp}"
        
        ensemble_info = {
            'ensemble_version': ensemble_version,
            'ensemble_name': ensemble_name,
            'model_versions': model_versions,
            'created_at': datetime.now().isoformat(),
            'metadata': ensemble_metadata
        }
        
        if ensemble_name not in self.registry['ensembles']:
            self.registry['ensembles'][ensemble_name] = []
        
        self.registry['ensembles'][ensemble_name].append(ensemble_info)
        self.save_registry()
        
        logger.info(f"Registered ensemble {ensemble_version}")
        return ensemble_version
    
    def get_latest_model(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get the latest version of a model"""
        if model_name not in self.registry['models']:
            return None
        
        models = self.registry['models'][model_name]
        if not models:
            return None
        
        # Sort by creation time and return latest
        latest = sorted(models, key=lambda x: x['created_at'])[-1]
        return latest
    
    def get_latest_ensemble(self, ensemble_name: str) -> Optional[Dict[str, Any]]:
        """Get the latest version of an ensemble"""
        if ensemble_name not in self.registry['ensembles']:
            return None
            
        ensembles = self.registry['ensembles'][ensemble_name]
        if not ensembles:
            return None
        
        latest = sorted(ensembles, key=lambda x: x['created_at'])[-1]
        return latest
    
    def get_model_performance_history(self, model_name: str) -> List[Dict[str, Any]]:
        """Get performance history for a model"""
        if model_name not in self.registry['models']:
            return []
        
        history = []
        for model_info in self.registry['models'][model_name]:
            metadata = model_info['metadata']
            history.append({
                'version_id': model_info['version_id'],
                'created_at': model_info['created_at'],
                'performance': metadata.get('performance_metrics', {}),
                'training_samples': metadata.get('training_samples', 0),
                'validation_auc': metadata.get('validation_auc', 0)
            })
        
        return sorted(history, key=lambda x: x['created_at'])
    
    def cleanup_old_versions(self, model_name: str, keep_versions: int = 5):
        """Clean up old model versions, keeping only the most recent"""
        if model_name not in self.registry['models']:
            return
        
        models = self.registry['models'][model_name]
        if len(models) <= keep_versions:
            return
        
        # Sort by creation time and keep only recent versions
        sorted_models = sorted(models, key=lambda x: x['created_at'])
        models_to_remove = sorted_models[:-keep_versions]
        
        for model_info in models_to_remove:
            # Remove model file
            model_path = Path(model_info['model_path'])
            if model_path.exists():
                model_path.unlink()
                logger.info(f"Removed old model file: {model_path}")
        
        # Update registry
        self.registry['models'][model_name] = sorted_models[-keep_versions:]
        self.save_registry()
        
        logger.info(f"Cleaned up {len(models_to_remove)} old versions of {model_name}")
    
    def verify_model_integrity(self, model_name: str, version_id: str = None) -> bool:
        """Verify model file integrity using stored hash"""
        if version_id:
            model_info = self._get_model_by_version(model_name, version_id)
        else:
            model_info = self.get_latest_model(model_name)
        
        if not model_info:
            return False
        
        model_path = Path(model_info['model_path'])
        if not model_path.exists():
            return False
        
        current_hash = self._calculate_file_hash(model_path)
        stored_hash = model_info['model_hash']
        
        return current_hash == stored_hash
    
    def _get_model_by_version(self, model_name: str, version_id: str) -> Optional[Dict[str, Any]]:
        """Get model info by specific version ID"""
        if model_name not in self.registry['models']:
            return None
        
        for model_info in self.registry['models'][model_name]:
            if model_info['version_id'] == version_id:
                return model_info
        
        return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def export_model_info(self, model_name: str, version_id: str = None) -> Dict[str, Any]:
        """Export complete model information for backup/transfer"""
        if version_id:
            model_info = self._get_model_by_version(model_name, version_id)
        else:
            model_info = self.get_latest_model(model_name)
        
        if not model_info:
            return {}
        
        # Include model file contents (base64 encoded for JSON serialization)
        model_path = Path(model_info['model_path'])
        if model_path.exists():
            import base64
            with open(model_path, 'rb') as f:
                model_data = base64.b64encode(f.read()).decode('utf-8')
            
            export_data = model_info.copy()
            export_data['model_data'] = model_data
            return export_data
        
        return model_info


class ModelValidation:
    """
    Model validation and performance assessment utilities
    """
    
    def __init__(self, target_metrics: Dict[str, float] = None):
        self.target_metrics = target_metrics or {
            'min_auc': 0.85,
            'min_precision': 0.80,
            'min_recall': 0.75,
            'max_false_positive_rate': 0.15
        }
    
    def validate_model_performance(self, y_true: np.ndarray, y_pred_proba: np.ndarray,
                                 y_pred: np.ndarray = None) -> Dict[str, Any]:
        """
        Comprehensive model performance validation
        
        Args:
            y_true: True labels
            y_pred_proba: Predicted probabilities
            y_pred: Predicted binary labels (optional)
            
        Returns:
            Validation results with pass/fail status
        """
        results = {
            'passed': False,
            'metrics': {},
            'failures': [],
            'warnings': []
        }
        
        # Calculate AUC
        try:
            auc = roc_auc_score(y_true, y_pred_proba)
            results['metrics']['auc'] = auc
            
            if auc < self.target_metrics['min_auc']:
                results['failures'].append(f"AUC {auc:.3f} below minimum {self.target_metrics['min_auc']}")
        except Exception as e:
            results['failures'].append(f"Failed to calculate AUC: {e}")
        
        # Calculate precision-recall metrics
        try:
            precision, recall, thresholds = precision_recall_curve(y_true, y_pred_proba)
            
            # Find optimal threshold
            f1_scores = 2 * (precision * recall) / (precision + recall + 1e-8)
            best_idx = np.argmax(f1_scores)
            best_threshold = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
            best_precision = precision[best_idx]
            best_recall = recall[best_idx]
            
            results['metrics']['best_threshold'] = best_threshold
            results['metrics']['precision'] = best_precision
            results['metrics']['recall'] = best_recall
            results['metrics']['f1_score'] = f1_scores[best_idx]
            
            # Check thresholds
            if best_precision < self.target_metrics['min_precision']:
                results['failures'].append(f"Precision {best_precision:.3f} below minimum {self.target_metrics['min_precision']}")
            
            if best_recall < self.target_metrics['min_recall']:
                results['failures'].append(f"Recall {best_recall:.3f} below minimum {self.target_metrics['min_recall']}")
                
        except Exception as e:
            results['failures'].append(f"Failed to calculate precision-recall: {e}")
        
        # Binary classification metrics if predictions provided
        if y_pred is not None:
            try:
                class_report = classification_report(y_true, y_pred, output_dict=True)
                results['metrics']['classification_report'] = class_report
                
                # False positive rate
                tn = class_report['0']['support'] * class_report['0']['recall']
                fp = class_report['0']['support'] - tn
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
                
                results['metrics']['false_positive_rate'] = fpr
                
                if fpr > self.target_metrics['max_false_positive_rate']:
                    results['failures'].append(f"False positive rate {fpr:.3f} above maximum {self.target_metrics['max_false_positive_rate']}")
                    
            except Exception as e:
                results['warnings'].append(f"Failed to calculate classification metrics: {e}")
        
        # Overall validation result
        results['passed'] = len(results['failures']) == 0
        
        return results
    
    def validate_ensemble_consistency(self, individual_predictions: Dict[str, np.ndarray],
                                    ensemble_prediction: np.ndarray) -> Dict[str, Any]:
        """
        Validate consistency between individual models and ensemble
        
        Args:
            individual_predictions: Dictionary of model name to predictions
            ensemble_prediction: Ensemble prediction array
            
        Returns:
            Consistency validation results
        """
        results = {
            'passed': True,
            'consistency_score': 0.0,
            'outlier_models': [],
            'warnings': []
        }
        
        if len(individual_predictions) < 2:
            results['warnings'].append("Cannot validate consistency with less than 2 models")
            return results
        
        try:
            # Calculate correlation between each model and ensemble
            correlations = {}
            for model_name, predictions in individual_predictions.items():
                if len(predictions) == len(ensemble_prediction):
                    corr = np.corrcoef(predictions, ensemble_prediction)[0, 1]
                    correlations[model_name] = corr
                else:
                    results['warnings'].append(f"Model {model_name} has mismatched prediction length")
            
            if correlations:
                avg_correlation = np.mean(list(correlations.values()))
                results['consistency_score'] = avg_correlation
                
                # Identify outlier models (low correlation with ensemble)
                correlation_threshold = 0.6
                for model_name, corr in correlations.items():
                    if corr < correlation_threshold:
                        results['outlier_models'].append({
                            'model': model_name,
                            'correlation': corr
                        })
                
                # Check if overall consistency is acceptable
                if avg_correlation < 0.7:
                    results['passed'] = False
                    results['warnings'].append(f"Low ensemble consistency: {avg_correlation:.3f}")
            
        except Exception as e:
            results['passed'] = False
            results['warnings'].append(f"Consistency validation failed: {e}")
        
        return results
    
    def validate_data_quality(self, X: pd.DataFrame, y: pd.Series = None) -> Dict[str, Any]:
        """
        Validate training/prediction data quality
        
        Args:
            X: Feature data
            y: Labels (optional)
            
        Returns:
            Data quality validation results
        """
        results = {
            'passed': True,
            'issues': [],
            'warnings': [],
            'statistics': {}
        }
        
        # Basic data checks
        if X.empty:
            results['passed'] = False
            results['issues'].append("Empty feature data")
            return results
        
        # Missing values check
        missing_ratio = X.isnull().sum().sum() / (X.shape[0] * X.shape[1])
        results['statistics']['missing_ratio'] = missing_ratio
        
        if missing_ratio > 0.3:
            results['passed'] = False
            results['issues'].append(f"High missing value ratio: {missing_ratio:.3f}")
        elif missing_ratio > 0.1:
            results['warnings'].append(f"Moderate missing values: {missing_ratio:.3f}")
        
        # Feature variance check
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        if len(numeric_columns) > 0:
            zero_variance_features = []
            for col in numeric_columns:
                if X[col].var() == 0:
                    zero_variance_features.append(col)
            
            if zero_variance_features:
                results['warnings'].append(f"Zero variance features: {len(zero_variance_features)}")
                results['statistics']['zero_variance_features'] = zero_variance_features
        
        # Infinite values check
        inf_count = np.isinf(X.select_dtypes(include=[np.number])).sum().sum()
        if inf_count > 0:
            results['passed'] = False
            results['issues'].append(f"Infinite values detected: {inf_count}")
        
        # Label distribution check (if labels provided)
        if y is not None:
            unique_labels = y.nunique()
            if unique_labels < 2:
                results['passed'] = False
                results['issues'].append("Insufficient label diversity")
            
            # Class imbalance check
            label_counts = y.value_counts()
            if unique_labels == 2:
                minority_ratio = label_counts.min() / label_counts.sum()
                results['statistics']['minority_class_ratio'] = minority_ratio
                
                if minority_ratio < 0.1:
                    results['warnings'].append(f"Severe class imbalance: {minority_ratio:.3f}")
                elif minority_ratio < 0.2:
                    results['warnings'].append(f"Moderate class imbalance: {minority_ratio:.3f}")
        
        # Feature correlation check
        if len(numeric_columns) > 1:
            corr_matrix = X[numeric_columns].corr()
            high_corr_pairs = []
            
            for i in range(len(corr_matrix.columns)):
                for j in range(i+1, len(corr_matrix.columns)):
                    corr_val = abs(corr_matrix.iloc[i, j])
                    if corr_val > 0.95:
                        high_corr_pairs.append((
                            corr_matrix.columns[i],
                            corr_matrix.columns[j],
                            corr_val
                        ))
            
            if high_corr_pairs:
                results['warnings'].append(f"High correlation feature pairs: {len(high_corr_pairs)}")
                results['statistics']['high_correlation_pairs'] = high_corr_pairs[:5]  # Top 5
        
        results['statistics']['shape'] = X.shape
        results['statistics']['feature_count'] = X.shape[1]
        results['statistics']['sample_count'] = X.shape[0]
        
        return results
    
    def generate_validation_report(self, validation_results: List[Dict[str, Any]]) -> str:
        """
        Generate a comprehensive validation report
        
        Args:
            validation_results: List of validation result dictionaries
            
        Returns:
            Formatted validation report string
        """
        report = []
        report.append("=" * 50)
        report.append("MODEL VALIDATION REPORT")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        for i, result in enumerate(validation_results, 1):
            report.append(f"Validation {i}:")
            report.append("-" * 20)
            
            if 'passed' in result:
                status = "PASSED" if result['passed'] else "FAILED"
                report.append(f"Status: {status}")
            
            if 'metrics' in result:
                report.append("Metrics:")
                for metric, value in result['metrics'].items():
                    if isinstance(value, (int, float)):
                        report.append(f"  {metric}: {value:.4f}")
                    else:
                        report.append(f"  {metric}: {value}")
            
            if 'failures' in result and result['failures']:
                report.append("Failures:")
                for failure in result['failures']:
                    report.append(f"  - {failure}")
            
            if 'warnings' in result and result['warnings']:
                report.append("Warnings:")
                for warning in result['warnings']:
                    report.append(f"  - {warning}")
            
            report.append("")
        
        return "\n".join(report)