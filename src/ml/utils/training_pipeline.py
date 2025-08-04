"""
Training Pipeline

Comprehensive training pipeline for the ML ensemble system.
Handles data preprocessing, model training, validation, and orchestration.
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import joblib
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.preprocessing import StandardScaler
from loguru import logger
import matplotlib.pyplot as plt
import seaborn as sns

from .model_utils import ModelVersionManager, ModelValidation
from ..features.feature_extractor import FeatureExtractor


class TrainingPipeline:
    """
    Complete training pipeline for the ML ensemble system
    
    Handles:
    - Data preprocessing and validation
    - Individual model training
    - Ensemble weight optimization
    - Performance validation
    - Model persistence and versioning
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._get_default_config()
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.model_manager = ModelVersionManager(self.config['model_dir'])
        self.validator = ModelValidation(self.config.get('target_metrics', {}))
        
        # Training state
        self.training_data = None
        self.validation_data = None
        self.test_data = None
        self.models = {}
        self.training_history = {}
        
        # Setup logging
        self._setup_logging()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default training configuration"""
        return {
            'model_dir': 'data/models',
            'log_dir': 'logs',
            'random_state': 42,
            'test_size': 0.2,
            'validation_size': 0.2,
            'cv_folds': 5,
            'target_metrics': {
                'min_auc': 0.85,
                'min_precision': 0.80,
                'min_recall': 0.75,
                'max_false_positive_rate': 0.15
            },
            'early_stopping': {
                'enabled': True,
                'patience': 10,
                'min_delta': 0.001
            },
            'ensemble_optimization': {
                'method': 'bayesian',  # 'grid_search', 'random_search', 'bayesian'
                'n_trials': 100
            },
            'model_selection': {
                'strategy': 'best_cv',  # 'best_cv', 'ensemble_all', 'threshold_based'
                'threshold': 0.8
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_dir = Path(self.config['log_dir'])
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logger.add(log_file, level="INFO", rotation="10 MB")
    
    def load_training_data(self, data_path: str = None, data: pd.DataFrame = None,
                          target_column: str = 'exploited') -> Dict[str, Any]:
        """
        Load and preprocess training data
        
        Args:
            data_path: Path to training data file
            data: DataFrame with training data (alternative to file path)
            target_column: Name of the target column
            
        Returns:
            Data loading results and statistics
        """
        logger.info("Loading training data...")
        
        # Load data
        if data is not None:
            df = data.copy()
        elif data_path:
            if not Path(data_path).exists():
                raise FileNotFoundError(f"Training data not found: {data_path}")
            
            if data_path.endswith('.csv'):
                df = pd.read_csv(data_path)
            elif data_path.endswith('.json'):
                df = pd.read_json(data_path)
            elif data_path.endswith('.parquet'):
                df = pd.read_parquet(data_path)
            else:
                raise ValueError(f"Unsupported file format: {data_path}")
        else:
            raise ValueError("Either data_path or data must be provided")
        
        logger.info(f"Loaded {len(df)} samples with {len(df.columns)} columns")
        
        # Validate data
        if target_column not in df.columns:
            raise ValueError(f"Target column '{target_column}' not found in data")
        
        # Data quality validation
        validation_results = self.validator.validate_data_quality(
            df.drop(columns=[target_column]), 
            df[target_column]
        )
        
        if not validation_results['passed']:
            logger.error("Data quality validation failed:")
            for issue in validation_results['issues']:
                logger.error(f"  - {issue}")
            raise ValueError("Data quality validation failed")
        
        if validation_results['warnings']:
            logger.warning("Data quality warnings:")
            for warning in validation_results['warnings']:
                logger.warning(f"  - {warning}")
        
        # Split data
        X = df.drop(columns=[target_column])
        y = df[target_column]
        
        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config['test_size'],
            random_state=self.config['random_state'],
            stratify=y
        )
        
        # Train/validation split
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train, test_size=self.config['validation_size'],
            random_state=self.config['random_state'],
            stratify=y_train
        )
        
        # Store data
        self.training_data = (X_train, y_train)
        self.validation_data = (X_val, y_val)
        self.test_data = (X_test, y_test)
        
        # Calculate statistics
        stats = {
            'total_samples': len(df),
            'training_samples': len(X_train),
            'validation_samples': len(X_val),
            'test_samples': len(X_test),
            'feature_count': X.shape[1],
            'positive_class_ratio': y.mean(),
            'data_quality': validation_results
        }
        
        logger.info(f"Data split: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
        logger.info(f"Positive class ratio: {stats['positive_class_ratio']:.3f}")
        
        return stats
    
    def train_individual_models(self, models_to_train: List[str] = None) -> Dict[str, Any]:
        """
        Train individual models in the ensemble
        
        Args:
            models_to_train: List of model names to train (default: all)
            
        Returns:
            Training results for each model
        """
        if self.training_data is None:
            raise RuntimeError("Training data not loaded. Call load_training_data() first.")
        
        X_train, y_train = self.training_data
        X_val, y_val = self.validation_data
        
        # Import models
        from ..models.epss_enhanced_model import EPSSEnhancedModel
        from ..models.velocity_model import VelocityModel
        from ..models.threat_actor_model import ThreatActorModel
        from ..models.temporal_model import TemporalModel
        from ..models.practicality_model import PracticalityModel
        from ..models.community_model import CommunityModel
        from ..models.pattern_model import PatternModel
        
        # Available models
        available_models = {
            'epss_enhanced': EPSSEnhancedModel,
            'velocity': VelocityModel,
            'threat_actor': ThreatActorModel,
            'temporal': TemporalModel,
            'practicality': PracticalityModel,
            'community': CommunityModel,
            'pattern': PatternModel
        }
        
        # Determine which models to train
        if models_to_train is None:
            models_to_train = list(available_models.keys())
        
        logger.info(f"Training {len(models_to_train)} models: {models_to_train}")
        
        training_results = {}
        
        for model_name in models_to_train:
            if model_name not in available_models:
                logger.warning(f"Unknown model: {model_name}")
                continue
            
            logger.info(f"Training {model_name} model...")
            
            try:
                # Initialize model
                model_class = available_models[model_name]
                model = model_class(random_state=self.config['random_state'])
                
                # Train model
                start_time = datetime.now()
                model.fit(X_train, y_train)
                training_time = (datetime.now() - start_time).total_seconds()
                
                # Validation
                val_predictions = model.predict_proba(X_val)[:, 1]
                val_auc = roc_auc_score(y_val, val_predictions)
                
                # Cross-validation
                cv_scores = cross_val_score(
                    model.get_sklearn_model(), X_train, y_train,
                    cv=self.config['cv_folds'], scoring='roc_auc'
                )
                
                # Model validation
                validation_results = self.validator.validate_model_performance(
                    y_val, val_predictions
                )
                
                # Store model and results
                self.models[model_name] = model
                
                training_results[model_name] = {
                    'validation_auc': val_auc,
                    'cv_mean_auc': cv_scores.mean(),
                    'cv_std_auc': cv_scores.std(),
                    'training_time_seconds': training_time,
                    'validation_passed': validation_results['passed'],
                    'validation_results': validation_results,
                    'feature_importance': model.get_feature_importance(),
                    'model_confidence': model.get_confidence(X_val)
                }
                
                logger.info(f"{model_name} - Val AUC: {val_auc:.3f}, "
                           f"CV AUC: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
                
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {e}")
                training_results[model_name] = {
                    'error': str(e),
                    'training_failed': True
                }
        
        # Store training history
        self.training_history = {
            'timestamp': datetime.now().isoformat(),
            'training_results': training_results,
            'config': self.config.copy()
        }
        
        successful_models = [name for name, result in training_results.items() 
                           if not result.get('training_failed', False)]
        
        logger.info(f"Successfully trained {len(successful_models)}/{len(models_to_train)} models")
        
        return training_results
    
    def optimize_ensemble_weights(self, method: str = None) -> Dict[str, Any]:
        """
        Optimize ensemble weights using various methods
        
        Args:
            method: Optimization method ('grid_search', 'random_search', 'bayesian')
            
        Returns:
            Optimization results and best weights
        """
        if not self.models:
            raise RuntimeError("No trained models available. Train models first.")
        
        if self.validation_data is None:
            raise RuntimeError("Validation data not available.")
        
        X_val, y_val = self.validation_data
        method = method or self.config['ensemble_optimization']['method']
        
        logger.info(f"Optimizing ensemble weights using {method}")
        
        # Get predictions from all models
        model_predictions = {}
        for model_name, model in self.models.items():
            try:
                predictions = model.predict_proba(X_val)[:, 1]
                model_predictions[model_name] = predictions
            except Exception as e:
                logger.warning(f"Failed to get predictions from {model_name}: {e}")
        
        if len(model_predictions) < 2:
            logger.warning("Not enough models for ensemble optimization")
            return {'error': 'Insufficient models for ensemble'}
        
        best_weights = None
        best_score = 0.0
        optimization_history = []
        
        if method == 'grid_search':
            best_weights, best_score, optimization_history = self._grid_search_weights(
                model_predictions, y_val
            )
        elif method == 'random_search':
            best_weights, best_score, optimization_history = self._random_search_weights(
                model_predictions, y_val
            )
        elif method == 'bayesian':
            best_weights, best_score, optimization_history = self._bayesian_optimize_weights(
                model_predictions, y_val
            )
        else:
            # Default: equal weights
            n_models = len(model_predictions)
            best_weights = {name: 1.0/n_models for name in model_predictions.keys()}
            best_score = self._evaluate_ensemble(model_predictions, best_weights, y_val)
        
        results = {
            'best_weights': best_weights,
            'best_score': best_score,
            'optimization_method': method,
            'optimization_history': optimization_history,
            'model_count': len(model_predictions)
        }
        
        logger.info(f"Best ensemble score: {best_score:.3f}")
        logger.info(f"Best weights: {best_weights}")
        
        return results
    
    def _grid_search_weights(self, model_predictions: Dict[str, np.ndarray], 
                           y_true: np.ndarray) -> Tuple[Dict[str, float], float, List[Dict]]:
        """Grid search optimization for ensemble weights"""
        from itertools import product
        
        model_names = list(model_predictions.keys())
        n_models = len(model_names)
        
        # Define weight grid (simplified for computational efficiency)
        weight_options = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        
        best_score = 0.0
        best_weights = None
        history = []
        
        logger.info(f"Grid search with {len(weight_options)**n_models} combinations")
        
        # Generate all weight combinations that sum to 1.0
        for weights in product(weight_options, repeat=n_models):
            if abs(sum(weights) - 1.0) < 0.01:  # Allow small tolerance
                # Normalize weights
                normalized_weights = [w / sum(weights) for w in weights]
                weight_dict = dict(zip(model_names, normalized_weights))
                
                score = self._evaluate_ensemble(model_predictions, weight_dict, y_true)
                history.append({'weights': weight_dict.copy(), 'score': score})
                
                if score > best_score:
                    best_score = score
                    best_weights = weight_dict.copy()
        
        return best_weights, best_score, history
    
    def _random_search_weights(self, model_predictions: Dict[str, np.ndarray],
                             y_true: np.ndarray) -> Tuple[Dict[str, float], float, List[Dict]]:
        """Random search optimization for ensemble weights"""
        model_names = list(model_predictions.keys())
        n_trials = self.config['ensemble_optimization']['n_trials']
        
        best_score = 0.0
        best_weights = None
        history = []
        
        logger.info(f"Random search with {n_trials} trials")
        
        for trial in range(n_trials):
            # Generate random weights
            weights = np.random.dirichlet(np.ones(len(model_names)))
            weight_dict = dict(zip(model_names, weights))
            
            score = self._evaluate_ensemble(model_predictions, weight_dict, y_true)
            history.append({'weights': weight_dict.copy(), 'score': score})
            
            if score > best_score:
                best_score = score
                best_weights = weight_dict.copy()
        
        return best_weights, best_score, history
    
    def _bayesian_optimize_weights(self, model_predictions: Dict[str, np.ndarray],
                                 y_true: np.ndarray) -> Tuple[Dict[str, float], float, List[Dict]]:
        """Bayesian optimization for ensemble weights (simplified implementation)"""
        # For now, fall back to random search
        # In production, you might want to use libraries like scikit-optimize
        logger.info("Using random search as Bayesian optimization fallback")
        return self._random_search_weights(model_predictions, y_true)
    
    def _evaluate_ensemble(self, model_predictions: Dict[str, np.ndarray],
                         weights: Dict[str, float], y_true: np.ndarray) -> float:
        """Evaluate ensemble performance with given weights"""
        ensemble_pred = np.zeros(len(y_true))
        
        for model_name, predictions in model_predictions.items():
            weight = weights.get(model_name, 0.0)
            ensemble_pred += weight * predictions
        
        try:
            return roc_auc_score(y_true, ensemble_pred)
        except:
            return 0.0
    
    def evaluate_final_performance(self, use_test_data: bool = True) -> Dict[str, Any]:
        """
        Evaluate final ensemble performance on test data
        
        Args:
            use_test_data: Whether to use test data or validation data
            
        Returns:
            Final performance evaluation results
        """
        if not self.models:
            raise RuntimeError("No trained models available")
        
        if use_test_data and self.test_data is None:
            raise RuntimeError("Test data not available")
        elif not use_test_data and self.validation_data is None:
            raise RuntimeError("Validation data not available")
        
        X_eval, y_eval = self.test_data if use_test_data else self.validation_data
        data_type = "test" if use_test_data else "validation"
        
        logger.info(f"Evaluating final performance on {data_type} data")
        
        # Get individual model predictions
        individual_predictions = {}
        for model_name, model in self.models.items():
            try:
                predictions = model.predict_proba(X_eval)[:, 1]
                individual_predictions[model_name] = predictions
            except Exception as e:
                logger.warning(f"Failed to get predictions from {model_name}: {e}")
        
        # Calculate ensemble prediction (using equal weights if not optimized)
        n_models = len(individual_predictions)
        if n_models == 0:
            raise RuntimeError("No model predictions available")
        
        ensemble_weights = {name: 1.0/n_models for name in individual_predictions.keys()}
        ensemble_pred = np.zeros(len(y_eval))
        
        for model_name, predictions in individual_predictions.items():
            ensemble_pred += ensemble_weights[model_name] * predictions
        
        # Comprehensive evaluation
        ensemble_auc = roc_auc_score(y_eval, ensemble_pred)
        
        # Individual model performance
        individual_performance = {}
        for model_name, predictions in individual_predictions.items():
            individual_performance[model_name] = {
                'auc': roc_auc_score(y_eval, predictions),
                'predictions': predictions.tolist()  # For detailed analysis
            }
        
        # Ensemble validation
        ensemble_validation = self.validator.validate_model_performance(
            y_eval, ensemble_pred
        )
        
        # Consistency validation
        consistency_validation = self.validator.validate_ensemble_consistency(
            individual_predictions, ensemble_pred
        )
        
        results = {
            'data_type': data_type,
            'sample_count': len(y_eval),
            'ensemble_auc': ensemble_auc,
            'individual_performance': individual_performance,
            'ensemble_validation': ensemble_validation,
            'consistency_validation': consistency_validation,
            'ensemble_weights': ensemble_weights,
            'evaluation_timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Final {data_type} AUC: {ensemble_auc:.3f}")
        logger.info(f"Ensemble validation passed: {ensemble_validation['passed']}")
        
        return results
    
    def save_trained_models(self, ensemble_name: str = "ml_ensemble") -> Dict[str, str]:
        """
        Save all trained models and ensemble configuration
        
        Args:
            ensemble_name: Name for the ensemble
            
        Returns:
            Dictionary with saved model information
        """
        if not self.models:
            raise RuntimeError("No trained models to save")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_models = {}
        
        # Save individual models
        for model_name, model in self.models.items():
            model_path = Path(self.config['model_dir']) / f"{model_name}_{timestamp}.joblib"
            model_path.parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(model, model_path)
            
            # Register with version manager
            metadata = {
                'training_timestamp': timestamp,
                'performance_metrics': self.training_history.get('training_results', {}).get(model_name, {}),
                'config': self.config
            }
            
            version_id = self.model_manager.register_model(
                model_name, str(model_path), metadata
            )
            saved_models[model_name] = version_id
        
        # Save ensemble configuration
        ensemble_metadata = {
            'individual_models': saved_models,
            'training_history': self.training_history,
            'config': self.config,
            'ensemble_timestamp': timestamp
        }
        
        ensemble_version = self.model_manager.register_ensemble(
            ensemble_name, saved_models, ensemble_metadata
        )
        
        logger.info(f"Saved ensemble {ensemble_version} with {len(saved_models)} models")
        
        return {
            'ensemble_version': ensemble_version,
            'individual_models': saved_models,
            'saved_timestamp': timestamp
        }
    
    def generate_training_report(self) -> str:
        """Generate comprehensive training report"""
        if not self.training_history:
            return "No training history available"
        
        report = []
        report.append("=" * 60)
        report.append("ML ENSEMBLE TRAINING REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Training Timestamp: {self.training_history['timestamp']}")
        report.append("")
        
        # Training configuration
        report.append("CONFIGURATION:")
        report.append("-" * 30)
        config = self.training_history['config']
        for key, value in config.items():
            if isinstance(value, dict):
                report.append(f"{key}:")
                for subkey, subvalue in value.items():
                    report.append(f"  {subkey}: {subvalue}")
            else:
                report.append(f"{key}: {value}")
        report.append("")
        
        # Model performance
        report.append("MODEL PERFORMANCE:")
        report.append("-" * 30)
        training_results = self.training_history['training_results']
        
        for model_name, results in training_results.items():
            if results.get('training_failed', False):
                report.append(f"{model_name}: FAILED - {results.get('error', 'Unknown error')}")
            else:
                report.append(f"{model_name}:")
                report.append(f"  Validation AUC: {results['validation_auc']:.4f}")
                report.append(f"  CV AUC: {results['cv_mean_auc']:.4f} ± {results['cv_std_auc']:.4f}")
                report.append(f"  Training Time: {results['training_time_seconds']:.2f}s")
                report.append(f"  Validation Passed: {results['validation_passed']}")
                report.append(f"  Model Confidence: {results['model_confidence']:.4f}")
        
        report.append("")
        
        # Top features (if available)
        report.append("TOP FEATURES BY MODEL:")
        report.append("-" * 30)
        for model_name, results in training_results.items():
            if 'feature_importance' in results and results['feature_importance']:
                report.append(f"{model_name}:")
                sorted_features = sorted(
                    results['feature_importance'].items(),
                    key=lambda x: x[1], reverse=True
                )[:5]
                for feature, importance in sorted_features:
                    report.append(f"  {feature}: {importance:.4f}")
                report.append("")
        
        return "\n".join(report)
    
    def create_visualization_plots(self, output_dir: str = "plots") -> List[str]:
        """
        Create visualization plots for training results
        
        Args:
            output_dir: Directory to save plots
            
        Returns:
            List of created plot file paths
        """
        if not self.training_history:
            logger.warning("No training history available for plotting")
            return []
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        created_plots = []
        training_results = self.training_history['training_results']
        
        # Model performance comparison
        try:
            model_names = []
            val_aucs = []
            cv_aucs = []
            
            for model_name, results in training_results.items():
                if not results.get('training_failed', False):
                    model_names.append(model_name)
                    val_aucs.append(results['validation_auc'])
                    cv_aucs.append(results['cv_mean_auc'])
            
            if model_names:
                plt.figure(figsize=(12, 6))
                
                x = np.arange(len(model_names))
                width = 0.35
                
                plt.bar(x - width/2, val_aucs, width, label='Validation AUC', alpha=0.8)
                plt.bar(x + width/2, cv_aucs, width, label='Cross-Validation AUC', alpha=0.8)
                
                plt.xlabel('Models')
                plt.ylabel('AUC Score')
                plt.title('Model Performance Comparison')
                plt.xticks(x, model_names, rotation=45, ha='right')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.tight_layout()
                
                plot_path = output_path / "model_performance_comparison.png"
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                created_plots.append(str(plot_path))
                
        except Exception as e:
            logger.warning(f"Failed to create performance comparison plot: {e}")
        
        # Feature importance plots (for models that have it)
        try:
            for model_name, results in training_results.items():
                if 'feature_importance' in results and results['feature_importance']:
                    importance_dict = results['feature_importance']
                    
                    # Get top 15 features
                    sorted_features = sorted(
                        importance_dict.items(),
                        key=lambda x: x[1], reverse=True
                    )[:15]
                    
                    if sorted_features:
                        features, importances = zip(*sorted_features)
                        
                        plt.figure(figsize=(10, 8))
                        plt.barh(range(len(features)), importances)
                        plt.yticks(range(len(features)), features)
                        plt.xlabel('Feature Importance')
                        plt.title(f'Top Features - {model_name}')
                        plt.grid(True, alpha=0.3)
                        plt.tight_layout()
                        
                        plot_path = output_path / f"feature_importance_{model_name}.png"
                        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                        plt.close()
                        created_plots.append(str(plot_path))
                        
        except Exception as e:
            logger.warning(f"Failed to create feature importance plots: {e}")
        
        logger.info(f"Created {len(created_plots)} visualization plots")
        return created_plots