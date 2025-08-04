"""
ML Ensemble Usage Example

Complete example demonstrating how to use the ML ensemble system
for zero-day vulnerability exploitation prediction.
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

# Import the ML ensemble system
from src.ml import (
    EnsemblePredictor, 
    TrainingPipeline,
    RealTimeCorrelationEngine, 
    ThreatIntelligence
)


def create_sample_vulnerability_data():
    """Create sample vulnerability data for demonstration"""
    return {
        'id': 'CVE-2024-0001',
        'cve_id': 'CVE-2024-0001',
        'published_date': '2024-01-15T10:00:00Z',
        'vulnerability_type': 'buffer_overflow',
        
        # CVSS information
        'cvss': {
            'base_score': 8.5,
            'temporal_score': 8.2,
            'exploitability_score': 3.9,
            'vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        },
        
        # EPSS scores
        'epss': {
            'score': 0.75,
            'percentile': 0.92
        },
        
        # Timeline information
        'timeline': {
            'disclosure_date': '2024-01-15T10:00:00Z',
            'first_poc_date': '2024-01-18T14:30:00Z',
            'patch_date': '2024-01-20T09:00:00Z'
        },
        
        # Affected software
        'affected_software': [
            {
                'vendor': 'example_vendor',
                'product': 'web_server',
                'versions': ['2.1.0', '2.1.1', '2.2.0']
            }
        ],
        
        # CWE information
        'cwe': ['CWE-120'],
        
        # References
        'references': [
            {'url': 'https://example.com/advisory/CVE-2024-0001'},
            {'url': 'https://exploit-db.com/exploits/50001'},
            {'url': 'https://github.com/security-researcher/CVE-2024-0001-poc'}
        ],
        
        # Community activity
        'community_activity': {
            'twitter_mentions_per_day': 15.5,
            'github_commits_per_day': 2.3,
            'blog_posts_per_day': 0.8,
            'technical_posts': 5
        },
        
        'social_media': {
            'twitter_mentions': 156,
            'twitter_retweets': 89,
            'twitter_sentiment': 0.3,
            'reddit_posts': 12,
            'reddit_upvotes': 234,
            'hacker_news_mentions': 3
        },
        
        'github_activity': {
            'repositories': 8,
            'stars': 145,
            'forks': 23
        },
        
        # Threat actor information
        'threat_actors': {
            'nation_state_score': 0.2,
            'criminal_score': 0.7,
            'hacktivist_score': 0.1,
            'insider_score': 0.0,
            'script_kiddie_score': 0.6
        },
        
        # Technical assessment
        'technical_assessment': {
            'difficulty_score': 0.4,
            'skill_level': 0.3,
            'dev_time_days': 5,
            'reliability': 0.8,
            'success_rate': 0.7,
            'payload_complexity': 0.3
        },
        
        # Environmental constraints
        'environmental_constraints': {
            'constraints_score': 0.2,
            'network_requirements': 0.1,
            'system_requirements': 0.3
        },
        
        # Research activity
        'research_activity': {
            'blog_posts': 3,
            'technical_analysis': 2,
            'white_papers': 1,
            'conference_talks': 0
        },
        
        # Temporal context
        'temporal_context': {
            'holiday_period': False,
            'summer_vacation': False,
            'conference_season': 0.3,
            'geopolitical_tension': 0.2
        },
        
        # Historical patterns
        'historical_patterns': {
            'similar_exploited': 15,
            'vendor_exploited': 8,
            'product_exploited': 3,
            'type_exploited_rate': 0.4,
            'overall_rate': 0.3
        }
    }


def create_sample_training_data(n_samples: int = 1000) -> pd.DataFrame:
    """Create sample training data for demonstration"""
    np.random.seed(42)
    
    data = []
    for i in range(n_samples):
        # Create realistic vulnerability data
        cvss_score = np.random.uniform(1, 10)
        epss_score = np.random.uniform(0, 1)
        
        # Higher CVSS and EPSS generally correlate with higher exploitation probability
        exploitation_prob = (cvss_score / 10 * 0.4 + epss_score * 0.6 + 
                            np.random.normal(0, 0.2))
        exploitation_prob = np.clip(exploitation_prob, 0, 1)
        
        # Generate binary label
        exploited = 1 if exploitation_prob > 0.6 else 0
        
        sample = {
            # EPSS Enhanced features
            'cvss_base_score': cvss_score,
            'epss_score': epss_score,
            'attack_vector_network': np.random.choice([0, 1], p=[0.3, 0.7]),
            'attack_complexity_low': np.random.choice([0, 1], p=[0.4, 0.6]),
            'cwe_buffer_overflow': np.random.choice([0, 1], p=[0.8, 0.2]),
            'vendor_count': np.random.randint(1, 5),
            'has_patch': np.random.choice([0, 1], p=[0.3, 0.7]),
            'references_count': np.random.randint(1, 20),
            
            # Velocity features
            'vulnerability_age_days': np.random.randint(1, 365),
            'disclosure_to_exploit_days': np.random.randint(0, 180),
            'twitter_mentions_velocity': np.random.uniform(0, 50),
            'github_activity_velocity': np.random.uniform(0, 10),
            'researcher_interest_score': np.random.uniform(0, 1),
            'technical_difficulty_score': np.random.uniform(0, 1),
            
            # Threat Actor features
            'nation_state_interest': np.random.uniform(0, 1),
            'criminal_group_interest': np.random.uniform(0, 1),
            'required_skill_level': np.random.uniform(0, 1),
            'financial_motivation_score': np.random.uniform(0, 1),
            'geopolitical_relevance': np.random.uniform(0, 1),
            
            # Temporal features
            'disclosure_month': np.random.randint(1, 13),
            'disclosure_day_of_week': np.random.randint(0, 7),
            'is_holiday_period': np.random.choice([0, 1], p=[0.9, 0.1]),
            'conference_season_proximity': np.random.uniform(0, 1),
            
            # Practicality features
            'technical_difficulty_score': np.random.uniform(0, 1),
            'exploitation_reliability': np.random.uniform(0, 1),
            'defensive_countermeasures_present': np.random.uniform(0, 1),
            'exploit_portability': np.random.uniform(0, 1),
            
            # Community features
            'twitter_mentions_count': np.random.randint(0, 1000),
            'github_repositories_count': np.random.randint(0, 50),
            'security_blog_posts': np.random.randint(0, 20),
            'technical_analysis_count': np.random.randint(0, 10),
            'exploit_db_entries': np.random.randint(0, 5),
            
            # Pattern features
            'similar_cves_exploited_count': np.random.randint(0, 50),
            'same_vendor_exploited_count': np.random.randint(0, 20),
            'historical_exploitation_rate': np.random.uniform(0, 1),
            'campaign_association_score': np.random.uniform(0, 1),
            
            # Target variable
            'exploited': exploited
        }
        
        data.append(sample)
    
    return pd.DataFrame(data)


def demonstrate_basic_prediction():
    """Demonstrate basic prediction functionality"""
    print("=" * 60)
    print("BASIC PREDICTION DEMONSTRATION")
    print("=" * 60)
    
    # Create ensemble predictor
    predictor = EnsemblePredictor(model_dir="data/models")
    
    # Create sample data
    vulnerability_data = create_sample_vulnerability_data()
    
    print(f"Analyzing vulnerability: {vulnerability_data['id']}")
    print(f"CVSS Score: {vulnerability_data['cvss']['base_score']}")
    print(f"EPSS Score: {vulnerability_data['epss']['score']}")
    
    # For demonstration, we'll simulate a trained model
    print("\n⚠️  Note: Using simulated trained models for demonstration")
    predictor.is_trained = True
    
    # Mock the models with reasonable predictions
    mock_predictions = {
        'epss_enhanced': 0.78,
        'velocity': 0.65,
        'threat_actor': 0.72,
        'temporal': 0.58,
        'practicality': 0.69,
        'community': 0.61,
        'pattern': 0.73
    }
    
    from unittest.mock import Mock
    import numpy as np
    
    for model_name, pred_value in mock_predictions.items():
        mock_model = Mock()
        mock_model.predict_proba.return_value = np.array([[1-pred_value, pred_value]])
        mock_model.get_confidence.return_value = 0.8
        predictor.models[model_name] = mock_model
    
    # Make prediction
    result = predictor.predict(vulnerability_data)
    
    print(f"\n📊 PREDICTION RESULTS:")
    print(f"Exploitation Probability: {result.exploitation_probability:.3f}")
    print(f"Confidence Score: {result.confidence_score:.3f}")
    print(f"Risk Level: {result.risk_level}")
    print(f"Estimated Time to Exploitation: {result.time_to_exploitation_days} days")
    
    print(f"\n🔍 MODEL CONTRIBUTIONS:")
    for model_name, prediction in result.model_predictions.items():
        print(f"  {model_name}: {prediction:.3f}")
    
    print(f"\n⚠️  CONTRIBUTING FACTORS:")
    for factor, score in result.contributing_factors.items():
        print(f"  {factor}: {score:.3f}")
    
    print(f"\n📋 RECOMMENDED ACTIONS:")
    for i, action in enumerate(result.recommended_actions, 1):
        print(f"  {i}. {action}")


def demonstrate_training_pipeline():
    """Demonstrate the training pipeline"""
    print("\n" + "=" * 60)
    print("TRAINING PIPELINE DEMONSTRATION")
    print("=" * 60)
    
    # Create training pipeline
    config = {
        'model_dir': 'data/models',
        'random_state': 42,
        'test_size': 0.2,
        'validation_size': 0.2,
        'cv_folds': 3,  # Reduced for demo
        'target_metrics': {
            'min_auc': 0.80,  # Lower for demo
            'min_precision': 0.75,
            'min_recall': 0.70
        }
    }
    
    pipeline = TrainingPipeline(config)
    
    # Generate sample training data
    print("📊 Generating sample training data...")
    training_data = create_sample_training_data(n_samples=500)  # Smaller for demo
    
    print(f"Training data shape: {training_data.shape}")
    print(f"Positive class ratio: {training_data['exploited'].mean():.3f}")
    
    # Load training data
    data_stats = pipeline.load_training_data(data=training_data, target_column='exploited')
    
    print(f"\n📈 DATA STATISTICS:")
    print(f"Total samples: {data_stats['total_samples']}")
    print(f"Training samples: {data_stats['training_samples']}")
    print(f"Validation samples: {data_stats['validation_samples']}")
    print(f"Test samples: {data_stats['test_samples']}")
    print(f"Feature count: {data_stats['feature_count']}")
    
    # For demonstration, we'll simulate training (actual training would take much longer)
    print(f"\n🔧 SIMULATING MODEL TRAINING...")
    print("⚠️  Note: In production, this would train 7 individual models")
    
    # Simulate training results
    simulated_results = {
        'epss_enhanced': {
            'validation_auc': 0.82,
            'cv_mean_auc': 0.81,
            'cv_std_auc': 0.03,
            'training_time_seconds': 45.2,
            'validation_passed': True
        },
        'velocity': {
            'validation_auc': 0.78,
            'cv_mean_auc': 0.77,
            'cv_std_auc': 0.04,
            'training_time_seconds': 38.1,
            'validation_passed': True
        },
        'threat_actor': {
            'validation_auc': 0.80,
            'cv_mean_auc': 0.79,
            'cv_std_auc': 0.03,
            'training_time_seconds': 42.8,
            'validation_passed': True
        }
    }
    
    print(f"\n📊 SIMULATED TRAINING RESULTS:")
    for model_name, results in simulated_results.items():
        print(f"  {model_name}:")
        print(f"    Validation AUC: {results['validation_auc']:.3f}")
        print(f"    CV AUC: {results['cv_mean_auc']:.3f} ± {results['cv_std_auc']:.3f}")
        print(f"    Training time: {results['training_time_seconds']:.1f}s")
        print(f"    Validation passed: {results['validation_passed']}")
    
    print(f"\n✅ Training pipeline demonstration complete!")


def demonstrate_threat_correlation():
    """Demonstrate real-time threat intelligence correlation"""
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE CORRELATION DEMONSTRATION")
    print("=" * 60)
    
    # Create correlation engine
    correlation_engine = RealTimeCorrelationEngine()
    
    # Create sample threat intelligence
    print("📡 Ingesting threat intelligence...")
    
    # Sample IOC intelligence
    ioc_intel = ThreatIntelligence(
        source="threat_feed_alpha",
        intelligence_type="ioc",
        content={
            "type": "ip_addresses",
            "indicators": ["192.168.1.100", "10.0.0.50"],
            "campaign": "apt_group_x"
        },
        confidence=0.85,
        timestamp=datetime.now(),
        expiry=datetime.now() + timedelta(hours=48),
        tags=["apt", "targeted_attack"],
        severity="high"
    )
    
    # Sample campaign intelligence
    campaign_intel = ThreatIntelligence(
        source="security_vendor_beta",
        intelligence_type="campaign",
        content={
            "campaign_id": "campaign_2024_001",
            "name": "Operation WebStrike",
            "target_industries": ["financial", "healthcare"],
            "vulnerability_types": ["buffer_overflow", "sql_injection"]
        },
        confidence=0.90,
        timestamp=datetime.now(),
        expiry=datetime.now() + timedelta(days=30),
        tags=["campaign", "financial_sector"],
        severity="critical"
    )
    
    # Sample actor intelligence
    actor_intel = ThreatIntelligence(
        source="government_intel",
        intelligence_type="actor",
        content={
            "actor_id": "apt_group_x",
            "name": "Advanced Persistent Threat Group X",
            "capabilities": ["zero_day_exploitation", "social_engineering"],
            "target_preferences": ["government", "defense_contractors"]
        },
        confidence=0.95,
        timestamp=datetime.now(),
        expiry=datetime.now() + timedelta(days=90),
        tags=["apt", "nation_state"],
        severity="critical"
    )
    
    print(f"💾 Threat intelligence samples created:")
    print(f"  - IOC Intelligence: {len(ioc_intel.content['indicators'])} indicators")
    print(f"  - Campaign Intelligence: {campaign_intel.content['name']}")
    print(f"  - Actor Intelligence: {actor_intel.content['name']}")
    
    # Simulate correlation (normally this would be asynchronous)
    vulnerability_data = create_sample_vulnerability_data()
    
    print(f"\n🔍 SIMULATED CORRELATION RESULTS:")
    print(f"Analyzing vulnerability: {vulnerability_data['id']}")
    
    # Simulate correlation results
    print(f"  ✅ Campaign correlation found:")
    print(f"    - Campaign: Operation WebStrike")
    print(f"    - Correlation score: 0.72")
    print(f"    - Risk adjustment: +0.15")
    
    print(f"  ✅ Actor correlation found:")
    print(f"    - Actor: APT Group X")
    print(f"    - Correlation score: 0.68")
    print(f"    - Risk adjustment: +0.12")
    
    print(f"  ⚠️  IOC correlation: No direct matches found")
    
    # Simulate dynamic risk scoring
    base_score = 0.65
    risk_adjustment = 0.15 + 0.12
    adjusted_score = min(base_score + risk_adjustment, 1.0)
    
    print(f"\n📊 DYNAMIC RISK SCORING:")
    print(f"  Base prediction score: {base_score:.3f}")
    print(f"  Threat intelligence adjustment: +{risk_adjustment:.3f}")
    print(f"  Final adjusted score: {adjusted_score:.3f}")
    print(f"  Risk increase: {(risk_adjustment / base_score * 100):.1f}%")


def demonstrate_advanced_features():
    """Demonstrate advanced features and analysis"""
    print("\n" + "=" * 60)
    print("ADVANCED FEATURES DEMONSTRATION")
    print("=" * 60)
    
    # Create predictor
    predictor = EnsemblePredictor()
    
    vulnerability_data = create_sample_vulnerability_data()
    
    print("🔍 FEATURE EXTRACTION ANALYSIS:")
    features_df = predictor.extract_features(vulnerability_data)
    
    print(f"  Total features extracted: {len(features_df.columns)}")
    print(f"  Sample features:")
    
    # Show some key features
    key_features = [
        'cvss_base_score', 'epss_score', 'vulnerability_age_days',
        'twitter_mentions_count', 'github_repositories_count',
        'nation_state_interest', 'technical_difficulty_score'
    ]
    
    for feature in key_features:
        if feature in features_df.columns:
            value = features_df[feature].iloc[0]
            print(f"    {feature}: {value}")
    
    print(f"\n📈 CONFIDENCE ANALYSIS:")
    # Simulate confidence factors
    confidence_factors = {
        'data_completeness': 0.92,
        'feature_quality': 0.88,
        'model_consensus': 0.85,
        'temporal_relevance': 0.90
    }
    
    for factor, score in confidence_factors.items():
        print(f"  {factor}: {score:.3f}")
    
    overall_confidence = sum(confidence_factors.values()) / len(confidence_factors)
    print(f"  Overall confidence: {overall_confidence:.3f}")
    
    print(f"\n🎯 PREDICTION EXPLANATION:")
    print(f"  This vulnerability shows high exploitation potential due to:")
    print(f"    • High CVSS score ({vulnerability_data['cvss']['base_score']}) indicating severe impact")
    print(f"    • High EPSS score ({vulnerability_data['epss']['score']}) suggesting likely exploitation")
    print(f"    • Active community discussion and POC availability")
    print(f"    • Suitable for criminal groups based on technical requirements")
    print(f"    • Current time period shows elevated threat activity")
    
    print(f"\n🛡️  MITIGATION RECOMMENDATIONS:")
    print(f"  Priority actions based on prediction:")
    print(f"    1. IMMEDIATE: Apply vendor patch within 24-48 hours")
    print(f"    2. MONITOR: Implement enhanced logging for affected systems")
    print(f"    3. ASSESS: Review exposure of affected web server instances")
    print(f"    4. PREPARE: Activate incident response procedures")
    print(f"    5. COMMUNICATE: Alert security teams and stakeholders")


def main():
    """Main demonstration function"""
    print("🤖 ML ENSEMBLE ZERO-DAY PREDICTION SYSTEM")
    print("Demonstration of Vulnerability Exploitation Prediction")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Run demonstrations
        demonstrate_basic_prediction()
        demonstrate_training_pipeline()
        demonstrate_threat_correlation()
        demonstrate_advanced_features()
        
        print("\n" + "=" * 60)
        print("✅ DEMONSTRATION COMPLETE")
        print("=" * 60)
        print(f"📚 Key Features Demonstrated:")
        print(f"  • 7-model ensemble prediction system")
        print(f"  • Comprehensive feature extraction (100+ features)")
        print(f"  • 85-90% accuracy target with confidence scoring")
        print(f"  • 14-21 day advance warning capability")
        print(f"  • Real-time threat intelligence correlation")
        print(f"  • Dynamic risk scoring and adjustment")
        print(f"  • Automated training and validation pipeline")
        print(f"  • Model versioning and persistence")
        
        print(f"\n🎯 Production Deployment Considerations:")
        print(f"  • Scale training data to 10,000+ samples")
        print(f"  • Implement continuous model retraining")
        print(f"  • Set up real-time threat intelligence feeds")
        print(f"  • Configure monitoring and alerting")
        print(f"  • Establish model performance tracking")
        print(f"  • Deploy with proper security controls")
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        
    print(f"\n📊 System Specifications:")
    print(f"  • Models: 7 specialized ML models")
    print(f"  • Features: 100+ engineered features")
    print(f"  • Accuracy: 85-90% target (AUC)")
    print(f"  • Warning: 14-21 days advance notice")
    print(f"  • Confidence: Multi-factor confidence scoring")
    print(f"  • Real-time: Threat intelligence correlation")


if __name__ == "__main__":
    main()