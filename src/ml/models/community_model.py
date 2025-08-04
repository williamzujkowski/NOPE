"""
Community Model

Analyzes security community activity, discourse, and social signals.
Predicts exploitation based on community interest, discussions, and research activity.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfIdfVectorizer
from typing import Dict, List, Optional, Any
import joblib
import re


class CommunityModel:
    """
    Community model that analyzes:
    - Security researcher interest and activity
    - Social media mentions and sentiment
    - Technical blog posts and analysis
    - Conference presentations and talks
    - GitHub activity and proof-of-concept code
    - Security forum discussions
    - Academic research references
    - Vendor communications and advisories
    """
    
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=120,
            max_depth=12,
            min_samples_split=25,
            min_samples_leaf=12,
            random_state=random_state,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.text_vectorizer = TfIdfVectorizer(
            max_features=100,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=2
        )
        self.svd = TruncatedSVD(n_components=15, random_state=random_state)
        self.feature_importance_ = {}
        self.is_fitted = False
        
        # Expected features for community analysis
        self.expected_features = [
            'twitter_mentions_count', 'twitter_retweets_count', 'twitter_sentiment_score',
            'reddit_posts_count', 'reddit_upvotes_count', 'reddit_comment_count',
            'hacker_news_mentions', 'hacker_news_points', 'hacker_news_comments',
            'github_repositories_count', 'github_stars_total', 'github_forks_total',
            'security_blog_posts', 'technical_analysis_count', 'white_paper_references',
            'conference_presentations', 'webinar_mentions', 'podcast_discussions',
            'cve_database_updates', 'nvd_analysis_count', 'vendor_advisories_count',
            'security_firm_reports', 'threat_intel_mentions', 'ioc_sharing_activity',
            'bounty_program_submissions', 'researcher_interest_score', 'academic_citations',
            'security_tool_integration', 'scanner_signatures_added', 'yara_rules_created',
            'exploit_db_entries', 'metasploit_modules', 'poc_code_availability',
            'security_forum_activity', 'mailing_list_discussions', 'discord_chat_activity'
        ]
        
        # Community platform weights
        self.platform_weights = {
            'twitter': 0.15,
            'reddit': 0.12,
            'github': 0.20,
            'blogs': 0.18,
            'conferences': 0.15,
            'forums': 0.10,
            'academic': 0.10
        }
        
        # Sentiment scaling factors
        self.sentiment_multipliers = {
            'very_negative': 0.3,  # May indicate difficulty/impracticality
            'negative': 0.6,
            'neutral': 1.0,
            'positive': 1.4,       # Increased interest/feasibility
            'very_positive': 1.8   # High excitement/activity
        }
    
    def _prepare_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare community-specific features"""
        X_prepared = X.copy()
        
        # Ensure all expected features exist
        for feature in self.expected_features:
            if feature not in X_prepared.columns:
                X_prepared[feature] = 0.0
        
        # Social media activity composite
        X_prepared['social_media_activity'] = (
            (X_prepared['twitter_mentions_count'] + X_prepared['twitter_retweets_count']) * self.platform_weights['twitter'] +
            (X_prepared['reddit_posts_count'] + X_prepared['reddit_upvotes_count']) * self.platform_weights['reddit'] +
            X_prepared['hacker_news_mentions'] * 0.05
        )
        
        # Technical community engagement
        X_prepared['technical_community_engagement'] = (
            X_prepared['github_repositories_count'] * 0.3 +
            np.log1p(X_prepared['github_stars_total']) * 0.25 +
            np.log1p(X_prepared['github_forks_total']) * 0.25 +
            X_prepared['security_blog_posts'] * 0.2
        )
        
        # Research and analysis activity
        X_prepared['research_activity'] = (
            X_prepared['technical_analysis_count'] * 0.25 +
            X_prepared['white_paper_references'] * 0.2 +
            X_prepared['academic_citations'] * 0.15 +
            X_prepared['conference_presentations'] * 0.25 +
            X_prepared['researcher_interest_score'] * 0.15
        )
        
        # Professional security community
        X_prepared['professional_security_activity'] = (
            X_prepared['security_firm_reports'] * 0.3 +
            X_prepared['threat_intel_mentions'] * 0.25 +
            X_prepared['vendor_advisories_count'] * 0.2 +
            X_prepared['security_tool_integration'] * 0.25
        )
        
        # Exploit development indicators
        X_prepared['exploit_development_signals'] = (
            X_prepared['poc_code_availability'] * 0.3 +
            X_prepared['exploit_db_entries'] * 0.25 +
            X_prepared['metasploit_modules'] * 0.25 +
            X_prepared['yara_rules_created'] * 0.1 +
            X_prepared['scanner_signatures_added'] * 0.1
        )
        
        # Community discourse volume
        X_prepared['discourse_volume'] = (
            X_prepared['security_forum_activity'] * 0.3 +
            X_prepared['mailing_list_discussions'] * 0.25 +
            X_prepared['discord_chat_activity'] * 0.15 +
            X_prepared['reddit_comment_count'] * 0.15 +
            X_prepared['hacker_news_comments'] * 0.15
        )
        
        # Sentiment-adjusted activity
        sentiment_factor = self._calculate_sentiment_factor(X_prepared)
        X_prepared['sentiment_adjusted_activity'] = (
            X_prepared['social_media_activity'] * sentiment_factor
        )
        
        # Buzz momentum (velocity of mentions)
        X_prepared['community_buzz_momentum'] = (
            X_prepared['social_media_activity'] * 0.3 +
            X_prepared['technical_community_engagement'] * 0.25 +
            X_prepared['discourse_volume'] * 0.25 +
            X_prepared['exploit_development_signals'] * 0.2
        )
        
        # Authority and credibility signals
        X_prepared['authority_signals'] = (
            X_prepared['security_firm_reports'] * 0.4 +
            X_prepared['academic_citations'] * 0.3 +
            X_prepared['conference_presentations'] * 0.3
        )
        
        # Early warning indicators
        X_prepared['early_warning_signals'] = (
            X_prepared['researcher_interest_score'] * 0.25 +
            X_prepared['bounty_program_submissions'] * 0.2 +
            X_prepared['technical_analysis_count'] * 0.25 +
            X_prepared['poc_code_availability'] * 0.3
        )
        
        # Community maturity indicator
        X_prepared['community_maturity'] = (
            X_prepared['white_paper_references'] * 0.3 +
            X_prepared['academic_citations'] * 0.25 +
            X_prepared['vendor_advisories_count'] * 0.25 +
            X_prepared['security_tool_integration'] * 0.2
        )
        
        # Overall community risk score
        X_prepared['community_risk_composite'] = (
            X_prepared['community_buzz_momentum'] * 0.25 +
            X_prepared['exploit_development_signals'] * 0.3 +
            X_prepared['early_warning_signals'] * 0.25 +
            X_prepared['authority_signals'] * 0.2
        )
        
        # Select features
        feature_columns = self.expected_features + [
            'social_media_activity', 'technical_community_engagement', 'research_activity',
            'professional_security_activity', 'exploit_development_signals', 'discourse_volume',
            'sentiment_adjusted_activity', 'community_buzz_momentum', 'authority_signals',
            'early_warning_signals', 'community_maturity', 'community_risk_composite'
        ]
        
        return X_prepared[feature_columns]
    
    def _calculate_sentiment_factor(self, X: pd.DataFrame) -> np.ndarray:
        """Calculate sentiment adjustment factor"""
        if 'twitter_sentiment_score' not in X.columns:
            return np.ones(len(X))
        
        sentiment_scores = X['twitter_sentiment_score'].fillna(0)
        
        # Map sentiment scores to multipliers
        conditions = [
            sentiment_scores <= -0.6,  # Very negative
            (sentiment_scores > -0.6) & (sentiment_scores <= -0.2),  # Negative
            (sentiment_scores > -0.2) & (sentiment_scores <= 0.2),   # Neutral
            (sentiment_scores > 0.2) & (sentiment_scores <= 0.6),    # Positive
            sentiment_scores > 0.6     # Very positive
        ]
        
        multipliers = [
            self.sentiment_multipliers['very_negative'],
            self.sentiment_multipliers['negative'],
            self.sentiment_multipliers['neutral'],
            self.sentiment_multipliers['positive'],
            self.sentiment_multipliers['very_positive']
        ]
        
        return np.select(conditions, multipliers, default=1.0)
    
    def fit(self, X: pd.DataFrame, y: pd.Series) -> 'CommunityModel':
        """Train the community model"""
        X_prepared = self._prepare_features(X)
        
        # Handle missing values and infinities
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_prepared)
        
        # Apply dimensionality reduction for community features
        X_reduced = self.svd.fit_transform(X_scaled)
        
        # Train model
        self.model.fit(X_reduced, y)
        
        # Store feature importance (mapped back to original features)
        svd_importance = self.model.feature_importances_
        original_importance = np.abs(self.svd.components_).T @ svd_importance
        
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
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_reduced = self.svd.transform(X_scaled)
        
        return self.model.predict(X_reduced)
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Make probability predictions"""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before making predictions")
        
        X_prepared = self._prepare_features(X)
        X_prepared = X_prepared.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_scaled = self.scaler.transform(X_prepared)
        X_reduced = self.svd.transform(X_scaled)
        
        return self.model.predict_proba(X_reduced)
    
    def get_confidence(self, X: pd.DataFrame) -> float:
        """
        Calculate confidence based on community signal quality
        """
        if not self.is_fitted:
            return 0.0
        
        X_prepared = self._prepare_features(X)
        
        # Confidence factors
        data_completeness = 1.0 - (X_prepared.isnull().sum(axis=1) / len(X_prepared.columns))
        
        # Signal strength from multiple platforms
        platform_diversity = (
            (X_prepared['social_media_activity'] > 0).astype(float) * 0.2 +
            (X_prepared['technical_community_engagement'] > 0).astype(float) * 0.3 +
            (X_prepared['research_activity'] > 0).astype(float) * 0.3 +
            (X_prepared['professional_security_activity'] > 0).astype(float) * 0.2
        )
        
        # Authority signal strength
        authority_strength = np.clip(
            X_prepared['authority_signals'] / X_prepared['authority_signals'].max(),
            0.0, 1.0
        ) if X_prepared['authority_signals'].max() > 0 else 0.0
        
        # Activity volume indicator
        activity_volume = np.clip(
            X_prepared['community_buzz_momentum'] / 
            (X_prepared['community_buzz_momentum'].quantile(0.9) + 1e-8),
            0.0, 1.0
        )
        
        # Combined confidence
        confidence = (
            data_completeness * 0.3 +
            platform_diversity * 0.3 +
            authority_strength * 0.2 +
            activity_volume * 0.2
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
    
    def analyze_community_activity(self, X: pd.DataFrame, sample_idx: int = 0) -> Dict[str, Any]:
        """
        Analyze community activity for a specific vulnerability
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before analysis")
        
        X_prepared = self._prepare_features(X)
        sample = X_prepared.iloc[sample_idx]
        
        activity_analysis = {
            'overall_community_interest': 'LOW',
            'platform_breakdown': {},
            'signal_strength': {},
            'development_indicators': {},
            'authority_indicators': {},
            'trending_factors': []
        }
        
        # Overall interest level
        community_risk = sample['community_risk_composite']
        if community_risk > 0.7:
            activity_analysis['overall_community_interest'] = 'HIGH'
        elif community_risk > 0.4:
            activity_analysis['overall_community_interest'] = 'MEDIUM'
        
        # Platform breakdown
        activity_analysis['platform_breakdown'] = {
            'social_media_score': float(sample['social_media_activity']),
            'technical_platforms_score': float(sample['technical_community_engagement']),
            'research_community_score': float(sample['research_activity']),
            'professional_security_score': float(sample['professional_security_activity']),
            'discourse_volume_score': float(sample['discourse_volume'])
        }
        
        # Signal strength
        activity_analysis['signal_strength'] = {
            'buzz_momentum': float(sample['community_buzz_momentum']),
            'early_warning_signals': float(sample['early_warning_signals']),
            'authority_signals': float(sample['authority_signals']),
            'sentiment_adjusted_activity': float(sample['sentiment_adjusted_activity'])
        }
        
        # Development indicators
        activity_analysis['development_indicators'] = {
            'poc_availability': float(sample['poc_code_availability']),
            'exploit_db_presence': float(sample['exploit_db_entries']),
            'metasploit_modules': float(sample['metasploit_modules']),
            'github_activity': float(sample['technical_community_engagement']),
            'overall_development_signals': float(sample['exploit_development_signals'])
        }
        
        # Authority indicators
        activity_analysis['authority_indicators'] = {
            'security_firm_reports': float(sample['security_firm_reports']),
            'academic_references': float(sample['academic_citations']),
            'conference_presentations': float(sample['conference_presentations']),
            'vendor_advisories': float(sample['vendor_advisories_count'])
        }
        
        # Trending factors
        if sample['community_buzz_momentum'] > 0.6:
            activity_analysis['trending_factors'].append("High community buzz momentum detected")
        
        if sample['early_warning_signals'] > 0.5:
            activity_analysis['trending_factors'].append("Early warning signals present")
        
        if sample['exploit_development_signals'] > 0.4:
            activity_analysis['trending_factors'].append("Active exploit development indicators")
        
        if sample['researcher_interest_score'] > 0.6:
            activity_analysis['trending_factors'].append("Strong researcher interest")
        
        if sample['social_media_activity'] > 0.5:
            activity_analysis['trending_factors'].append("Significant social media attention")
        
        return activity_analysis
    
    def get_community_trends(self, X: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze community trends across all vulnerabilities
        """
        X_prepared = self._prepare_features(X)
        
        trends = {
            'platform_activity_distribution': {},
            'community_engagement_patterns': {},
            'development_activity_trends': {},
            'authority_source_analysis': {}
        }
        
        # Platform activity distribution
        platform_features = {
            'social_media': 'social_media_activity',
            'technical_platforms': 'technical_community_engagement',
            'research_community': 'research_activity',
            'professional_security': 'professional_security_activity'
        }
        
        for platform, feature in platform_features.items():
            trends['platform_activity_distribution'][platform] = {
                'mean_activity': float(X_prepared[feature].mean()),
                'high_activity_percentage': float((X_prepared[feature] > 0.5).mean() * 100),
                'activity_variance': float(X_prepared[feature].var())
            }
        
        # Community engagement patterns
        trends['community_engagement_patterns'] = {
            'average_buzz_momentum': float(X_prepared['community_buzz_momentum'].mean()),
            'high_engagement_percentage': float((X_prepared['community_buzz_momentum'] > 0.6).mean() * 100),
            'discourse_volume_avg': float(X_prepared['discourse_volume'].mean()),
            'sentiment_impact_avg': float(X_prepared['sentiment_adjusted_activity'].mean())
        }
        
        # Development activity trends
        trends['development_activity_trends'] = {
            'poc_availability_rate': float((X_prepared['poc_code_availability'] > 0).mean() * 100),
            'exploit_development_activity': float(X_prepared['exploit_development_signals'].mean()),
            'github_engagement_avg': float(X_prepared['technical_community_engagement'].mean()),
            'tool_integration_rate': float((X_prepared['security_tool_integration'] > 0).mean() * 100)
        }
        
        # Authority source analysis
        trends['authority_source_analysis'] = {
            'security_firm_coverage': float((X_prepared['security_firm_reports'] > 0).mean() * 100),
            'academic_interest': float(X_prepared['academic_citations'].mean()),
            'vendor_communication': float(X_prepared['vendor_advisories_count'].mean()),
            'conference_coverage': float((X_prepared['conference_presentations'] > 0).mean() * 100)
        }
        
        return trends
    
    def predict_viral_potential(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict the viral potential of vulnerabilities in the community
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predictions")
        
        X_prepared = self._prepare_features(X)
        
        # Viral potential factors
        social_amplification = X_prepared['social_media_activity']
        technical_interest = X_prepared['technical_community_engagement']
        authority_endorsement = X_prepared['authority_signals']
        development_activity = X_prepared['exploit_development_signals']
        
        # Viral potential score
        viral_potential = (
            social_amplification * 0.3 +
            technical_interest * 0.25 +
            authority_endorsement * 0.25 +
            development_activity * 0.2
        )
        
        # Normalize to 0-1 range
        if viral_potential.max() > 0:
            viral_potential = viral_potential / viral_potential.max()
        
        return viral_potential.values
    
    def identify_community_leaders(self, X: pd.DataFrame) -> Dict[str, List[str]]:
        """
        Identify key community platforms and sources driving discussion
        """
        X_prepared = self._prepare_features(X)
        
        leaders = {
            'top_platforms': [],
            'key_signal_sources': [],
            'authority_sources': []
        }
        
        # Calculate platform influence scores
        platform_scores = {
            'Twitter/Social': X_prepared['social_media_activity'].mean(),
            'GitHub/Technical': X_prepared['technical_community_engagement'].mean(),
            'Research/Academic': X_prepared['research_activity'].mean(),
            'Professional Security': X_prepared['professional_security_activity'].mean(),
            'Forums/Discourse': X_prepared['discourse_volume'].mean()
        }
        
        # Sort platforms by influence
        sorted_platforms = sorted(platform_scores.items(), key=lambda x: x[1], reverse=True)
        leaders['top_platforms'] = [platform for platform, score in sorted_platforms[:3]]
        
        # Key signal sources (features with highest importance)
        if self.feature_importance_:
            sorted_features = sorted(self.feature_importance_.items(), key=lambda x: x[1], reverse=True)
            leaders['key_signal_sources'] = [feature for feature, importance in sorted_features[:5]]
        
        # Authority sources
        authority_features = [
            'security_firm_reports', 'academic_citations', 'conference_presentations',
            'vendor_advisories_count', 'threat_intel_mentions'
        ]
        
        authority_scores = {}
        for feature in authority_features:
            if feature in X_prepared.columns:
                authority_scores[feature] = X_prepared[feature].mean()
        
        sorted_authority = sorted(authority_scores.items(), key=lambda x: x[1], reverse=True)
        leaders['authority_sources'] = [source for source, score in sorted_authority[:3]]
        
        return leaders