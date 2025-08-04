"""
Feature Extractor

Comprehensive feature extraction system for vulnerability data.
Transforms raw vulnerability information into ML-ready features for all 7 models.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import re
import json
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Comprehensive feature extractor that prepares features for all ensemble models:
    1. EPSS Enhanced Model features
    2. Velocity Model features  
    3. Threat Actor Model features
    4. Temporal Model features
    5. Practicality Model features
    6. Community Model features
    7. Pattern Model features
    """
    
    def __init__(self):
        # Feature extraction configuration
        self.cvss_metrics = [
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'scope', 'confidentiality_impact',
            'integrity_impact', 'availability_impact'
        ]
        
        # CWE categories for classification
        self.cwe_categories = {
            'buffer_overflow': [119, 120, 121, 122, 125, 787],
            'sql_injection': [89, 564, 643],
            'xss': [79, 80, 83, 85, 87],
            'rce': [78, 94, 95, 77, 88],
            'directory_traversal': [22, 23, 36, 73],
            'csrf': [352],
            'xxe': [611, 827],
            'deserialization': [502],
            'authentication': [287, 288, 290, 306, 307],
            'authorization': [284, 285, 862, 863]
        }
        
        # Vendor categories
        self.vendor_categories = {
            'microsoft': ['microsoft', 'ms', 'windows', 'office', 'exchange'],
            'apple': ['apple', 'macos', 'ios', 'safari'],
            'google': ['google', 'chrome', 'android'],
            'adobe': ['adobe', 'flash', 'acrobat', 'reader'],
            'oracle': ['oracle', 'java', 'mysql'],
            'mozilla': ['mozilla', 'firefox', 'thunderbird'],
            'cisco': ['cisco'],
            'linux': ['linux', 'ubuntu', 'debian', 'redhat', 'centos']
        }
        
        # Attack vector mappings
        self.attack_vectors = {
            'network': ['network', 'remote', 'internet'],
            'adjacent': ['adjacent', 'local network', 'lan'],
            'local': ['local', 'localhost'],
            'physical': ['physical', 'console']
        }
    
    def extract_all_features(self, vulnerability_data: Dict) -> Dict[str, Any]:
        """
        Extract all features for all models from vulnerability data
        
        Args:
            vulnerability_data: Dictionary containing vulnerability information
            
        Returns:
            Dictionary with all extracted features
        """
        features = {}
        
        # Extract features for each model
        features.update(self._extract_epss_enhanced_features(vulnerability_data))
        features.update(self._extract_velocity_features(vulnerability_data))
        features.update(self._extract_threat_actor_features(vulnerability_data))
        features.update(self._extract_temporal_features(vulnerability_data))
        features.update(self._extract_practicality_features(vulnerability_data))
        features.update(self._extract_community_features(vulnerability_data))
        features.update(self._extract_pattern_features(vulnerability_data))
        
        # Add meta features
        features.update(self._extract_meta_features(vulnerability_data))
        
        return features
    
    def _extract_epss_enhanced_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for EPSS Enhanced Model"""
        features = {}
        
        # CVSS scores
        cvss_data = data.get('cvss', {})
        features['cvss_base_score'] = float(cvss_data.get('base_score', 0))
        features['cvss_temporal_score'] = float(cvss_data.get('temporal_score', features['cvss_base_score']))
        features['cvss_exploitability'] = float(cvss_data.get('exploitability_score', 0))
        
        # EPSS scores
        epss_data = data.get('epss', {})
        features['epss_score'] = float(epss_data.get('score', 0))
        features['epss_percentile'] = float(epss_data.get('percentile', 0))
        
        # CVSS metrics (one-hot encoded)
        cvss_vector = cvss_data.get('vector_string', '')
        features.update(self._parse_cvss_vector(cvss_vector))
        
        # CWE analysis
        cwe_list = data.get('cwe', [])
        features.update(self._extract_cwe_features(cwe_list))
        
        # Affected software
        affected = data.get('affected_software', [])
        features['vendor_count'] = len(set(item.get('vendor', '') for item in affected))
        features['product_count'] = len(set(item.get('product', '') for item in affected))
        features['version_count'] = sum(len(item.get('versions', [])) for item in affected)
        
        # Patch information
        patch_data = data.get('patch_info', {})
        features['has_patch'] = float(patch_data.get('available', False))
        features['patch_available_days'] = float(patch_data.get('days_since_available', 0))
        features['patch_complexity_low'] = float(patch_data.get('complexity', 'high') == 'low')
        
        # References and exploit information
        references = data.get('references', [])
        features['references_count'] = len(references)
        features['exploitdb_entries'] = len([r for r in references if 'exploit-db' in r.get('url', '')])
        features['metasploit_modules'] = len([r for r in references if 'metasploit' in r.get('url', '')])
        
        return features
    
    def _extract_velocity_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for Velocity Model"""
        features = {}
        
        # Timeline data
        timeline = data.get('timeline', {})
        disclosure_date = self._parse_date(timeline.get('disclosure_date'))
        poc_date = self._parse_date(timeline.get('first_poc_date'))
        exploit_date = self._parse_date(timeline.get('first_exploit_date'))
        patch_date = self._parse_date(timeline.get('patch_date'))
        wild_date = self._parse_date(timeline.get('first_seen_wild'))
        
        current_date = datetime.now()
        
        # Calculate time differences
        if disclosure_date:
            features['vulnerability_age_days'] = (current_date - disclosure_date).days
            
            if poc_date:
                features['disclosure_to_poc_days'] = (poc_date - disclosure_date).days
            else:
                features['disclosure_to_poc_days'] = 0
                
            if exploit_date:
                features['disclosure_to_exploit_days'] = (exploit_date - disclosure_date).days
                if poc_date:
                    features['poc_to_exploit_days'] = (exploit_date - poc_date).days
                else:
                    features['poc_to_exploit_days'] = features['disclosure_to_exploit_days']
            else:
                features['disclosure_to_exploit_days'] = 0
                features['poc_to_exploit_days'] = 0
                
            if patch_date and exploit_date:
                features['patch_to_exploit_days'] = (exploit_date - patch_date).days
            else:
                features['patch_to_exploit_days'] = 0
                
            if wild_date:
                features['first_seen_wild_days'] = (wild_date - disclosure_date).days
            else:
                features['first_seen_wild_days'] = 0
        else:
            # Default values when dates are missing
            for key in ['vulnerability_age_days', 'disclosure_to_poc_days', 'disclosure_to_exploit_days',
                       'poc_to_exploit_days', 'patch_to_exploit_days', 'first_seen_wild_days']:
                features[key] = 0
        
        # Community activity velocity
        community_data = data.get('community_activity', {})
        features['twitter_mentions_velocity'] = float(community_data.get('twitter_mentions_per_day', 0))
        features['github_activity_velocity'] = float(community_data.get('github_commits_per_day', 0))
        features['blog_posts_velocity'] = float(community_data.get('blog_posts_per_day', 0))
        features['exploit_releases_per_day'] = float(community_data.get('exploit_releases_per_day', 0))
        features['security_advisories_velocity'] = float(community_data.get('advisories_per_day', 0))
        features['cve_updates_velocity'] = float(community_data.get('cve_updates_per_day', 0))
        
        # Interest and complexity indicators
        features['researcher_interest_score'] = float(data.get('researcher_interest', 0))
        features['bounty_program_interest'] = float(data.get('bounty_interest', 0))
        features['technical_analysis_posts'] = float(community_data.get('technical_posts', 0))
        features['technical_difficulty_score'] = float(data.get('technical_difficulty', 0.5))
        
        # Similar vulnerabilities context
        features['similar_vulns_exploited_count'] = float(data.get('similar_exploited_count', 0))
        features['vendor_response_speed'] = float(data.get('vendor_response_days', 30))
        
        # Software and attack characteristics
        features['affected_software_popularity'] = float(data.get('software_popularity_score', 0))
        features['exploit_code_complexity'] = float(data.get('exploit_complexity_score', 0.5))
        features['attack_surface_size'] = float(data.get('attack_surface_score', 0))
        features['required_user_interaction'] = float(data.get('requires_user_interaction', False))
        features['network_accessibility'] = float(data.get('network_accessible', False))
        features['authentication_required'] = float(data.get('authentication_required', True))
        features['payload_delivery_methods'] = float(len(data.get('delivery_methods', [])))
        features['evasion_techniques_count'] = float(len(data.get('evasion_techniques', [])))
        
        return features
    
    def _extract_threat_actor_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for Threat Actor Model"""
        features = {}
        
        # Threat actor interest indicators
        actor_data = data.get('threat_actors', {})
        features['nation_state_interest'] = float(actor_data.get('nation_state_score', 0))
        features['criminal_group_interest'] = float(actor_data.get('criminal_score', 0))
        features['hacktivist_interest'] = float(actor_data.get('hacktivist_score', 0))
        features['insider_threat_potential'] = float(actor_data.get('insider_score', 0))
        features['script_kiddie_accessible'] = float(actor_data.get('script_kiddie_score', 0))
        
        # Capability requirements
        features['required_skill_level'] = float(data.get('required_skill_level', 0.5))
        features['required_resources_level'] = float(data.get('required_resources', 0.5))
        features['operational_complexity'] = float(data.get('operational_complexity', 0.5))
        
        # Motivation factors
        features['financial_motivation_score'] = float(data.get('financial_value', 0))
        features['espionage_value_score'] = float(data.get('espionage_value', 0))
        features['disruption_value_score'] = float(data.get('disruption_potential', 0))
        features['geopolitical_relevance'] = float(data.get('geopolitical_score', 0))
        
        # Target characteristics
        target_data = data.get('target_info', {})
        features['target_industry_attractiveness'] = float(target_data.get('industry_score', 0))
        features['critical_infrastructure_target'] = float(target_data.get('critical_infra', False))
        features['high_value_target_relevance'] = float(target_data.get('high_value_score', 0))
        features['supply_chain_impact_potential'] = float(target_data.get('supply_chain_score', 0))
        
        # Technical capabilities
        tech_data = data.get('technical_requirements', {})
        features['attack_attribution_difficulty'] = float(tech_data.get('attribution_difficulty', 0))
        features['forensic_evasion_potential'] = float(tech_data.get('forensic_evasion', 0))
        features['lateral_movement_potential'] = float(tech_data.get('lateral_movement', 0))
        features['persistence_mechanisms_available'] = float(len(tech_data.get('persistence_methods', [])))
        features['c2_infrastructure_complexity'] = float(tech_data.get('c2_complexity', 0))
        features['payload_sophistication_required'] = float(tech_data.get('payload_sophistication', 0))
        features['anti_analysis_techniques'] = float(len(tech_data.get('anti_analysis', [])))
        
        # Market and campaign indicators
        market_data = data.get('underground_market', {})
        features['zero_day_broker_interest'] = float(market_data.get('broker_interest', 0))
        features['apt_campaign_alignment'] = float(data.get('apt_alignment_score', 0))
        features['ransomware_potential'] = float(data.get('ransomware_potential', 0))
        features['data_exfiltration_value'] = float(data.get('data_value_score', 0))
        
        return features
    
    def _extract_temporal_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for Temporal Model"""
        features = {}
        
        # Parse disclosure timing
        timeline = data.get('timeline', {})
        disclosure_date = self._parse_date(timeline.get('disclosure_date'))
        
        if disclosure_date:
            features['disclosure_month'] = disclosure_date.month
            features['disclosure_day_of_week'] = disclosure_date.weekday()
            features['disclosure_hour'] = disclosure_date.hour
            features['disclosure_quarter'] = (disclosure_date.month - 1) // 3 + 1
            features['days_since_disclosure'] = (datetime.now() - disclosure_date).days
            
            # Calculate days to next Patch Tuesday (second Tuesday of month)
            next_patch_tuesday = self._get_next_patch_tuesday(disclosure_date)
            features['days_to_patch_tuesday'] = (next_patch_tuesday - disclosure_date).days
        else:
            # Default values
            current_date = datetime.now()
            features['disclosure_month'] = current_date.month
            features['disclosure_day_of_week'] = current_date.weekday()
            features['disclosure_hour'] = 12
            features['disclosure_quarter'] = (current_date.month - 1) // 3 + 1
            features['days_since_disclosure'] = 0
            features['days_to_patch_tuesday'] = 7
        
        # Temporal context indicators
        temporal_context = data.get('temporal_context', {})
        features['is_holiday_period'] = float(temporal_context.get('holiday_period', False))
        features['is_summer_vacation'] = float(temporal_context.get('summer_vacation', False))
        features['is_end_of_quarter'] = float(temporal_context.get('end_of_quarter', False))
        features['conference_season_proximity'] = float(temporal_context.get('conference_season', 0))
        features['academic_semester_timing'] = float(temporal_context.get('academic_timing', 0))
        features['geopolitical_tension_level'] = float(temporal_context.get('geopolitical_tension', 0))
        features['cyber_awareness_month'] = float(temporal_context.get('cyber_awareness', False))
        features['black_friday_proximity'] = float(temporal_context.get('black_friday_proximity', 0))
        features['election_period_proximity'] = float(temporal_context.get('election_proximity', 0))
        features['earnings_season_proximity'] = float(temporal_context.get('earnings_season', 0))
        
        # Age and cycle information
        features['vulnerability_age_weeks'] = features['days_since_disclosure'] / 7.0
        features['patch_cycle_position'] = float(temporal_context.get('patch_cycle_position', 0))
        features['maintenance_window_proximity'] = float(temporal_context.get('maintenance_window', 0))
        
        # Timing patterns
        features['weekend_disclosure'] = float(features['disclosure_day_of_week'] >= 5)
        features['business_hours_disclosure'] = float(9 <= features['disclosure_hour'] <= 17)
        features['after_hours_activity'] = float(data.get('after_hours_activity', 0))
        features['time_zone_coordination_factor'] = float(temporal_context.get('timezone_coordination', 0))
        features['working_days_since_disclosure'] = self._calculate_working_days(disclosure_date) if disclosure_date else 0
        features['security_conference_timing'] = float(temporal_context.get('security_conference_timing', 0))
        
        return features
    
    def _extract_practicality_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for Practicality Model"""
        features = {}
        
        # Technical difficulty assessment
        technical_data = data.get('technical_assessment', {})
        features['technical_difficulty_score'] = float(technical_data.get('difficulty_score', 0.5))
        features['required_skill_level'] = float(technical_data.get('skill_level', 0.5))
        features['development_time_estimate'] = float(technical_data.get('dev_time_days', 30))
        features['exploitation_reliability'] = float(technical_data.get('reliability', 0.5))
        features['success_rate_estimate'] = float(technical_data.get('success_rate', 0.5))
        features['payload_complexity'] = float(technical_data.get('payload_complexity', 0.5))
        
        # Resource requirements
        resources_data = data.get('resource_requirements', {})
        features['required_tools_availability'] = float(resources_data.get('tools_availability', 0.5))
        features['specialized_knowledge_needed'] = float(resources_data.get('specialized_knowledge', 0.5))
        
        # Environmental constraints
        env_data = data.get('environmental_constraints', {})
        features['environmental_constraints'] = float(env_data.get('constraints_score', 0))
        features['network_requirements'] = float(env_data.get('network_requirements', 0))
        features['system_requirements'] = float(env_data.get('system_requirements', 0))
        features['user_interaction_complexity'] = float(env_data.get('user_interaction', 0))
        features['social_engineering_required'] = float(env_data.get('social_engineering', False))
        
        # Attack characteristics
        attack_data = data.get('attack_characteristics', {})
        features['multiple_stage_attack'] = float(attack_data.get('multi_stage', False))
        features['persistence_difficulty'] = float(attack_data.get('persistence_difficulty', 0.5))
        features['detection_avoidance_complexity'] = float(attack_data.get('detection_avoidance', 0.5))
        features['forensic_cleanup_difficulty'] = float(attack_data.get('forensic_cleanup', 0.5))
        features['attribution_difficulty'] = float(attack_data.get('attribution_difficulty', 0.5))
        
        # Defensive measures
        defense_data = data.get('defensive_measures', {})
        features['defensive_countermeasures_present'] = float(defense_data.get('countermeasures_score', 0))
        features['waf_bypass_required'] = float(defense_data.get('waf_present', False))
        features['ids_evasion_needed'] = float(defense_data.get('ids_present', False))
        features['antivirus_evasion_required'] = float(defense_data.get('av_detection_rate', 0))
        features['sandbox_evasion_needed'] = float(defense_data.get('sandbox_detection', False))
        
        # Portability and dependencies
        portability_data = data.get('portability', {})
        features['exploit_portability'] = float(portability_data.get('portability_score', 0.5))
        features['target_specificity'] = float(portability_data.get('target_specificity', 0.5))
        features['version_dependency'] = float(portability_data.get('version_dependency', 0.5))
        features['hardware_dependency'] = float(portability_data.get('hardware_dependency', 0))
        features['architecture_dependency'] = float(portability_data.get('architecture_dependency', 0))
        
        # Timing and execution constraints
        timing_data = data.get('timing_constraints', {})
        features['timing_sensitivity'] = float(timing_data.get('timing_sensitive', False))
        features['race_condition_exploitation'] = float(timing_data.get('race_condition', False))
        
        # Reliability factors
        reliability_data = data.get('reliability_factors', {})
        features['memory_corruption_complexity'] = float(reliability_data.get('memory_corruption', 0))
        features['code_execution_reliability'] = float(reliability_data.get('code_execution', 0.5))
        features['privilege_escalation_difficulty'] = float(reliability_data.get('privilege_escalation', 0.5))
        features['lateral_movement_potential'] = float(reliability_data.get('lateral_movement', 0))
        
        return features
    
    def _extract_community_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for Community Model"""
        features = {}
        
        # Social media activity
        social_data = data.get('social_media', {})
        features['twitter_mentions_count'] = float(social_data.get('twitter_mentions', 0))
        features['twitter_retweets_count'] = float(social_data.get('twitter_retweets', 0))
        features['twitter_sentiment_score'] = float(social_data.get('twitter_sentiment', 0))
        features['reddit_posts_count'] = float(social_data.get('reddit_posts', 0))
        features['reddit_upvotes_count'] = float(social_data.get('reddit_upvotes', 0))
        features['reddit_comment_count'] = float(social_data.get('reddit_comments', 0))
        features['hacker_news_mentions'] = float(social_data.get('hn_mentions', 0))
        features['hacker_news_points'] = float(social_data.get('hn_points', 0))
        features['hacker_news_comments'] = float(social_data.get('hn_comments', 0))
        
        # GitHub activity
        github_data = data.get('github_activity', {})
        features['github_repositories_count'] = float(github_data.get('repositories', 0))
        features['github_stars_total'] = float(github_data.get('stars', 0))
        features['github_forks_total'] = float(github_data.get('forks', 0))
        
        # Technical analysis and research
        research_data = data.get('research_activity', {})
        features['security_blog_posts'] = float(research_data.get('blog_posts', 0))
        features['technical_analysis_count'] = float(research_data.get('technical_analysis', 0))
        features['white_paper_references'] = float(research_data.get('white_papers', 0))
        features['conference_presentations'] = float(research_data.get('conference_talks', 0))
        features['webinar_mentions'] = float(research_data.get('webinars', 0))
        features['podcast_discussions'] = float(research_data.get('podcasts', 0))
        features['academic_citations'] = float(research_data.get('academic_citations', 0))
        
        # Official channels
        official_data = data.get('official_channels', {})
        features['cve_database_updates'] = float(official_data.get('cve_updates', 0))
        features['nvd_analysis_count'] = float(official_data.get('nvd_entries', 0))
        features['vendor_advisories_count'] = float(official_data.get('vendor_advisories', 0))
        features['security_firm_reports'] = float(official_data.get('security_reports', 0))
        features['threat_intel_mentions'] = float(official_data.get('threat_intel', 0))
        features['ioc_sharing_activity'] = float(official_data.get('ioc_sharing', 0))
        
        # Researcher and bounty activity
        researcher_data = data.get('researcher_activity', {})
        features['bounty_program_submissions'] = float(researcher_data.get('bounty_submissions', 0))
        features['researcher_interest_score'] = float(researcher_data.get('interest_score', 0))
        
        # Security tools and signatures
        tools_data = data.get('security_tools', {})
        features['security_tool_integration'] = float(tools_data.get('tool_integration', 0))
        features['scanner_signatures_added'] = float(tools_data.get('scanner_signatures', 0))
        features['yara_rules_created'] = float(tools_data.get('yara_rules', 0))
        
        # Exploit databases and frameworks
        exploit_data = data.get('exploit_databases', {})
        features['exploit_db_entries'] = float(exploit_data.get('exploitdb_entries', 0))
        features['metasploit_modules'] = float(exploit_data.get('metasploit_modules', 0))
        features['poc_code_availability'] = float(exploit_data.get('poc_available', 0))
        
        # Community forums and discussions
        forum_data = data.get('forum_activity', {})
        features['security_forum_activity'] = float(forum_data.get('security_forums', 0))
        features['mailing_list_discussions'] = float(forum_data.get('mailing_lists', 0))
        features['discord_chat_activity'] = float(forum_data.get('discord_activity', 0))
        
        return features
    
    def _extract_pattern_features(self, data: Dict) -> Dict[str, float]:
        """Extract features for Pattern Model"""
        features = {}
        
        # Basic vulnerability metadata
        features['cve_year'] = float(self._parse_date(data.get('published_date', '')).year if self._parse_date(data.get('published_date', '')) else 2024)
        features['disclosure_month'] = float(self._parse_date(data.get('published_date', '')).month if self._parse_date(data.get('published_date', '')) else 1)
        
        # Vulnerability classification
        features['vulnerability_type'] = float(self._encode_vulnerability_type(data.get('vulnerability_type', '')))
        features['attack_vector_type'] = float(self._encode_attack_vector(data.get('attack_vector', '')))
        features['affected_software_type'] = float(self._encode_software_type(data.get('affected_software', [])))
        features['vendor_type'] = float(self._encode_vendor_type(data.get('vendor', '')))
        
        # CVSS-based patterns
        cvss_score = data.get('cvss', {}).get('base_score', 0)
        features['cvss_score_range'] = float(self._encode_cvss_range(cvss_score))
        
        # Historical exploitation patterns
        historical_data = data.get('historical_patterns', {})
        features['similar_cves_exploited_count'] = float(historical_data.get('similar_exploited', 0))
        features['same_vendor_exploited_count'] = float(historical_data.get('vendor_exploited', 0))
        features['same_product_exploited_count'] = float(historical_data.get('product_exploited', 0))
        features['same_vulnerability_type_exploited'] = float(historical_data.get('type_exploited_rate', 0))
        features['same_attack_vector_exploited'] = float(historical_data.get('vector_exploited_rate', 0))
        features['historical_exploitation_rate'] = float(historical_data.get('overall_rate', 0))
        
        # Vendor and product history
        vendor_history = data.get('vendor_history', {})
        features['vendor_patch_speed_history'] = float(vendor_history.get('avg_patch_days', 30) / 100.0)  # Normalize
        features['product_exploitation_history'] = float(vendor_history.get('product_exploit_rate', 0))
        features['zero_day_history'] = float(vendor_history.get('zero_day_rate', 0))
        
        # Campaign and actor patterns
        campaign_data = data.get('campaign_patterns', {})
        features['campaign_association_score'] = float(campaign_data.get('campaign_score', 0))
        features['exploit_kit_integration_history'] = float(campaign_data.get('exploit_kit_rate', 0))
        features['apt_group_preference_score'] = float(campaign_data.get('apt_preference', 0))
        features['criminal_group_preference_score'] = float(campaign_data.get('criminal_preference', 0))
        
        # Timeline similarity patterns
        timeline_patterns = data.get('timeline_patterns', {})
        features['exploitation_timeline_similarity'] = float(timeline_patterns.get('timeline_similarity', 0))
        
        # Technical pattern indicators
        technical_patterns = data.get('technical_patterns', {})
        features['attack_complexity_pattern'] = float(technical_patterns.get('complexity_pattern', 0))
        features['payload_type_pattern'] = float(technical_patterns.get('payload_pattern', 0))
        features['persistence_method_pattern'] = float(technical_patterns.get('persistence_pattern', 0))
        features['lateral_movement_pattern'] = float(technical_patterns.get('lateral_pattern', 0))
        features['data_exfiltration_pattern'] = float(technical_patterns.get('exfiltration_pattern', 0))
        
        # Targeting patterns
        targeting_patterns = data.get('targeting_patterns', {})
        features['geographic_targeting_pattern'] = float(targeting_patterns.get('geographic_pattern', 0))
        features['industry_targeting_pattern'] = float(targeting_patterns.get('industry_pattern', 0))
        features['victim_size_pattern'] = float(targeting_patterns.get('victim_size_pattern', 0))
        
        # Temporal patterns
        temporal_patterns = data.get('temporal_patterns', {})
        features['seasonal_exploitation_pattern'] = float(temporal_patterns.get('seasonal_pattern', 0))
        features['day_of_week_pattern'] = float(temporal_patterns.get('day_pattern', 0))
        features['time_of_day_pattern'] = float(temporal_patterns.get('time_pattern', 0))
        
        return features
    
    def _extract_meta_features(self, data: Dict) -> Dict[str, Any]:
        """Extract meta features and data quality indicators"""
        features = {}
        
        # Data completeness indicators
        features['data_completeness_score'] = self._calculate_data_completeness(data)
        features['cvss_data_available'] = float(bool(data.get('cvss')))
        features['epss_data_available'] = float(bool(data.get('epss')))
        features['timeline_data_available'] = float(bool(data.get('timeline')))
        features['community_data_available'] = float(bool(data.get('community_activity')))
        features['threat_actor_data_available'] = float(bool(data.get('threat_actors')))
        
        # Data source reliability
        features['data_source_reliability'] = float(data.get('data_quality', {}).get('reliability_score', 0.5))
        features['last_updated_days'] = float(data.get('data_quality', {}).get('days_since_update', 0))
        
        # Confidence indicators
        features['prediction_confidence_prior'] = float(data.get('confidence_indicators', {}).get('prior_confidence', 0.5))
        
        return features
    
    # Helper methods
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string into datetime object"""
        if not date_str:
            return None
        
        try:
            # Try common date formats
            formats = [
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
                    
            # If none work, try parsing just the date part
            if 'T' in date_str:
                date_part = date_str.split('T')[0]
                return datetime.strptime(date_part, '%Y-%m-%d')
                
        except Exception as e:
            logger.warning(f"Failed to parse date '{date_str}': {e}")
            
        return None
    
    def _parse_cvss_vector(self, vector_string: str) -> Dict[str, float]:
        """Parse CVSS vector string into one-hot encoded features"""
        features = {}
        
        # Initialize all possible values to 0
        cvss_mappings = {
            'attack_vector': ['N', 'A', 'L', 'P'],  # Network, Adjacent, Local, Physical
            'attack_complexity': ['L', 'H'],  # Low, High
            'privileges_required': ['N', 'L', 'H'],  # None, Low, High
            'user_interaction': ['N', 'R'],  # None, Required
            'scope': ['U', 'C'],  # Unchanged, Changed
            'confidentiality_impact': ['H', 'L', 'N'],  # High, Low, None
            'integrity_impact': ['H', 'L', 'N'],
            'availability_impact': ['H', 'L', 'N']
        }
        
        # Initialize all features to 0
        for metric, values in cvss_mappings.items():
            for value in values:
                feature_name = f"{metric}_{value.lower()}"
                if value == 'N' and metric.endswith('_impact'):
                    feature_name = f"{metric}_none"
                elif value == 'N' and metric == 'attack_vector':
                    feature_name = f"{metric}_network"
                elif value == 'N' and metric == 'privileges_required':
                    feature_name = f"{metric}_none"
                elif value == 'N' and metric == 'user_interaction':
                    feature_name = f"{metric}_none"
                elif value == 'A':
                    feature_name = f"{metric}_adjacent"
                elif value == 'P':
                    feature_name = f"{metric}_physical"
                elif value == 'U':
                    feature_name = f"{metric}_unchanged"
                elif value == 'C':
                    feature_name = f"{metric}_changed"
                elif value == 'R':
                    feature_name = f"{metric}_required"
                
                features[feature_name] = 0.0
        
        # Parse the vector string
        if vector_string:
            try:
                parts = vector_string.split('/')
                for part in parts:
                    if ':' in part:
                        key, value = part.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Map CVSS v3 keys to our metric names
                        key_mapping = {
                            'AV': 'attack_vector',
                            'AC': 'attack_complexity',
                            'PR': 'privileges_required',
                            'UI': 'user_interaction',
                            'S': 'scope',
                            'C': 'confidentiality_impact',
                            'I': 'integrity_impact',
                            'A': 'availability_impact'
                        }
                        
                        if key in key_mapping:
                            metric = key_mapping[key]
                            feature_name = f"{metric}_{value.lower()}"
                            
                            # Handle special cases
                            if value == 'N' and metric.endswith('_impact'):
                                feature_name = f"{metric}_none"
                            elif value == 'N' and metric == 'attack_vector':
                                feature_name = f"{metric}_network"
                            elif value == 'N' and metric == 'privileges_required':
                                feature_name = f"{metric}_none"
                            elif value == 'N' and metric == 'user_interaction':
                                feature_name = f"{metric}_none"
                            elif value == 'A' and metric == 'attack_vector':
                                feature_name = f"{metric}_adjacent"
                            elif value == 'P':
                                feature_name = f"{metric}_physical"
                            elif value == 'U':
                                feature_name = f"{metric}_unchanged"
                            elif value == 'C' and metric == 'scope':
                                feature_name = f"{metric}_changed"
                            elif value == 'R':
                                feature_name = f"{metric}_required"
                            
                            if feature_name in features:
                                features[feature_name] = 1.0
                                
            except Exception as e:
                logger.warning(f"Failed to parse CVSS vector '{vector_string}': {e}")
        
        return features
    
    def _extract_cwe_features(self, cwe_list: List) -> Dict[str, float]:
        """Extract CWE-based features"""
        features = {}
        
        # Initialize all CWE categories to 0
        for category in self.cwe_categories.keys():
            features[f'cwe_{category}'] = 0.0
        
        # Process CWE list
        if cwe_list:
            for cwe_item in cwe_list:
                cwe_id = None
                
                if isinstance(cwe_item, dict):
                    cwe_id = cwe_item.get('id')
                elif isinstance(cwe_item, str):
                    # Extract CWE ID from string like "CWE-79"
                    match = re.search(r'CWE-(\d+)', cwe_item)
                    if match:
                        cwe_id = int(match.group(1))
                elif isinstance(cwe_item, int):
                    cwe_id = cwe_item
                
                if cwe_id:
                    # Check which category this CWE belongs to
                    for category, cwe_ids in self.cwe_categories.items():
                        if cwe_id in cwe_ids:
                            features[f'cwe_{category}'] = 1.0
                            break
        
        return features
    
    def _encode_vulnerability_type(self, vuln_type: str) -> int:
        """Encode vulnerability type as integer"""
        type_mapping = {
            'buffer_overflow': 1, 'sql_injection': 2, 'xss': 3, 'rce': 4,
            'directory_traversal': 5, 'csrf': 6, 'xxe': 7, 'deserialization': 8,
            'authentication': 9, 'authorization': 10, 'other': 0
        }
        
        vuln_type_lower = vuln_type.lower() if vuln_type else ''
        for key, value in type_mapping.items():
            if key in vuln_type_lower:
                return value
        return 0
    
    def _encode_attack_vector(self, attack_vector: str) -> int:
        """Encode attack vector as integer"""
        vector_mapping = {'network': 1, 'adjacent': 2, 'local': 3, 'physical': 4}
        
        attack_vector_lower = attack_vector.lower() if attack_vector else ''
        for key, value in vector_mapping.items():
            if key in attack_vector_lower:
                return value
        return 0
    
    def _encode_software_type(self, affected_software: List) -> int:
        """Encode affected software type"""
        if not affected_software:
            return 0
            
        # Count different software types
        software_types = set()
        for software in affected_software:
            if isinstance(software, dict):
                product = software.get('product', '').lower()
                vendor = software.get('vendor', '').lower()
            else:
                product = str(software).lower()
                vendor = ''
            
            if any(os_name in product or os_name in vendor for os_name in ['windows', 'linux', 'macos']):
                software_types.add('os')
            elif any(app_name in product for app_name in ['browser', 'chrome', 'firefox', 'safari']):
                software_types.add('browser')
            elif any(server_name in product for server_name in ['apache', 'nginx', 'iis']):
                software_types.add('server')
            else:
                software_types.add('application')
        
        # Return encoded value based on software type diversity
        return len(software_types)
    
    def _encode_vendor_type(self, vendor: str) -> int:
        """Encode vendor type as integer"""
        if not vendor:
            return 0
            
        vendor_lower = vendor.lower()
        for category, vendors in self.vendor_categories.items():
            if any(v in vendor_lower for v in vendors):
                return hash(category) % 100  # Simple hash to integer
        
        return hash(vendor_lower) % 100
    
    def _encode_cvss_range(self, cvss_score: float) -> int:
        """Encode CVSS score into range categories"""
        if cvss_score == 0:
            return 0
        elif cvss_score < 4.0:
            return 1  # Low
        elif cvss_score < 7.0:
            return 2  # Medium
        elif cvss_score < 9.0:
            return 3  # High
        else:
            return 4  # Critical
    
    def _get_next_patch_tuesday(self, date: datetime) -> datetime:
        """Calculate next Patch Tuesday (second Tuesday of the month)"""
        # Start with first day of current month
        first_of_month = date.replace(day=1)
        
        # Find first Tuesday of the month
        days_ahead = 1 - first_of_month.weekday()  # Tuesday is 1
        if days_ahead <= 0:  # Target day already happened this week
            days_ahead += 7
        
        first_tuesday = first_of_month + timedelta(days=days_ahead)
        second_tuesday = first_tuesday + timedelta(days=7)
        
        # If we're past this month's Patch Tuesday, get next month's
        if date > second_tuesday:
            if first_of_month.month == 12:
                next_month = first_of_month.replace(year=first_of_month.year + 1, month=1)
            else:
                next_month = first_of_month.replace(month=first_of_month.month + 1)
            
            return self._get_next_patch_tuesday(next_month)
        
        return second_tuesday
    
    def _calculate_working_days(self, start_date: datetime) -> float:
        """Calculate working days since start date"""
        if not start_date:
            return 0
            
        current_date = datetime.now()
        total_days = (current_date - start_date).days
        
        # Simple approximation: 5/7 of days are working days
        return total_days * (5.0 / 7.0)
    
    def _calculate_data_completeness(self, data: Dict) -> float:
        """Calculate overall data completeness score"""
        required_fields = [
            'cvss', 'timeline', 'affected_software', 'references'
        ]
        
        optional_fields = [
            'epss', 'community_activity', 'threat_actors', 'technical_assessment'
        ]
        
        # Check required fields
        required_score = sum(1 for field in required_fields if data.get(field)) / len(required_fields)
        
        # Check optional fields
        optional_score = sum(1 for field in optional_fields if data.get(field)) / len(optional_fields)
        
        # Weight required fields more heavily
        return required_score * 0.7 + optional_score * 0.3