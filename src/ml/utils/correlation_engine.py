"""
Real-Time Correlation Engine

Correlates real-time threat intelligence with vulnerability predictions.
Provides dynamic risk scoring and threat correlation capabilities.
"""

import asyncio
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import threading
import time
from loguru import logger


@dataclass
class ThreatIntelligence:
    """Structure for threat intelligence data"""
    source: str
    intelligence_type: str  # 'ioc', 'campaign', 'actor', 'technique'
    content: Dict[str, Any]
    confidence: float
    timestamp: datetime
    expiry: Optional[datetime]
    tags: List[str]
    severity: str  # 'low', 'medium', 'high', 'critical'


@dataclass
class CorrelationResult:
    """Structure for correlation results"""
    vulnerability_id: str
    correlation_score: float
    correlation_type: str
    intelligence_sources: List[str]
    risk_adjustment: float
    evidence: List[Dict[str, Any]]
    timestamp: datetime


class RealTimeCorrelationEngine:
    """
    Real-time correlation engine that correlates threat intelligence
    with vulnerability predictions to provide dynamic risk scoring
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._get_default_config()
        
        # Threat intelligence storage
        self.threat_intel_buffer = deque(maxlen=self.config['buffer_size'])
        self.active_campaigns = {}
        self.known_actors = {}
        self.ioc_database = defaultdict(list)
        
        # Correlation state
        self.correlation_rules = self._load_correlation_rules()
        self.correlation_history = deque(maxlen=self.config['correlation_history_size'])
        self.risk_adjustments = {}
        
        # Real-time processing
        self.processing_queue = asyncio.Queue()
        self.correlation_cache = {}
        self.cache_expiry = {}
        
        # Background tasks
        self.running = False
        self.processing_task = None
        self.cleanup_task = None
        
        # Correlation metrics
        self.correlation_stats = {
            'processed_intel': 0,
            'correlations_found': 0,
            'risk_adjustments': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        logger.info("Real-time correlation engine initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'buffer_size': 10000,
            'correlation_history_size': 5000,
            'cache_ttl_seconds': 300,  # 5 minutes
            'cleanup_interval_seconds': 60,
            'correlation_threshold': 0.3,
            'risk_adjustment_max': 0.5,
            'intel_freshness_hours': 24,
            'correlation_weights': {
                'ioc_match': 0.8,
                'campaign_association': 0.7,
                'actor_attribution': 0.6,
                'technique_similarity': 0.5,
                'temporal_correlation': 0.4
            }
        }
    
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load correlation rules configuration"""
        return {
            'ioc_correlations': {
                'ip_addresses': {'weight': 0.8, 'decay_hours': 48},
                'domain_names': {'weight': 0.7, 'decay_hours': 72},
                'file_hashes': {'weight': 0.9, 'decay_hours': 168},
                'urls': {'weight': 0.6, 'decay_hours': 24}
            },
            'campaign_correlations': {
                'vulnerability_types': {'weight': 0.7, 'decay_hours': 168},
                'target_industries': {'weight': 0.6, 'decay_hours': 168},
                'attack_patterns': {'weight': 0.8, 'decay_hours': 168}
            },
            'actor_correlations': {
                'ttps': {'weight': 0.8, 'decay_hours': 720},  # 30 days
                'target_preferences': {'weight': 0.7, 'decay_hours': 720},
                'tool_usage': {'weight': 0.6, 'decay_hours': 720}
            },
            'temporal_correlations': {
                'exploit_timing': {'weight': 0.5, 'decay_hours': 72},
                'campaign_timing': {'weight': 0.6, 'decay_hours': 168}
            }
        }
    
    async def start(self):
        """Start the real-time correlation engine"""
        if self.running:
            logger.warning("Correlation engine is already running")
            return
        
        self.running = True
        
        # Start background tasks
        self.processing_task = asyncio.create_task(self._process_intelligence_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Real-time correlation engine started")
    
    async def stop(self):
        """Stop the real-time correlation engine"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        if self.processing_task:
            self.processing_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        # Wait for tasks to complete
        try:
            await asyncio.gather(self.processing_task, self.cleanup_task, return_exceptions=True)
        except:
            pass
        
        logger.info("Real-time correlation engine stopped")
    
    async def ingest_threat_intelligence(self, intel: ThreatIntelligence):
        """
        Ingest new threat intelligence data
        
        Args:
            intel: ThreatIntelligence object
        """
        # Validate intelligence
        if not self._validate_intelligence(intel):
            logger.warning(f"Invalid threat intelligence from {intel.source}")
            return
        
        # Add to buffer
        self.threat_intel_buffer.append(intel)
        
        # Queue for processing
        await self.processing_queue.put(intel)
        
        # Update statistics
        self.correlation_stats['processed_intel'] += 1
        
        # Store in appropriate database
        await self._store_intelligence(intel)
        
        logger.debug(f"Ingested {intel.intelligence_type} intelligence from {intel.source}")
    
    async def correlate_vulnerability(self, vulnerability_data: Dict[str, Any]) -> List[CorrelationResult]:
        """
        Correlate a vulnerability with current threat intelligence
        
        Args:
            vulnerability_data: Vulnerability information
            
        Returns:
            List of correlation results
        """
        vuln_id = vulnerability_data.get('id', 'unknown')
        
        # Check cache first
        cache_key = self._generate_cache_key(vulnerability_data)
        if self._is_cache_valid(cache_key):
            self.correlation_stats['cache_hits'] += 1
            return self.correlation_cache[cache_key]
        
        self.correlation_stats['cache_misses'] += 1
        
        correlations = []
        
        # IOC correlations
        ioc_correlations = await self._correlate_iocs(vulnerability_data)
        correlations.extend(ioc_correlations)
        
        # Campaign correlations
        campaign_correlations = await self._correlate_campaigns(vulnerability_data)
        correlations.extend(campaign_correlations)
        
        # Actor correlations
        actor_correlations = await self._correlate_actors(vulnerability_data)
        correlations.extend(actor_correlations)
        
        # Technique correlations
        technique_correlations = await self._correlate_techniques(vulnerability_data)
        correlations.extend(technique_correlations)
        
        # Temporal correlations
        temporal_correlations = await self._correlate_temporal_patterns(vulnerability_data)
        correlations.extend(temporal_correlations)
        
        # Sort by correlation score
        correlations.sort(key=lambda x: x.correlation_score, reverse=True)
        
        # Cache results
        self.correlation_cache[cache_key] = correlations
        self.cache_expiry[cache_key] = datetime.now() + timedelta(seconds=self.config['cache_ttl_seconds'])
        
        if correlations:
            self.correlation_stats['correlations_found'] += len(correlations)
            logger.info(f"Found {len(correlations)} correlations for vulnerability {vuln_id}")
        
        return correlations
    
    async def calculate_dynamic_risk_score(self, vulnerability_data: Dict[str, Any],
                                         base_score: float) -> Tuple[float, Dict[str, Any]]:
        """
        Calculate dynamic risk score based on threat intelligence correlations
        
        Args:
            vulnerability_data: Vulnerability information
            base_score: Base prediction score
            
        Returns:
            Tuple of (adjusted_score, adjustment_details)
        """
        vuln_id = vulnerability_data.get('id', 'unknown')
        
        # Get correlations
        correlations = await self.correlate_vulnerability(vulnerability_data)
        
        if not correlations:
            return base_score, {'adjustments': [], 'total_adjustment': 0.0}
        
        # Calculate risk adjustments
        total_adjustment = 0.0
        adjustments = []
        
        for correlation in correlations:
            # Calculate adjustment based on correlation score and type
            adjustment_weight = self.config['correlation_weights'].get(
                correlation.correlation_type, 0.5
            )
            
            risk_adjustment = correlation.correlation_score * adjustment_weight * correlation.risk_adjustment
            risk_adjustment = min(risk_adjustment, self.config['risk_adjustment_max'])
            
            total_adjustment += risk_adjustment
            
            adjustments.append({
                'type': correlation.correlation_type,
                'sources': correlation.intelligence_sources,
                'correlation_score': correlation.correlation_score,
                'risk_adjustment': risk_adjustment,
                'evidence_count': len(correlation.evidence)
            })
        
        # Cap total adjustment
        total_adjustment = min(total_adjustment, self.config['risk_adjustment_max'])
        
        # Calculate adjusted score
        adjusted_score = min(base_score + total_adjustment, 1.0)
        
        adjustment_details = {
            'adjustments': adjustments,
            'total_adjustment': total_adjustment,
            'base_score': base_score,
            'adjusted_score': adjusted_score,
            'correlation_count': len(correlations)
        }
        
        # Update statistics
        if total_adjustment > 0:
            self.correlation_stats['risk_adjustments'] += 1
        
        logger.info(f"Dynamic risk score for {vuln_id}: {base_score:.3f} -> {adjusted_score:.3f} "
                   f"(+{total_adjustment:.3f})")
        
        return adjusted_score, adjustment_details
    
    async def get_active_threats(self, threat_types: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Get currently active threats by type
        
        Args:
            threat_types: List of threat types to filter by
            
        Returns:
            Dictionary of active threats by type
        """
        current_time = datetime.now()
        active_threats = defaultdict(list)
        
        # Filter threat intelligence by freshness and type
        for intel in self.threat_intel_buffer:
            # Check freshness
            age_hours = (current_time - intel.timestamp).total_seconds() / 3600
            if age_hours > self.config['intel_freshness_hours']:
                continue
            
            # Check expiry
            if intel.expiry and current_time > intel.expiry:
                continue
            
            # Filter by type if specified
            if threat_types and intel.intelligence_type not in threat_types:
                continue
            
            threat_info = {
                'source': intel.source,
                'content': intel.content,
                'confidence': intel.confidence,
                'timestamp': intel.timestamp.isoformat(),
                'tags': intel.tags,
                'severity': intel.severity,
                'age_hours': age_hours
            }
            
            active_threats[intel.intelligence_type].append(threat_info)
        
        # Sort by confidence and recency
        for threat_type, threats in active_threats.items():
            threats.sort(key=lambda x: (x['confidence'], -x['age_hours']), reverse=True)
        
        return dict(active_threats)
    
    def get_correlation_statistics(self) -> Dict[str, Any]:
        """Get correlation engine statistics"""
        stats = self.correlation_stats.copy()
        
        stats.update({
            'threat_intel_buffer_size': len(self.threat_intel_buffer),
            'active_campaigns': len(self.active_campaigns),
            'known_actors': len(self.known_actors),
            'ioc_database_size': sum(len(iocs) for iocs in self.ioc_database.values()),
            'correlation_cache_size': len(self.correlation_cache),
            'correlation_history_size': len(self.correlation_history),
            'engine_running': self.running
        })
        
        # Calculate rates
        if stats['processed_intel'] > 0:
            stats['correlation_rate'] = stats['correlations_found'] / stats['processed_intel']
            stats['risk_adjustment_rate'] = stats['risk_adjustments'] / stats['processed_intel']
        else:
            stats['correlation_rate'] = 0.0
            stats['risk_adjustment_rate'] = 0.0
        
        # Cache hit rate
        total_cache_requests = stats['cache_hits'] + stats['cache_misses']
        if total_cache_requests > 0:
            stats['cache_hit_rate'] = stats['cache_hits'] / total_cache_requests
        else:
            stats['cache_hit_rate'] = 0.0
        
        return stats
    
    # Private methods
    
    async def _process_intelligence_loop(self):
        """Background task to process intelligence queue"""
        while self.running:
            try:
                # Process with timeout to allow periodic cleanup
                intel = await asyncio.wait_for(
                    self.processing_queue.get(), 
                    timeout=1.0
                )
                
                await self._process_intelligence(intel)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing intelligence: {e}")
    
    async def _cleanup_loop(self):
        """Background task for periodic cleanup"""
        while self.running:
            try:
                await asyncio.sleep(self.config['cleanup_interval_seconds'])
                await self._cleanup_expired_data()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def _process_intelligence(self, intel: ThreatIntelligence):
        """Process individual threat intelligence"""
        try:
            # Extract and index relevant information
            if intel.intelligence_type == 'campaign':
                await self._process_campaign_intel(intel)
            elif intel.intelligence_type == 'actor':
                await self._process_actor_intel(intel)
            elif intel.intelligence_type == 'ioc':
                await self._process_ioc_intel(intel)
            elif intel.intelligence_type == 'technique':
                await self._process_technique_intel(intel)
            
        except Exception as e:
            logger.error(f"Error processing {intel.intelligence_type} intelligence: {e}")
    
    async def _store_intelligence(self, intel: ThreatIntelligence):
        """Store intelligence in appropriate databases"""
        if intel.intelligence_type == 'ioc':
            ioc_type = intel.content.get('type', 'unknown')
            self.ioc_database[ioc_type].append(intel)
        elif intel.intelligence_type == 'campaign':
            campaign_id = intel.content.get('campaign_id')
            if campaign_id:
                self.active_campaigns[campaign_id] = intel
        elif intel.intelligence_type == 'actor':
            actor_id = intel.content.get('actor_id')
            if actor_id:
                self.known_actors[actor_id] = intel
    
    def _validate_intelligence(self, intel: ThreatIntelligence) -> bool:
        """Validate threat intelligence data"""
        if not intel.source or not intel.intelligence_type:
            return False
        
        if not isinstance(intel.content, dict):
            return False
        
        if not 0 <= intel.confidence <= 1:
            return False
        
        if intel.expiry and intel.expiry <= intel.timestamp:
            return False
        
        return True
    
    def _generate_cache_key(self, vulnerability_data: Dict[str, Any]) -> str:
        """Generate cache key for vulnerability data"""
        vuln_id = vulnerability_data.get('id', 'unknown')
        # Include relevant fields that affect correlation
        key_fields = {
            'id': vuln_id,
            'cve_id': vulnerability_data.get('cve_id'),
            'vulnerability_type': vulnerability_data.get('vulnerability_type'),
            'affected_software': vulnerability_data.get('affected_software'),
            'attack_vector': vulnerability_data.get('attack_vector')
        }
        
        key_str = json.dumps(key_fields, sort_keys=True)
        return f"vuln_{hash(key_str)}"
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is valid"""
        if cache_key not in self.correlation_cache:
            return False
        
        if cache_key not in self.cache_expiry:
            return False
        
        return datetime.now() < self.cache_expiry[cache_key]
    
    async def _correlate_iocs(self, vulnerability_data: Dict[str, Any]) -> List[CorrelationResult]:
        """Correlate with IOC data"""
        correlations = []
        vuln_id = vulnerability_data.get('id', 'unknown')
        
        # Look for IOC matches in vulnerability data
        for ioc_type, iocs in self.ioc_database.items():
            for intel in iocs:
                correlation_score = self._calculate_ioc_correlation(vulnerability_data, intel)
                
                if correlation_score >= self.config['correlation_threshold']:
                    correlations.append(CorrelationResult(
                        vulnerability_id=vuln_id,
                        correlation_score=correlation_score,
                        correlation_type='ioc_match',
                        intelligence_sources=[intel.source],
                        risk_adjustment=correlation_score * 0.3,
                        evidence=[{
                            'type': 'ioc_match',
                            'ioc_type': ioc_type,
                            'content': intel.content,
                            'confidence': intel.confidence
                        }],
                        timestamp=datetime.now()
                    ))
        
        return correlations
    
    async def _correlate_campaigns(self, vulnerability_data: Dict[str, Any]) -> List[CorrelationResult]:
        """Correlate with campaign data"""
        correlations = []
        vuln_id = vulnerability_data.get('id', 'unknown')
        
        for campaign_id, intel in self.active_campaigns.items():
            correlation_score = self._calculate_campaign_correlation(vulnerability_data, intel)
            
            if correlation_score >= self.config['correlation_threshold']:
                correlations.append(CorrelationResult(
                    vulnerability_id=vuln_id,
                    correlation_score=correlation_score,
                    correlation_type='campaign_association',
                    intelligence_sources=[intel.source],
                    risk_adjustment=correlation_score * 0.4,
                    evidence=[{
                        'type': 'campaign_association',
                        'campaign_id': campaign_id,
                        'content': intel.content,
                        'confidence': intel.confidence
                    }],
                    timestamp=datetime.now()
                ))
        
        return correlations
    
    async def _correlate_actors(self, vulnerability_data: Dict[str, Any]) -> List[CorrelationResult]:
        """Correlate with threat actor data"""
        correlations = []
        vuln_id = vulnerability_data.get('id', 'unknown')
        
        for actor_id, intel in self.known_actors.items():
            correlation_score = self._calculate_actor_correlation(vulnerability_data, intel)
            
            if correlation_score >= self.config['correlation_threshold']:
                correlations.append(CorrelationResult(
                    vulnerability_id=vuln_id,
                    correlation_score=correlation_score,
                    correlation_type='actor_attribution',
                    intelligence_sources=[intel.source],
                    risk_adjustment=correlation_score * 0.35,
                    evidence=[{
                        'type': 'actor_attribution',
                        'actor_id': actor_id,
                        'content': intel.content,
                        'confidence': intel.confidence
                    }],
                    timestamp=datetime.now()
                ))
        
        return correlations
    
    async def _correlate_techniques(self, vulnerability_data: Dict[str, Any]) -> List[CorrelationResult]:
        """Correlate with technique data"""
        correlations = []
        # Implementation depends on technique database structure
        return correlations
    
    async def _correlate_temporal_patterns(self, vulnerability_data: Dict[str, Any]) -> List[CorrelationResult]:
        """Correlate with temporal patterns"""
        correlations = []
        # Implementation for temporal correlation
        return correlations
    
    def _calculate_ioc_correlation(self, vulnerability_data: Dict[str, Any], 
                                 intel: ThreatIntelligence) -> float:
        """Calculate IOC correlation score"""
        # Simplified correlation calculation
        # In practice, this would involve complex matching logic
        base_score = intel.confidence
        
        # Adjust based on IOC type and content
        ioc_content = intel.content
        ioc_type = ioc_content.get('type', 'unknown')
        
        # Apply decay based on age
        age_hours = (datetime.now() - intel.timestamp).total_seconds() / 3600
        decay_hours = self.correlation_rules['ioc_correlations'].get(ioc_type, {}).get('decay_hours', 24)
        decay_factor = max(0, 1 - (age_hours / decay_hours))
        
        return base_score * decay_factor
    
    def _calculate_campaign_correlation(self, vulnerability_data: Dict[str, Any],
                                      intel: ThreatIntelligence) -> float:
        """Calculate campaign correlation score"""
        base_score = intel.confidence
        
        # Apply temporal decay
        age_hours = (datetime.now() - intel.timestamp).total_seconds() / 3600
        decay_factor = max(0, 1 - (age_hours / 168))  # 7 days decay
        
        return base_score * decay_factor
    
    def _calculate_actor_correlation(self, vulnerability_data: Dict[str, Any],
                                   intel: ThreatIntelligence) -> float:
        """Calculate actor correlation score"""
        base_score = intel.confidence
        
        # Apply temporal decay (longer for actor intelligence)
        age_hours = (datetime.now() - intel.timestamp).total_seconds() / 3600
        decay_factor = max(0, 1 - (age_hours / 720))  # 30 days decay
        
        return base_score * decay_factor
    
    async def _cleanup_expired_data(self):
        """Clean up expired data from caches and databases"""
        current_time = datetime.now()
        
        # Clean correlation cache
        expired_keys = [
            key for key, expiry in self.cache_expiry.items()
            if current_time > expiry
        ]
        
        for key in expired_keys:
            self.correlation_cache.pop(key, None)
            self.cache_expiry.pop(key, None)
        
        # Clean IOC database
        intel_freshness_threshold = current_time - timedelta(hours=self.config['intel_freshness_hours'])
        
        for ioc_type in list(self.ioc_database.keys()):
            self.ioc_database[ioc_type] = [
                intel for intel in self.ioc_database[ioc_type]
                if intel.timestamp > intel_freshness_threshold and
                (not intel.expiry or intel.expiry > current_time)
            ]
            
            if not self.ioc_database[ioc_type]:
                del self.ioc_database[ioc_type]
        
        # Clean campaigns and actors
        expired_campaigns = [
            campaign_id for campaign_id, intel in self.active_campaigns.items()
            if intel.timestamp < intel_freshness_threshold or
            (intel.expiry and intel.expiry <= current_time)
        ]
        
        for campaign_id in expired_campaigns:
            del self.active_campaigns[campaign_id]
        
        expired_actors = [
            actor_id for actor_id, intel in self.known_actors.items()
            if intel.timestamp < intel_freshness_threshold or
            (intel.expiry and intel.expiry <= current_time)
        ]
        
        for actor_id in expired_actors:
            del self.known_actors[actor_id]
        
        if expired_keys or expired_campaigns or expired_actors:
            logger.debug(f"Cleaned up {len(expired_keys)} cache entries, "
                        f"{len(expired_campaigns)} campaigns, {len(expired_actors)} actors")
    
    async def _process_campaign_intel(self, intel: ThreatIntelligence):
        """Process campaign intelligence"""
        # Extract campaign-specific information
        campaign_content = intel.content
        campaign_id = campaign_content.get('campaign_id')
        
        if campaign_id:
            self.active_campaigns[campaign_id] = intel
    
    async def _process_actor_intel(self, intel: ThreatIntelligence):
        """Process actor intelligence"""
        # Extract actor-specific information
        actor_content = intel.content
        actor_id = actor_content.get('actor_id')
        
        if actor_id:
            self.known_actors[actor_id] = intel
    
    async def _process_ioc_intel(self, intel: ThreatIntelligence):
        """Process IOC intelligence"""
        # IOCs are already stored in _store_intelligence
        pass
    
    async def _process_technique_intel(self, intel: ThreatIntelligence):
        """Process technique intelligence"""
        # Implementation for technique processing
        pass