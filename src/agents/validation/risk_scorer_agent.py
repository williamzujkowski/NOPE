"""
Risk Scorer Agent

This agent calculates comprehensive risk scores for CVEs based on multiple factors
including CVSS, EPSS, CISA KEV status, exploit availability, and package impact.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import json
import math

from ..base_agent import BaseAgent, AgentResult


class RiskScorerAgent(BaseAgent):
    """Agent for calculating composite risk scores for CVEs"""
    
    def __init__(self):
        super().__init__("RiskScorerAgent")
        
        # Risk scoring weights (must sum to 1.0)
        self.weights = {
            "cvss_score": 0.25,          # 25% - Technical severity
            "epss_score": 0.35,          # 35% - Exploitation probability (highest weight)
            "cisa_kev": 0.20,           # 20% - Known exploitation
            "exploit_availability": 0.15, # 15% - Public exploits
            "package_impact": 0.05       # 5% - Supply chain impact
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            "critical": 90,
            "high": 70,
            "elevated": 50,
            "medium": 30,
            "low": 0
        }
        
        # Temporal decay factors
        self.temporal_factors = {
            "cve_age_days": 365,  # CVEs older than 1 year get slight reduction
            "kev_recency_bonus": 30,  # KEVs added in last 30 days get bonus
            "exploit_recency_bonus": 60  # Exploits published in last 60 days get bonus
        }
        
    async def initialize(self) -> bool:
        """Initialize agent"""
        init_success = await super().initialize()
        if not init_success:
            return False
            
        # Validate weights sum to 1.0
        weight_sum = sum(self.weights.values())
        if abs(weight_sum - 1.0) > 0.01:
            self.logger.error("invalid_weight_configuration", weight_sum=weight_sum)
            return False
            
        await self.notify_progress(f"Initialized risk scorer with {len(self.weights)} factors")
        return True
    
    def score_cvss_component(self, cve: Dict) -> Tuple[float, Dict]:
        """Score CVSS component (0-100)"""
        
        cvss_data = cve.get("cvss", {})
        base_score = cvss_data.get("baseScore", 0)
        
        if base_score == 0:
            return 0.0, {"base_score": 0, "normalized_score": 0, "notes": "No CVSS score available"}
        
        # Normalize CVSS (0-10) to 0-100 scale
        normalized_score = (base_score / 10.0) * 100
        
        # Apply modifiers based on CVSS vector
        vector = cvss_data.get("vector", "")
        modifiers = []
        modifier_value = 1.0
        
        # Network accessible vulnerabilities get slight bonus
        if "AV:N" in vector:
            modifier_value *= 1.1
            modifiers.append("network_accessible")
        
        # No authentication required gets bonus
        if "PR:N" in vector:
            modifier_value *= 1.05
            modifiers.append("no_auth_required")
        
        # No user interaction gets bonus
        if "UI:N" in vector:
            modifier_value *= 1.05
            modifiers.append("no_user_interaction")
        
        final_score = min(100, normalized_score * modifier_value)
        
        return final_score, {
            "base_score": base_score,
            "normalized_score": normalized_score,
            "modifiers": modifiers,
            "modifier_multiplier": modifier_value,
            "final_score": final_score
        }
    
    def score_epss_component(self, cve: Dict) -> Tuple[float, Dict]:
        """Score EPSS component (0-100)"""
        
        epss_data = cve.get("epss", {})
        epss_score = epss_data.get("score", 0)
        percentile = epss_data.get("percentile", 0)
        
        if epss_score == 0:
            return 0.0, {"epss_score": 0, "percentile": 0, "notes": "No EPSS score available"}
        
        # Convert EPSS (0-1) to 0-100 scale
        base_score = epss_score * 100
        
        # Apply percentile bonus - top percentile CVEs get extra points
        percentile_bonus = 0
        if percentile >= 0.99:  # Top 1%
            percentile_bonus = 15
        elif percentile >= 0.95:  # Top 5%
            percentile_bonus = 10
        elif percentile >= 0.90:  # Top 10%
            percentile_bonus = 5
        
        final_score = min(100, base_score + percentile_bonus)
        
        return final_score, {
            "epss_score": epss_score,
            "percentile": percentile,
            "base_score": base_score,
            "percentile_bonus": percentile_bonus,
            "final_score": final_score
        }
    
    def score_cisa_kev_component(self, cve: Dict) -> Tuple[float, Dict]:
        """Score CISA KEV component (0-100)"""
        
        kev_data = cve.get("cisa_kev", {})
        
        if not kev_data.get("is_known_exploited", False):
            return 0.0, {"is_kev": False, "final_score": 0}
        
        # Base score for being in KEV
        base_score = 75
        
        # Ransomware campaign bonus
        ransomware_bonus = 0
        if kev_data.get("known_ransomware_campaign_use") == "Known":
            ransomware_bonus = 20
        
        # Recency bonus - recently added KEVs are higher risk
        recency_bonus = 0
        date_added = kev_data.get("date_added")
        if date_added:
            try:
                added_date = datetime.strptime(date_added, "%Y-%m-%d")
                days_since_added = (datetime.now() - added_date).days
                
                if days_since_added <= 7:
                    recency_bonus = 15
                elif days_since_added <= 30:
                    recency_bonus = 10
                elif days_since_added <= 90:
                    recency_bonus = 5
                    
            except ValueError:
                pass
        
        # Overdue penalty/bonus
        overdue_factor = 0
        if kev_data.get("is_overdue"):
            overdue_factor = 5  # Overdue KEVs are higher priority
        
        final_score = min(100, base_score + ransomware_bonus + recency_bonus + overdue_factor)
        
        return final_score, {
            "is_kev": True,
            "base_score": base_score,
            "ransomware_bonus": ransomware_bonus,
            "recency_bonus": recency_bonus,
            "overdue_factor": overdue_factor,
            "days_since_added": kev_data.get("days_since_kev_addition"),
            "final_score": final_score
        }
    
    def score_exploit_availability_component(self, cve: Dict) -> Tuple[float, Dict]:
        """Score exploit availability component (0-100)"""
        
        exploit_data = cve.get("exploit_availability", {})
        
        if not exploit_data.get("exploits_available", False):
            return 0.0, {"exploits_available": False, "final_score": 0}
        
        # Base scoring by maturity
        maturity = exploit_data.get("exploit_maturity", "none")
        maturity_scores = {
            "weaponized": 90,      # Metasploit modules
            "functional": 70,      # Working exploits
            "proof_of_concept": 50, # PoC code
            "detection_rule": 30,   # Detection templates
            "none": 0
        }
        
        base_score = maturity_scores.get(maturity, 0)
        
        # Multiple sources bonus
        source_count = len([s for s in exploit_data.get("exploit_sources", {}).values() if s])
        source_bonus = min(15, source_count * 3)  # Up to 15 points for multiple sources
        
        # Verified exploits bonus
        verified_count = exploit_data.get("verified_exploits", 0)
        verified_bonus = min(10, verified_count * 2)  # Up to 10 points for verified
        
        # Recency bonus - recent exploits are more dangerous
        recency_bonus = 0
        days_since_first = exploit_data.get("days_since_first_exploit")
        if days_since_first is not None:
            if days_since_first <= 7:
                recency_bonus = 10
            elif days_since_first <= 30:
                recency_bonus = 7
            elif days_since_first <= 90:
                recency_bonus = 5
        
        final_score = min(100, base_score + source_bonus + verified_bonus + recency_bonus)
        
        return final_score, {
            "exploits_available": True,
            "maturity": maturity,
            "base_score": base_score,
            "source_bonus": source_bonus,
            "verified_bonus": verified_bonus,
            "recency_bonus": recency_bonus,
            "total_exploits": exploit_data.get("total_exploits", 0),
            "final_score": final_score
        }
    
    def score_package_impact_component(self, cve: Dict) -> Tuple[float, Dict]:
        """Score package impact component (0-100)"""
        
        package_data = cve.get("package_impact", {})
        
        if not package_data or package_data.get("total_packages", 0) == 0:
            return 0.0, {"has_packages": False, "final_score": 0}
        
        # Base scoring by supply chain risk
        supply_chain_risk = package_data.get("supply_chain_risk", "unknown")
        risk_scores = {
            "critical": 90,
            "high": 70,
            "medium": 50,
            "low": 30,
            "minimal": 15,
            "unknown": 0
        }
        
        base_score = risk_scores.get(supply_chain_risk, 0)
        
        # Dependent count bonus
        max_dependents = package_data.get("max_dependent_count", 0)
        dependent_bonus = 0
        if max_dependents > 1000000:
            dependent_bonus = 10
        elif max_dependents > 100000:
            dependent_bonus = 8
        elif max_dependents > 10000:
            dependent_bonus = 6
        elif max_dependents > 1000:
            dependent_bonus = 4
        elif max_dependents > 100:
            dependent_bonus = 2
        
        # Ecosystem diversity bonus
        ecosystems = package_data.get("affected_ecosystems", [])
        ecosystem_bonus = min(5, len(ecosystems))  # Up to 5 points for multiple ecosystems
        
        final_score = min(100, base_score + dependent_bonus + ecosystem_bonus)
        
        return final_score, {
            "has_packages": True,
            "supply_chain_risk": supply_chain_risk,
            "base_score": base_score,
            "dependent_bonus": dependent_bonus,
            "ecosystem_bonus": ecosystem_bonus,
            "max_dependents": max_dependents,
            "ecosystems_count": len(ecosystems),
            "final_score": final_score
        }
    
    def apply_temporal_factors(self, base_score: float, cve: Dict, component_scores: Dict) -> Tuple[float, Dict]:
        """Apply temporal factors to adjust risk score"""
        
        temporal_adjustments = {
            "cve_age_factor": 1.0,
            "kev_recency_factor": 1.0,
            "exploit_recency_factor": 1.0
        }
        
        # CVE age factor - very old CVEs get slight reduction unless actively exploited
        cve_published = cve.get("published")
        if cve_published:
            try:
                pub_date = datetime.fromisoformat(cve_published.replace('Z', '+00:00'))
                days_old = (datetime.now(pub_date.tzinfo) - pub_date).days
                
                # Only apply age penalty if not actively exploited
                kev_data = cve.get("cisa_kev", {})
                if not kev_data.get("is_known_exploited") and days_old > 365:
                    # Gradual reduction for very old CVEs
                    age_factor = max(0.85, 1.0 - (days_old - 365) / 3650)  # 15% max reduction over 10 years
                    temporal_adjustments["cve_age_factor"] = age_factor
                    
            except (ValueError, TypeError):
                pass
        
        # Recent KEV addition bonus
        kev_data = cve.get("cisa_kev", {})
        days_since_kev = kev_data.get("days_since_kev_addition")
        if days_since_kev is not None and days_since_kev <= 30:
            temporal_adjustments["kev_recency_factor"] = 1.1  # 10% bonus
        
        # Recent exploit bonus
        exploit_data = cve.get("exploit_availability", {})
        days_since_exploit = exploit_data.get("days_since_first_exploit")
        if days_since_exploit is not None and days_since_exploit <= 60:
            temporal_adjustments["exploit_recency_factor"] = 1.05  # 5% bonus
        
        # Apply all temporal factors
        final_multiplier = 1.0
        for factor in temporal_adjustments.values():
            final_multiplier *= factor
        
        adjusted_score = min(100, base_score * final_multiplier)
        
        return adjusted_score, temporal_adjustments
    
    def determine_risk_level(self, risk_score: int) -> str:
        """Determine risk level from score"""
        
        for level, threshold in self.risk_thresholds.items():
            if risk_score >= threshold:
                return level
        
        return "low"
    
    def generate_risk_summary(self, risk_score: int, risk_level: str, component_breakdown: Dict) -> str:
        """Generate human-readable risk summary"""
        
        # Find top contributing factors
        contributions = []
        for component, data in component_breakdown.items():
            if isinstance(data, dict) and data.get("final_score", 0) > 0:
                weight = self.weights.get(component, 0)
                contribution = data["final_score"] * weight
                contributions.append((component, contribution, data))
        
        contributions.sort(key=lambda x: x[1], reverse=True)
        
        summary_parts = [f"Risk Score: {risk_score}/100 ({risk_level.upper()})"]
        
        if contributions:
            top_factor = contributions[0]
            component_name = top_factor[0].replace("_", " ").title()
            summary_parts.append(f"Primary risk driver: {component_name}")
            
            # Add specific details for top factor
            factor_data = top_factor[2]
            if top_factor[0] == "cisa_kev" and factor_data.get("is_kev"):
                if factor_data.get("ransomware_bonus", 0) > 0:
                    summary_parts.append("⚠️ Used in ransomware campaigns")
                if factor_data.get("recency_bonus", 0) > 0:
                    summary_parts.append("🔥 Recently added to KEV")
            
            elif top_factor[0] == "exploit_availability" and factor_data.get("exploits_available"):
                maturity = factor_data.get("maturity", "")
                if maturity == "weaponized":
                    summary_parts.append("🚨 Weaponized exploits available")
                elif maturity == "functional":
                    summary_parts.append("⚡ Functional exploits available")
            
            elif top_factor[0] == "epss_score":
                percentile = component_breakdown.get("epss_score", {}).get("percentile", 0)
                if percentile >= 0.99:
                    summary_parts.append("📈 Top 1% exploitation probability")
                elif percentile >= 0.95:
                    summary_parts.append("📊 Top 5% exploitation probability")
        
        return " | ".join(summary_parts)
    
    async def calculate_risk_score(self, cve: Dict) -> Dict:
        """Calculate comprehensive risk score for a CVE"""
        
        cve_id = cve.get("cve_id", "unknown")
        
        try:
            # Calculate component scores
            cvss_score, cvss_breakdown = self.score_cvss_component(cve)
            epss_score, epss_breakdown = self.score_epss_component(cve)
            kev_score, kev_breakdown = self.score_cisa_kev_component(cve)
            exploit_score, exploit_breakdown = self.score_exploit_availability_component(cve)
            package_score, package_breakdown = self.score_package_impact_component(cve)
            
            # Store component scores
            component_scores = {
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "cisa_kev": kev_score,
                "exploit_availability": exploit_score,
                "package_impact": package_score
            }
            
            component_breakdown = {
                "cvss_score": cvss_breakdown,
                "epss_score": epss_breakdown,
                "cisa_kev": kev_breakdown,
                "exploit_availability": exploit_breakdown,
                "package_impact": package_breakdown
            }
            
            # Calculate weighted composite score
            composite_score = sum(
                score * self.weights[component]
                for component, score in component_scores.items()
            )
            
            # Apply temporal factors
            final_score, temporal_factors = self.apply_temporal_factors(
                composite_score, cve, component_breakdown
            )
            
            # Round to integer
            risk_score = int(round(final_score))
            risk_level = self.determine_risk_level(risk_score)
            risk_summary = self.generate_risk_summary(risk_score, risk_level, component_breakdown)
            
            return {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_summary": risk_summary,
                "component_scores": component_scores,
                "component_breakdown": component_breakdown,
                "weights_used": self.weights,
                "temporal_factors": temporal_factors,
                "calculation_metadata": {
                    "calculated_at": datetime.now().isoformat(),
                    "agent_version": "1.0",
                    "methodology": "NOPE Composite Risk Scoring v1.0"
                }
            }
            
        except Exception as e:
            self.logger.error("risk_score_calculation_failed", cve_id=cve_id, error=str(e))
            
            # Return minimal risk data
            return {
                "risk_score": 0,
                "risk_level": "unknown",
                "risk_summary": f"Risk calculation failed: {str(e)}",
                "component_scores": {},
                "component_breakdown": {},
                "weights_used": self.weights,
                "temporal_factors": {},
                "calculation_metadata": {
                    "calculated_at": datetime.now().isoformat(),
                    "agent_version": "1.0",
                    "methodology": "NOPE Composite Risk Scoring v1.0",
                    "error": str(e)
                }
            }
    
    async def enrich_cve(self, cve: Dict) -> Dict:
        """Enrich CVE with risk score data"""
        cve_id = cve.get("cve_id")
        if not cve_id:
            self.logger.warning("missing_cve_id", cve=cve)
            return cve
        
        try:
            # Calculate risk score
            risk_data = await self.calculate_risk_score(cve)
            
            # Add risk data to CVE
            cve.update({
                "risk_score": risk_data["risk_score"],
                "risk_level": risk_data["risk_level"],
                "risk_summary": risk_data["risk_summary"],
                "risk_score_breakdown": {
                    "component_scores": risk_data["component_scores"],
                    "component_breakdown": risk_data["component_breakdown"],
                    "weights": risk_data["weights_used"],
                    "temporal_factors": risk_data["temporal_factors"]
                }
            })
            
            # Store coordination data
            await self.hooks.post_edit(
                file=f"enrichment/risk/{cve_id}.json",
                memory_key=f"agent/risk/{cve_id}"
            )
            
            await self.notify_progress(
                f"Risk score calculated for {cve_id}: {risk_data['risk_score']}/100 ({risk_data['risk_level']})"
            )
            
            # Update enrichment metadata
            if "enrichment_metadata" not in cve:
                cve["enrichment_metadata"] = {}
            
            cve["enrichment_metadata"]["risk_scorer"] = {
                "enriched_at": datetime.now().isoformat(),
                "agent_version": "1.0",
                "methodology": "NOPE Composite Risk Scoring v1.0",
                "success": True,
                "risk_score": risk_data["risk_score"]
            }
            
            return cve
            
        except Exception as e:
            self.logger.error("cve_risk_scoring_failed", cve_id=cve_id, error=str(e))
            
            # Add minimal risk data to maintain schema
            cve.update({
                "risk_score": 0,
                "risk_level": "unknown",
                "risk_summary": f"Risk scoring failed: {str(e)}",
                "risk_score_breakdown": {
                    "component_scores": {},
                    "component_breakdown": {},
                    "weights": self.weights,
                    "temporal_factors": {}
                }
            })
            
            # Add error metadata
            if "enrichment_metadata" not in cve:
                cve["enrichment_metadata"] = {}
            
            cve["enrichment_metadata"]["risk_scorer"] = {
                "enriched_at": datetime.now().isoformat(),
                "agent_version": "1.0",
                "methodology": "NOPE Composite Risk Scoring v1.0",
                "success": False,
                "error": str(e)
            }
            
            return cve