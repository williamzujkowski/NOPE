"""
deps.dev Package Dependency Impact Agent

This agent enriches CVE data with package dependency information from deps.dev,
analyzing supply chain impact and dependency tree implications.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
import aiohttp
import json
import re
from urllib.parse import quote

from ..base_agent import BaseAgent, AgentResult


class AsyncLimiter:
    """Simple async rate limiter"""
    
    def __init__(self, calls: int, period: float):
        self.calls = calls
        self.period = period
        self.call_times = []
    
    async def __aenter__(self):
        now = asyncio.get_event_loop().time()
        
        # Remove old calls outside the period
        self.call_times = [t for t in self.call_times if now - t < self.period]
        
        # Wait if we've hit the limit
        if len(self.call_times) >= self.calls:
            sleep_time = self.period - (now - self.call_times[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        self.call_times.append(now)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class DepsDevAgent(BaseAgent):
    """Agent for enriching CVEs with package dependency data from deps.dev"""
    
    def __init__(self):
        super().__init__("DepsDevAgent")
        self.base_url = "https://api.deps.dev/v3alpha"
        self.rate_limiter = AsyncLimiter(10, 1)  # 10 requests per second
        self.package_cache = {}
        self.ecosystem_mappings = {
            "npm": "NPM",
            "pypi": "PyPI", 
            "maven": "Maven",
            "nuget": "NuGet",
            "cargo": "Cargo",
            "go": "Go",
            "packagist": "Packagist"
        }
        
    async def initialize(self) -> bool:
        """Initialize agent"""
        init_success = await super().initialize()
        if not init_success:
            return False
            
        await self.notify_progress("Initialized deps.dev agent with rate limiting")
        return True
    
    def extract_packages_from_cve(self, cve: Dict) -> List[Dict]:
        """Extract package information from CVE data"""
        packages = []
        
        # Extract from CVE description
        description = cve.get("description", "").lower()
        
        # Common package patterns
        package_patterns = [
            # NPM packages
            (r'npm\s+package\s+([a-z0-9-_.]+)', "npm"),
            (r'node\.js\s+package\s+([a-z0-9-_.]+)', "npm"),
            (r'javascript\s+library\s+([a-z0-9-_.]+)', "npm"),
            
            # Python packages
            (r'python\s+package\s+([a-z0-9-_.]+)', "pypi"),
            (r'pypi\s+package\s+([a-z0-9-_.]+)', "pypi"),
            (r'pip\s+package\s+([a-z0-9-_.]+)', "pypi"),
            
            # Maven packages
            (r'maven\s+artifact\s+([a-z0-9-_.]+)', "maven"),
            (r'java\s+library\s+([a-z0-9-_.]+)', "maven"),
            
            # Go modules
            (r'go\s+module\s+([a-z0-9-_.\/]+)', "go"),
            (r'golang\s+package\s+([a-z0-9-_.\/]+)', "go"),
            
            # Generic patterns
            (r'package\s+([a-z0-9-_.]+)', "unknown"),
            (r'library\s+([a-z0-9-_.]+)', "unknown")
        ]
        
        for pattern, ecosystem in package_patterns:
            matches = re.findall(pattern, description)
            for match in matches:
                # Clean up the match
                package_name = match.strip()
                if len(package_name) > 2 and not package_name.startswith('.'):
                    packages.append({
                        "name": package_name,
                        "ecosystem": ecosystem,
                        "source": "cve_description"
                    })
        
        # Extract from CVE metadata if available
        if "affected" in cve:
            for affected in cve["affected"]:
                package_info = affected.get("package", {})
                if package_info:
                    ecosystem = package_info.get("ecosystem", "unknown").lower()
                    name = package_info.get("name", "")
                    
                    if name:
                        packages.append({
                            "name": name,
                            "ecosystem": ecosystem,
                            "versions": affected.get("ranges", []),
                            "source": "cve_metadata"
                        })
        
        # Deduplicate packages
        seen = set()
        unique_packages = []
        for pkg in packages:
            key = (pkg["name"], pkg["ecosystem"])
            if key not in seen:
                seen.add(key)
                unique_packages.append(pkg)
        
        return unique_packages
    
    async def get_package_info(self, ecosystem: str, package_name: str) -> Optional[Dict]:
        """Get package information from deps.dev"""
        
        # Normalize ecosystem name
        normalized_ecosystem = self.ecosystem_mappings.get(ecosystem.lower(), ecosystem.upper())
        
        cache_key = f"{normalized_ecosystem}:{package_name}"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data:
            return cached_data
        
        try:
            async with self.rate_limiter:
                url = f"{self.base_url}/systems/{normalized_ecosystem}/packages/{quote(package_name)}"
                
                response = await self.safe_http_request("GET", url)
                if response:
                    # Cache for 24 hours
                    await self.cache.set(cache_key, response, tier="all", ttl=24*3600)
                    return response
                else:
                    return None
                    
        except Exception as e:
            self.logger.error(
                "package_info_fetch_failed",
                ecosystem=normalized_ecosystem,
                package=package_name,
                error=str(e)
            )
            return None
    
    async def get_dependent_count(self, ecosystem: str, package_name: str) -> int:
        """Get number of packages that depend on this package"""
        
        normalized_ecosystem = self.ecosystem_mappings.get(ecosystem.lower(), ecosystem.upper())
        
        try:
            async with self.rate_limiter:
                url = f"{self.base_url}/systems/{normalized_ecosystem}/packages/{quote(package_name)}/dependents"
                
                response = await self.safe_http_request("GET", url)
                if response and "dependents" in response:
                    return len(response["dependents"])
                else:
                    return 0
                    
        except Exception as e:
            self.logger.error(
                "dependent_count_fetch_failed",
                ecosystem=normalized_ecosystem,
                package=package_name,
                error=str(e)
            )
            return 0
    
    async def analyze_package_impact(self, package: Dict) -> Optional[Dict]:
        """Analyze the impact of a specific package"""
        
        ecosystem = package.get("ecosystem", "unknown")
        name = package.get("name", "")
        
        if not name or ecosystem == "unknown":
            return None
        
        try:
            # Get package metadata
            package_info = await self.get_package_info(ecosystem, name)
            if not package_info:
                return None
            
            # Get dependent count
            dependent_count = await self.get_dependent_count(ecosystem, name)
            
            # Extract scores if available
            scorecard = package_info.get("scorecard", {})
            
            impact_data = {
                "ecosystem": ecosystem,
                "package": name,
                "versions": package.get("versions", []),
                "dependent_count": dependent_count,
                "popularity_score": scorecard.get("popularity", 0),
                "maintenance_score": scorecard.get("maintenance", 0), 
                "security_score": scorecard.get("security", 0),
                "overall_score": scorecard.get("overall", 0),
                "package_url": package_info.get("packageKey", {}).get("name", ""),
                "source_repository": self.extract_source_repo(package_info),
                "impact_level": self.calculate_impact_level(dependent_count),
                "risk_factors": self.identify_risk_factors(package_info, dependent_count)
            }
            
            return impact_data
            
        except Exception as e:
            self.logger.error(
                "package_impact_analysis_failed",
                ecosystem=ecosystem,
                package=name,
                error=str(e)
            )
            return None
    
    def extract_source_repo(self, package_info: Dict) -> Optional[str]:
        """Extract source repository URL from package info"""
        
        # Try different possible locations for source repo
        possible_paths = [
            ["links", "repository"],
            ["links", "homepage"],  
            ["sourceRepository"],
            ["repository", "url"]
        ]
        
        for path in possible_paths:
            current = package_info
            for key in path:
                current = current.get(key, {})
                if isinstance(current, str):
                    if "github.com" in current or "gitlab.com" in current:
                        return current
                    break
                elif not isinstance(current, dict):
                    break
        
        return None
    
    def calculate_impact_level(self, dependent_count: int) -> str:
        """Calculate impact level based on dependent count"""
        if dependent_count > 100000:
            return "critical"
        elif dependent_count > 10000:
            return "high"
        elif dependent_count > 1000:
            return "medium"
        elif dependent_count > 100:
            return "low"
        else:
            return "minimal"
    
    def identify_risk_factors(self, package_info: Dict, dependent_count: int) -> List[str]:
        """Identify risk factors for the package"""
        risk_factors = []
        
        # High dependency count
        if dependent_count > 50000:
            risk_factors.append("extremely_high_dependency_count")
        elif dependent_count > 10000:
            risk_factors.append("high_dependency_count")
        
        # Security score analysis
        scorecard = package_info.get("scorecard", {})
        security_score = scorecard.get("security", 0)
        
        if security_score < 0.3:
            risk_factors.append("low_security_score")
        
        maintenance_score = scorecard.get("maintenance", 0)
        if maintenance_score < 0.3:
            risk_factors.append("poor_maintenance")
        
        # Check for critical package patterns
        package_name = package_info.get("packageKey", {}).get("name", "").lower()
        critical_patterns = [
            "core", "common", "util", "base", "foundation", 
            "framework", "runtime", "engine", "library"
        ]
        
        if any(pattern in package_name for pattern in critical_patterns):
            risk_factors.append("critical_infrastructure_package")
        
        return risk_factors
    
    def calculate_supply_chain_risk(self, package_impacts: List[Dict]) -> str:
        """Calculate overall supply chain risk level"""
        if not package_impacts:
            return "unknown"
        
        max_dependents = max([p.get("dependent_count", 0) for p in package_impacts])
        critical_packages = sum(1 for p in package_impacts if p.get("impact_level") == "critical")
        high_packages = sum(1 for p in package_impacts if p.get("impact_level") == "high")
        
        # Critical if any package has critical impact or multiple high impact
        if critical_packages > 0 or (high_packages >= 2 and max_dependents > 50000):
            return "critical"
        elif high_packages > 0 or max_dependents > 10000:
            return "high"
        elif max_dependents > 1000:
            return "medium"
        elif max_dependents > 100:
            return "low"
        else:
            return "minimal"
    
    async def enrich_cve(self, cve: Dict) -> Dict:
        """Enrich CVE with package dependency data"""
        cve_id = cve.get("cve_id")
        if not cve_id:
            self.logger.warning("missing_cve_id", cve=cve)
            return cve
        
        try:
            # Extract package information from CVE
            packages = self.extract_packages_from_cve(cve)
            
            if not packages:
                # No packages identified
                cve["package_impact"] = {
                    "total_packages": 0,
                    "analyzed_packages": 0,
                    "max_dependent_count": 0,
                    "affected_ecosystems": [],
                    "supply_chain_risk": "unknown",
                    "packages": []
                }
                
                if "enrichment_metadata" not in cve:
                    cve["enrichment_metadata"] = {}
                
                cve["enrichment_metadata"]["deps_dev"] = {
                    "enriched_at": datetime.now().isoformat(),
                    "agent_version": "1.0",
                    "data_source": "deps.dev API",
                    "success": True,
                    "packages_found": 0
                }
                
                return cve
            
            await self.notify_progress(f"Analyzing {len(packages)} packages for {cve_id}")
            
            # Analyze each package
            package_impacts = []
            for package in packages:
                impact_data = await self.analyze_package_impact(package)
                if impact_data:
                    package_impacts.append(impact_data)
                    
                # Small delay to be respectful to API
                await asyncio.sleep(0.1)
            
            # Calculate aggregate statistics
            total_packages = len(packages)
            analyzed_packages = len(package_impacts)
            max_dependent_count = max([p.get("dependent_count", 0) for p in package_impacts], default=0)
            affected_ecosystems = list(set([p.get("ecosystem") for p in package_impacts]))
            supply_chain_risk = self.calculate_supply_chain_risk(package_impacts)
            
            # Calculate risk score contribution
            risk_score_contribution = self.calculate_risk_score_contribution(package_impacts, supply_chain_risk)
            
            cve["package_impact"] = {
                "total_packages": total_packages,
                "analyzed_packages": analyzed_packages,
                "max_dependent_count": max_dependent_count,
                "affected_ecosystems": affected_ecosystems,
                "supply_chain_risk": supply_chain_risk,
                "risk_score_contribution": risk_score_contribution,
                "packages": package_impacts,
                "summary": {
                    "critical_packages": sum(1 for p in package_impacts if p.get("impact_level") == "critical"),
                    "high_impact_packages": sum(1 for p in package_impacts if p.get("impact_level") == "high"),
                    "total_dependents": sum(p.get("dependent_count", 0) for p in package_impacts),
                    "avg_security_score": sum(p.get("security_score", 0) for p in package_impacts) / len(package_impacts) if package_impacts else 0
                }
            }
            
            # Store coordination data
            await self.hooks.post_edit(
                file=f"enrichment/deps/{cve_id}.json",
                memory_key=f"agent/deps/{cve_id}"
            )
            
            await self.notify_progress(
                f"Completed deps.dev analysis for {cve_id}: {analyzed_packages}/{total_packages} packages, risk={supply_chain_risk}"
            )
            
            # Update enrichment metadata
            if "enrichment_metadata" not in cve:
                cve["enrichment_metadata"] = {}
            
            cve["enrichment_metadata"]["deps_dev"] = {
                "enriched_at": datetime.now().isoformat(),
                "agent_version": "1.0", 
                "data_source": "deps.dev API",
                "success": True,
                "packages_found": total_packages,
                "packages_analyzed": analyzed_packages
            }
            
            return cve
            
        except Exception as e:
            self.logger.error("cve_deps_enrichment_failed", cve_id=cve_id, error=str(e))
            
            # Add minimal package impact data to maintain schema
            cve["package_impact"] = {
                "total_packages": 0,
                "analyzed_packages": 0,
                "max_dependent_count": 0,
                "affected_ecosystems": [],
                "supply_chain_risk": "unknown",
                "risk_score_contribution": 0,
                "packages": [],
                "summary": {
                    "critical_packages": 0,
                    "high_impact_packages": 0,
                    "total_dependents": 0,
                    "avg_security_score": 0
                }
            }
            
            # Add error metadata
            if "enrichment_metadata" not in cve:
                cve["enrichment_metadata"] = {}
            
            cve["enrichment_metadata"]["deps_dev"] = {
                "enriched_at": datetime.now().isoformat(),
                "agent_version": "1.0",
                "data_source": "deps.dev API",
                "success": False,
                "error": str(e)
            }
            
            return cve
    
    def calculate_risk_score_contribution(self, package_impacts: List[Dict], supply_chain_risk: str) -> int:
        """Calculate risk score contribution (0-20 points)"""
        
        risk_multipliers = {
            "critical": 20,
            "high": 15,
            "medium": 10,
            "low": 5,
            "minimal": 2,
            "unknown": 0
        }
        
        return risk_multipliers.get(supply_chain_risk, 0)