"""
NOPE Data Collection Agent

This module provides the data collection agent implementation
for gathering CVE data from external sources.
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from nope.agents.base import BaseAgent, AgentTask
from nope.core.exceptions import ExternalAPIError, RateLimitExceededError


class DataCollectionAgent(BaseAgent):
    """
    Data collection agent for gathering CVE data from external sources.
    
    Supports multiple data sources including:
    - NIST NVD (National Vulnerability Database)
    - MITRE CVE Database
    - CISA KEV (Known Exploited Vulnerabilities)
    - GitHub Security Advisories
    """
    
    def __init__(
        self,
        name: str = "DataCollectionAgent",
        sources: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize data collection agent.
        
        Args:
            name: Agent name
            sources: List of data sources to collect from
            config: Agent configuration
        """
        super().__init__(name, "data_collection", config)
        
        self.sources = sources or ["nvd", "mitre", "cisa", "github"]
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Source configurations
        self.source_configs = {
            "nvd": {
                "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "api_key": self.settings.nvd_api_key,
                "rate_limit": 50,  # requests per minute
                "batch_size": 1000,
            },
            "mitre": {
                "base_url": "https://cve.mitre.org/data/downloads",
                "rate_limit": 30,
                "batch_size": 500,
            },
            "cisa": {
                "base_url": "https://www.cisa.gov/sites/default/files/csv",
                "rate_limit": 20,
                "batch_size": 100,
            },
            "github": {
                "base_url": "https://api.github.com/advisories",
                "api_key": self.settings.github_token,
                "rate_limit": 60,
                "batch_size": 200,
            },
        }
    
    async def initialize(self) -> None:
        """Initialize HTTP session and validate configurations."""
        self.logger.info("Initializing data collection agent")
        
        # Create HTTP session with timeout
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        # Validate source configurations
        for source in self.sources:
            if source not in self.source_configs:
                raise ValueError(f"Unknown data source: {source}")
            
            config = self.source_configs[source]
            if config.get("api_key") is None and source in ["nvd", "github"]:
                self.logger.warning(f"No API key configured for {source}")
        
        self.logger.info(f"Initialized with sources: {self.sources}")
    
    async def cleanup(self) -> None:
        """Clean up HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
        
        self.logger.info("Data collection agent cleaned up")
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute data collection task.
        
        Args:
            task: Task to execute
            
        Returns:
            Collection results
        """
        task_name = task.name.lower()
        
        if task_name == "collect_all":
            return await self._collect_from_all_sources(task.parameters)
        elif task_name == "collect_source":
            source = task.parameters.get("source")
            if not source:
                raise ValueError("Source parameter required for collect_source task")
            return await self._collect_from_source(source, task.parameters)
        elif task_name == "collect_recent":
            return await self._collect_recent_cves(task.parameters)
        else:
            raise ValueError(f"Unknown task: {task_name}")
    
    async def _collect_from_all_sources(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect data from all configured sources.
        
        Args:
            params: Collection parameters
            
        Returns:
            Combined collection results
        """
        results = {}
        errors = {}
        
        # Collect from each source concurrently
        tasks = [
            self._collect_from_source(source, params)
            for source in self.sources
        ]
        
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        for source, result in zip(self.sources, completed_tasks):
            if isinstance(result, Exception):
                errors[source] = str(result)
                self.logger.error(f"Error collecting from {source}: {result}")
            else:
                results[source] = result
        
        return {
            "sources_collected": len(results),
            "sources_failed": len(errors),
            "results": results,
            "errors": errors,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    async def _collect_from_source(
        self,
        source: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Collect data from a specific source.
        
        Args:
            source: Data source name
            params: Collection parameters
            
        Returns:
            Source-specific collection results
        """
        if source not in self.source_configs:
            raise ValueError(f"Unknown source: {source}")
        
        config = self.source_configs[source]
        
        if source == "nvd":
            return await self._collect_nvd_data(config, params)
        elif source == "mitre":
            return await self._collect_mitre_data(config, params)
        elif source == "cisa":
            return await self._collect_cisa_data(config, params)
        elif source == "github":
            return await self._collect_github_data(config, params)
        else:
            raise ValueError(f"Collection not implemented for source: {source}")
    
    async def _collect_nvd_data(
        self,
        config: Dict[str, Any],
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Collect CVE data from NIST NVD.
        
        Args:
            config: NVD configuration
            params: Collection parameters
            
        Returns:
            NVD collection results
        """
        self.logger.info("Collecting data from NIST NVD")
        
        headers = {}
        if config.get("api_key"):
            headers["apiKey"] = config["api_key"]
        
        # Build query parameters
        query_params = {
            "resultsPerPage": config["batch_size"],
            "startIndex": params.get("start_index", 0),
        }
        
        # Add time filters if specified
        if params.get("last_modified_start"):
            query_params["lastModStartDate"] = params["last_modified_start"]
        if params.get("last_modified_end"):
            query_params["lastModEndDate"] = params["last_modified_end"]
        
        # Add severity filter if specified
        if params.get("cvss_severity"):
            query_params["cvssV3Severity"] = params["cvss_severity"]
        
        try:
            async with self.session.get(
                config["base_url"],
                headers=headers,
                params=query_params
            ) as response:
                
                # Check for rate limiting
                if response.status == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise RateLimitExceededError(
                        "NVD API rate limit exceeded",
                        source="nvd",
                        retry_after=retry_after
                    )
                
                response.raise_for_status()
                data = await response.json()
                
                cves = data.get("vulnerabilities", [])
                
                return {
                    "source": "nvd",
                    "total_results": data.get("totalResults", 0),
                    "results_per_page": data.get("resultsPerPage", 0),
                    "start_index": data.get("startIndex", 0),
                    "cves_collected": len(cves),
                    "cves": cves,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
        except aiohttp.ClientError as e:
            raise ExternalAPIError(
                f"Failed to collect from NVD: {e}",
                source="nvd",
                api_url=config["base_url"]
            )
    
    async def _collect_mitre_data(
        self,
        config: Dict[str, Any],
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Collect CVE data from MITRE.
        
        Args:
            config: MITRE configuration
            params: Collection parameters
            
        Returns:
            MITRE collection results
        """
        self.logger.info("Collecting data from MITRE CVE")
        
        # MITRE provides CSV downloads of all CVE data
        csv_url = urljoin(config["base_url"], "allitems.csv")
        
        try:
            async with self.session.get(csv_url) as response:
                response.raise_for_status()
                csv_data = await response.text()
                
                # Parse CSV data (simplified - would need proper CSV parsing)
                lines = csv_data.strip().split('\n')
                headers = lines[0].split(',') if lines else []
                rows = [line.split(',') for line in lines[1:]]
                
                return {
                    "source": "mitre",
                    "total_results": len(rows),
                    "headers": headers,
                    "cves_collected": len(rows),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
        except aiohttp.ClientError as e:
            raise ExternalAPIError(
                f"Failed to collect from MITRE: {e}",
                source="mitre",
                api_url=csv_url
            )
    
    async def _collect_cisa_data(
        self,
        config: Dict[str, Any],  
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Collect Known Exploited Vulnerabilities from CISA.
        
        Args:
            config: CISA configuration
            params: Collection parameters
            
        Returns:
            CISA collection results
        """
        self.logger.info("Collecting data from CISA KEV")
        
        kev_url = urljoin(config["base_url"], "known_exploited_vulnerabilities.csv")
        
        try:
            async with self.session.get(kev_url) as response:
                response.raise_for_status()
                csv_data = await response.text()
                
                # Parse CSV data
                lines = csv_data.strip().split('\n')
                headers = lines[0].split(',') if lines else []
                rows = [line.split(',') for line in lines[1:]]
                
                return {
                    "source": "cisa",
                    "total_results": len(rows),
                    "headers": headers,
                    "kevs_collected": len(rows),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
        except aiohttp.ClientError as e:
            raise ExternalAPIError(
                f"Failed to collect from CISA: {e}",
                source="cisa",
                api_url=kev_url
            )
    
    async def _collect_github_data(
        self,
        config: Dict[str, Any],
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Collect security advisories from GitHub.
        
        Args:
            config: GitHub configuration
            params: Collection parameters
            
        Returns:
            GitHub collection results
        """
        self.logger.info("Collecting data from GitHub Security Advisories")
        
        headers = {}
        if config.get("api_key"):
            headers["Authorization"] = f"token {config['api_key']}"
        headers["Accept"] = "application/vnd.github.v3+json"
        
        # Build query parameters
        query_params = {
            "per_page": min(config["batch_size"], 100),  # GitHub max is 100
            "page": params.get("page", 1),
        }
        
        # Add severity filter if specified
        if params.get("severity"):
            query_params["severity"] = params["severity"]
        
        try:
            async with self.session.get(
                config["base_url"],
                headers=headers,
                params=query_params
            ) as response:
                
                # Check for rate limiting
                if response.status == 403:
                    reset_time = response.headers.get("X-RateLimit-Reset")
                    raise RateLimitExceededError(
                        "GitHub API rate limit exceeded",
                        source="github",
                        retry_after=int(reset_time) if reset_time else 3600
                    )
                
                response.raise_for_status()
                advisories = await response.json()
                
                return {
                    "source": "github",
                    "advisories_collected": len(advisories),
                    "advisories": advisories,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
        except aiohttp.ClientError as e:
            raise ExternalAPIError(
                f"Failed to collect from GitHub: {e}",
                source="github",
                api_url=config["base_url"]
            )
    
    async def _collect_recent_cves(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collect recently updated CVEs from all sources.
        
        Args:
            params: Collection parameters
            
        Returns:
            Recent CVE collection results
        """
        # Set time filter for recent data (last 24 hours by default)
        hours_back = params.get("hours_back", 24)
        from datetime import timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        # Add time filter to parameters
        recent_params = params.copy()
        recent_params["last_modified_start"] = cutoff_time.isoformat()
        
        return await self._collect_from_all_sources(recent_params)