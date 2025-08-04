"""
CISA KEV (Known Exploited Vulnerabilities) Enrichment Agent

This agent enriches CVE data with CISA Known Exploited Vulnerability catalog information,
providing critical intelligence about vulnerabilities that are actively being exploited.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import aiohttp
import json

from ..base_agent import BaseAgent, AgentResult


class CISAKEVAgent(BaseAgent):
    """Agent for enriching CVEs with CISA KEV data"""
    
    def __init__(self):
        super().__init__("CISAKEVAgent")
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.cache_ttl = 24 * 3600  # 24 hours
        self.kev_catalog = None
        self.last_fetch = None
        
    async def initialize(self) -> bool:
        """Initialize agent and fetch KEV catalog"""
        init_success = await super().initialize()
        if not init_success:
            return False
            
        try:
            # Pre-fetch KEV catalog
            await self.fetch_kev_catalog()
            
            await self.notify_progress(
                f"Initialized with {len(self.kev_catalog.get('vulnerabilities', []))} KEV entries"
            )
            
            return True
            
        except Exception as e:
            self.logger.error("kev_catalog_fetch_failed", error=str(e))
            return False
    
    async def fetch_kev_catalog(self) -> Dict:
        """Fetch and cache CISA KEV catalog"""
        cache_key = "cisa_kev_catalog"
        
        # Check cache first
        cached_data = await self.cache.get(cache_key)
        if cached_data and self.kev_catalog is None:
            self.kev_catalog = cached_data
            self.logger.info("kev_catalog_loaded_from_cache")
            return cached_data
        
        # Check if we need to refresh (24 hour TTL)
        if (self.last_fetch and 
            datetime.now() - self.last_fetch < timedelta(hours=24) and 
            self.kev_catalog):
            return self.kev_catalog
        
        try:
            self.logger.info("fetching_kev_catalog", url=self.kev_url)
            
            response = await self.safe_http_request("GET", self.kev_url)
            if not response:
                raise Exception("Failed to fetch KEV catalog")
            
            # Validate catalog structure
            if "vulnerabilities" not in response:
                raise Exception("Invalid KEV catalog structure")
            
            self.kev_catalog = response
            self.last_fetch = datetime.now()
            
            # Cache the data
            await self.cache.set(cache_key, response, tier="all", ttl=self.cache_ttl)
            
            # Store in coordination memory
            await self.store_coordination_data("kev_catalog_meta", {
                "vulnerabilities_count": len(response.get("vulnerabilities", [])),
                "catalog_version": response.get("catalogVersion", "unknown"),
                "date_released": response.get("dateReleased", "unknown"),
                "last_updated": datetime.now().isoformat()
            })
            
            self.logger.info(
                "kev_catalog_fetched",
                vulnerabilities_count=len(response.get("vulnerabilities", [])),
                catalog_version=response.get("catalogVersion", "unknown")
            )
            
            return response
            
        except Exception as e:
            self.logger.error("kev_catalog_fetch_error", error=str(e))
            
            # Fall back to cached data if available
            if self.kev_catalog:
                self.logger.warning("using_cached_kev_catalog")
                return self.kev_catalog
            
            raise e
    
    def find_kev_entry(self, cve_id: str) -> Optional[Dict]:
        """Find KEV entry for a CVE ID"""
        if not self.kev_catalog or "vulnerabilities" not in self.kev_catalog:
            return None
        
        for vuln in self.kev_catalog["vulnerabilities"]:
            if vuln.get("cveID") == cve_id:
                return vuln
        
        return None
    
    async def enrich_cve(self, cve: Dict) -> Dict:
        """Enrich CVE with CISA KEV data"""
        cve_id = cve.get("cve_id")
        if not cve_id:
            self.logger.warning("missing_cve_id", cve=cve)
            return cve
        
        try:
            # Ensure we have fresh KEV data
            if not self.kev_catalog:
                await self.fetch_kev_catalog()
            
            kev_entry = self.find_kev_entry(cve_id)
            
            if kev_entry:
                # CVE is in CISA KEV catalog
                kev_data = {
                    "is_known_exploited": True,
                    "date_added": kev_entry.get("dateAdded"),
                    "due_date": kev_entry.get("dueDate"),
                    "required_action": kev_entry.get("requiredAction", "").strip(),
                    "known_ransomware_campaign_use": kev_entry.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": kev_entry.get("notes", "").strip(),
                    "vendor_project": kev_entry.get("vendorProject", "").strip(),
                    "product": kev_entry.get("product", "").strip(),
                    "vulnerability_name": kev_entry.get("vulnerabilityName", "").strip(),
                    "short_description": kev_entry.get("shortDescription", "").strip()
                }
                
                # Calculate days since KEV addition
                if kev_data["date_added"]:
                    try:
                        date_added = datetime.strptime(kev_data["date_added"], "%Y-%m-%d")
                        days_since_kev = (datetime.now() - date_added).days
                        kev_data["days_since_kev_addition"] = days_since_kev
                    except ValueError:
                        kev_data["days_since_kev_addition"] = None
                
                # Check if due date has passed (for federal agencies)
                if kev_data["due_date"]:
                    try:
                        due_date = datetime.strptime(kev_data["due_date"], "%Y-%m-%d")
                        kev_data["is_overdue"] = datetime.now() > due_date
                        kev_data["days_until_due"] = (due_date - datetime.now()).days
                    except ValueError:
                        kev_data["is_overdue"] = None
                        kev_data["days_until_due"] = None
                
                # Risk amplification for ransomware campaigns
                if kev_data["known_ransomware_campaign_use"] == "Known":
                    kev_data["ransomware_risk_amplifier"] = 1.5
                else:
                    kev_data["ransomware_risk_amplifier"] = 1.0
                
                self.logger.info(
                    "cve_kev_match_found",
                    cve_id=cve_id,
                    date_added=kev_data["date_added"],
                    ransomware_use=kev_data["known_ransomware_campaign_use"]
                )
                
            else:
                # CVE is not in CISA KEV catalog
                kev_data = {
                    "is_known_exploited": False,
                    "date_added": None,
                    "due_date": None,
                    "required_action": None,
                    "known_ransomware_campaign_use": "Unknown",
                    "notes": None,
                    "vendor_project": None,
                    "product": None,
                    "vulnerability_name": None,
                    "short_description": None,
                    "days_since_kev_addition": None,
                    "is_overdue": None,
                    "days_until_due": None,
                    "ransomware_risk_amplifier": 1.0
                }
            
            # Add KEV data to CVE
            cve["cisa_kev"] = kev_data
            
            # Store coordination data
            await self.hooks.post_edit(
                file=f"enrichment/kev/{cve_id}.json",
                memory_key=f"agent/kev/{cve_id}"
            )
            
            # Update enrichment metadata
            if "enrichment_metadata" not in cve:
                cve["enrichment_metadata"] = {}
            
            cve["enrichment_metadata"]["cisa_kev"] = {
                "enriched_at": datetime.now().isoformat(),
                "agent_version": "1.0",
                "data_source": "CISA KEV Catalog",
                "success": True
            }
            
            return cve
            
        except Exception as e:
            self.logger.error("cve_kev_enrichment_failed", cve_id=cve_id, error=str(e))
            
            # Add error metadata but don't fail the enrichment
            if "enrichment_metadata" not in cve:
                cve["enrichment_metadata"] = {}
            
            cve["enrichment_metadata"]["cisa_kev"] = {
                "enriched_at": datetime.now().isoformat(),
                "agent_version": "1.0",
                "data_source": "CISA KEV Catalog",
                "success": False,
                "error": str(e)
            }
            
            # Add minimal KEV data to maintain schema
            cve["cisa_kev"] = {
                "is_known_exploited": False,
                "date_added": None,
                "due_date": None,
                "required_action": None,
                "known_ransomware_campaign_use": "Unknown",
                "notes": None,
                "vendor_project": None,
                "product": None,
                "vulnerability_name": None,
                "short_description": None,
                "days_since_kev_addition": None,
                "is_overdue": None,
                "days_until_due": None,
                "ransomware_risk_amplifier": 1.0
            }
            
            return cve
    
    async def get_kev_statistics(self) -> Dict:
        """Get statistics about the KEV catalog"""
        if not self.kev_catalog:
            await self.fetch_kev_catalog()
        
        if not self.kev_catalog or "vulnerabilities" not in self.kev_catalog:
            return {}
        
        vulnerabilities = self.kev_catalog["vulnerabilities"]
        
        # Calculate statistics
        total_count = len(vulnerabilities)
        ransomware_count = sum(
            1 for v in vulnerabilities 
            if v.get("knownRansomwareCampaignUse") == "Known"
        )
        
        # Group by year added
        year_counts = {}
        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded")
            if date_added:
                try:
                    year = datetime.strptime(date_added, "%Y-%m-%d").year
                    year_counts[year] = year_counts.get(year, 0) + 1
                except ValueError:
                    pass
        
        # Recent additions (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_count = 0
        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded")
            if date_added:
                try:
                    added_date = datetime.strptime(date_added, "%Y-%m-%d")
                    if added_date >= thirty_days_ago:
                        recent_count += 1
                except ValueError:
                    pass
        
        return {
            "total_vulnerabilities": total_count,
            "ransomware_used": ransomware_count,
            "ransomware_percentage": (ransomware_count / total_count * 100) if total_count > 0 else 0,
            "recent_additions_30_days": recent_count,
            "additions_by_year": year_counts,
            "catalog_version": self.kev_catalog.get("catalogVersion"),
            "date_released": self.kev_catalog.get("dateReleased"),
            "last_updated": datetime.now().isoformat()
        }
    
    async def check_cve_batch_kev_status(self, cve_ids: List[str]) -> Dict[str, bool]:
        """Batch check KEV status for multiple CVEs"""
        if not self.kev_catalog:
            await self.fetch_kev_catalog()
        
        kev_cves = set()
        if self.kev_catalog and "vulnerabilities" in self.kev_catalog:
            for vuln in self.kev_catalog["vulnerabilities"]:
                cve_id = vuln.get("cveID")
                if cve_id:
                    kev_cves.add(cve_id)
        
        return {cve_id: cve_id in kev_cves for cve_id in cve_ids}