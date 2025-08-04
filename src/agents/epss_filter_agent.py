"""EPSS filtering agent."""
from typing import Dict, Any, List, Optional
from src.agents.base_agent import BaseAgent

class EPSSFilterAgent(BaseAgent):
    """Filters CVEs by EPSS threshold."""
    
    def __init__(self, threshold: float = 0.10):
        super().__init__("EPSSFilterAgent")
        self.threshold = threshold
        
    async def run(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Filter CVEs by EPSS score."""
        self.run_count += 1
        
        if not data or "cves" not in data:
            return {"filtered_cves": [], "count": 0}
            
        filtered = []
        for cve in data["cves"]:
            if cve.get("epss_score", 0) >= self.threshold:
                filtered.append(cve)
                
        return {
            "filtered_cves": filtered,
            "count": len(filtered),
            "threshold_used": self.threshold
        }
