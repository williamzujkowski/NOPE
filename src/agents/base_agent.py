"""Base agent class for NOPE pipeline."""
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Abstract base agent class."""
    
    def __init__(self, name: str):
        self.name = name
        self.start_time = datetime.now()
        self.run_count = 0
        self.errors = []
        
    @abstractmethod
    async def run(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute agent logic."""
        pass
        
    async def health_check(self) -> Dict[str, Any]:
        """Return agent health status."""
        return {
            "name": self.name,
            "status": "healthy" if not self.errors else "degraded",
            "uptime": (datetime.now() - self.start_time).total_seconds(),
            "run_count": self.run_count,
            "error_count": len(self.errors)
        }
