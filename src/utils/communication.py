"""Agent communication utilities."""
from typing import Dict, Any
import json
from datetime import datetime

class Message:
    """Inter-agent message."""
    
    def __init__(self, sender: str, data: Dict[str, Any]):
        self.sender = sender
        self.data = data
        self.timestamp = datetime.now()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": self.sender,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }
