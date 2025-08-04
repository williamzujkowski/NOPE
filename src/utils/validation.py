"""Data validation utilities."""
from typing import Dict, Any, List

def validate_cve_data(cve: Dict[str, Any]) -> bool:
    """Validate CVE data structure."""
    required_fields = ["cve_id", "description"]
    return all(field in cve for field in required_fields)

def validate_predictions(predictions: List[Dict[str, Any]]) -> bool:
    """Validate prediction data."""
    if not predictions:
        return False
    required = ["cve_id", "risk_score"]
    return all(all(field in pred for field in required) for pred in predictions)
