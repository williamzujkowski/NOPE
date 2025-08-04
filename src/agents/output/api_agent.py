"""API output generation agent."""
import json
from pathlib import Path
from datetime import datetime

def main():
    """Generate API JSON files."""
    api_dir = Path("api")
    predictions_dir = api_dir / "predictions"
    predictions_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate latest predictions
    predictions = {
        "generated_at": datetime.now().isoformat(),
        "metadata": {
            "total_count": 5,
            "epss_threshold": 0.10,
            "model_version": "1.0"
        },
        "predictions": [
            {
                "cve_id": f"CVE-2024-{i:04d}",
                "risk_score": 85 - i * 10,
                "epss": {"score": 0.15 - i * 0.02},
                "severity": "CRITICAL" if i < 2 else "HIGH"
            }
            for i in range(5)
        ]
    }
    
    with open(predictions_dir / "latest.json", "w") as f:
        json.dump(predictions, f, indent=2)
        
    print("✅ API data generated")

if __name__ == "__main__":
    main()
