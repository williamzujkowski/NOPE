#!/usr/bin/env python
"""Generate metrics data."""
import json
from pathlib import Path
from datetime import datetime

def main():
    metrics_dir = Path("api/metrics")
    metrics_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate dummy metrics
    metrics = {
        "generated_at": datetime.now().isoformat(),
        "overall_metrics": {
            "accuracy_rate": 0.875,
            "precision": 0.823,
            "recall": 0.912,
            "false_positive_rate": 0.225
        },
        "model_performance": {
            "epss_enhanced": {"accuracy": 0.812},
            "velocity_model": {"accuracy": 0.887}
        }
    }
    
    with open(metrics_dir / "accuracy.json", "w") as f:
        json.dump(metrics, f, indent=2)
        
    print("✅ Metrics generated")

if __name__ == "__main__":
    main()
