#!/usr/bin/env python
"""Download or create dummy ML models."""
import os
import json
from pathlib import Path

def main():
    models_dir = Path("data/models")
    models_dir.mkdir(parents=True, exist_ok=True)
    
    # Create dummy model files
    models = [
        "epss_enhanced_model.pkl",
        "velocity_model.pkl", 
        "threat_actor_model.pkl",
        "temporal_model.pkl",
        "practicality_model.pkl",
        "community_model.pkl",
        "pattern_model.pkl"
    ]
    
    for model in models:
        model_path = models_dir / model
        if not model_path.exists():
            # Create dummy model file
            with open(model_path, "w") as f:
                json.dump({"model": model, "version": "1.0", "dummy": True}, f)
            print(f"Created dummy model: {model}")
    
    print("✅ Model files ready")

if __name__ == "__main__":
    main()
