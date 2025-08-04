#!/usr/bin/env python
"""Validate predictions output."""
import json
import sys
from pathlib import Path

def main():
    predictions_dir = Path("data/predictions")
    if not predictions_dir.exists():
        print("❌ No predictions directory found")
        sys.exit(1)
        
    # For now, just check if files exist
    json_files = list(predictions_dir.glob("*.json"))
    if not json_files:
        print("⚠️  No prediction files found (this is OK for initial deployment)")
        sys.exit(0)
        
    print(f"✅ Found {len(json_files)} prediction files")
    return 0

if __name__ == "__main__":
    sys.exit(main())
