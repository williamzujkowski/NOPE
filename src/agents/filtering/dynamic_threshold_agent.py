#!/usr/bin/env python
"""Calculate dynamic EPSS thresholds."""
import json

if __name__ == "__main__":
    # Return fixed thresholds for now
    thresholds = {
        "default": 0.10,
        "daily_target": 5
    }
    print(json.dumps(thresholds))
