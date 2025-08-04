"""Configuration settings."""
import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BASE_DIR / "data"
CACHE_DIR = DATA_DIR / "cache"
MODELS_DIR = DATA_DIR / "models"

# EPSS Settings
EPSS_THRESHOLD = float(os.getenv("EPSS_THRESHOLD", "0.10"))
MAX_DAILY_CVES = int(os.getenv("MAX_DAILY_CVES", "8"))

# API Settings
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
