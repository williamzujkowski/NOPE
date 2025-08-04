#!/usr/bin/env python
"""Clean up stale files."""
from pathlib import Path
import shutil

def main():
    # Clean build directories
    for dir_name in ["_site", "api"]:
        dir_path = Path(dir_name)
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"Cleaned: {dir_name}")
    
    print("✅ Cleanup complete")

if __name__ == "__main__":
    main()
