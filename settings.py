"""
User-side settings management for the application.
This module handles configurations stored in ( SETTINGS_FILE ).
"""

import json
import os
from typing import Optional

# Location of the user settings file on disk "folder/filename"
SETTINGS_FILE = "settings/user_settings.json"

# Default settings, used when creating or merging settings files
DEFAULT_SETTINGS = {
    "max_concurrent_downloads": 2,
    "max_concurrent_conversions": 1,  # Default 1 for CPU-only systems
    "max_download_speed": 0,  # Measured in MiB/s (0 = unlimited)
    "min_disk_space_mb": 1000,  # Minimum free disk space before pausing downloads
    "zip_avg_compression_ratio": 0.95,  # Default 95%
    "zip_compression_samples": [],  # Recent compression ratios for size estimates
}

class Settings:
    
    def __init__(self):
        # Initialize settings by loading from disk or using defaults
        self.settings = self._load_settings()
        
    def _load_settings(self) -> dict:
        # Loads settings if file exists and is readable
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults - any missing keys get default values - this allows backwards compatibility
                    return {**DEFAULT_SETTINGS, **loaded}
            except Exception:
                # File is corrupted or unreadable, fall back to defaults
                return DEFAULT_SETTINGS.copy()
        else:
            # No settings file exists yet, create one with defaults
            self._save_settings(DEFAULT_SETTINGS)
            return DEFAULT_SETTINGS.copy()

    def _save_settings(self, settings: dict):
        # Save settings to JSON, keep default if not set
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)

    def get(self, key: str, default=None):
        # Get a single setting value, return default if not found
        return self.settings.get(key, default)

    def set(self, key: str, value):
        # Update a single settings value, save file to persist changes
        self.settings[key] = value
        self._save_settings(self.settings)

    def get_all(self) -> dict:
        # Get all setting values
        return self.settings.copy()

    def update(self, updates: dict):
        # Update multiple setting values at once, better than calling single save multiple times
        self.settings.update(updates)
        self._save_settings(self.settings)

# Global settings instance used throughout the application
# Initialized once when the module is imported
settings = Settings()