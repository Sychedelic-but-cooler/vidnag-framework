"""
Settings management for the application.
Handles loading, saving, and updating configuration stored in settings.json.
"""
import json
import os
from typing import Optional

# Location of the settings file on disk
SETTINGS_FILE = "settings.json"

# Default settings used when creating a new settings file or merging with existing settings
DEFAULT_SETTINGS = {
    "max_concurrent_downloads": 2,
    "max_concurrent_conversions": 1,  # Default 1 for CPU-only systems
    "max_download_speed": 0,  # MiB/s (0 = unlimited)
    "min_disk_space_mb": 1000,  # Minimum free disk space before pausing downloads
    "zip_compression_samples": [],  # Recent compression ratios for size estimates
    "zip_avg_compression_ratio": 0.95,  # Default 95% (videos don't compress much)
}


class Settings:
    """
    Manages application settings with persistent storage.
    Settings are stored in settings.json and automatically saved on changes.
    """

    def __init__(self):
        """Initialize by loading settings from disk or creating defaults"""
        self.settings = self._load_settings()

    def _load_settings(self) -> dict:
        """
        Load settings from the JSON file.
        If the file exists, loads it and merges with defaults to ensure all keys are present.
        If the file doesn't exist or is corrupted, creates a new one with defaults.
        This merge approach allows adding new settings without breaking existing configs.
        """
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults - any missing keys get default values
                    # This lets us add new settings without breaking old configs
                    return {**DEFAULT_SETTINGS, **loaded}
            except Exception:
                # File is corrupted or unreadable, fall back to defaults
                return DEFAULT_SETTINGS.copy()
        else:
            # No settings file exists yet, create one with defaults
            self._save_settings(DEFAULT_SETTINGS)
            return DEFAULT_SETTINGS.copy()

    def _save_settings(self, settings: dict):
        """
        Save settings to disk as formatted JSON.
        Uses indent=2 to make the file human-readable.
        """
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)

    def get(self, key: str, default=None):
        """
        Retrieve a single setting value by key.
        Returns the provided default if the key doesn't exist.
        """
        return self.settings.get(key, default)

    def set(self, key: str, value):
        """
        Update a single setting and save to disk immediately.
        Changes are persisted right away to prevent data loss.
        """
        self.settings[key] = value
        self._save_settings(self.settings)

    def get_all(self) -> dict:
        """
        Get a copy of all current settings.
        Returns a copy to prevent external modification of the internal state.
        """
        return self.settings.copy()

    def update(self, updates: dict):
        """
        Update multiple settings at once and save to disk.
        More efficient than calling set() multiple times since it only saves once.
        """
        self.settings.update(updates)
        self._save_settings(self.settings)


# Global settings instance used throughout the application
# Initialized once when the module is imported
settings = Settings()
