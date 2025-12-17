"""
Admin Settings Management for Security and Proxy Configuration

This module handles loading security-critical settings from admin_settings.json.
These settings are READ-ONLY after startup and cannot be modified via web UI.

Settings include:
- CORS origin whitelist
- Trusted proxy configuration
- Rate limiting parameters
- HTTPS enforcement
- Debug logging control
- yt-dlp update permissions

No API endpoints expose these settings. All changes require:
1. Edit admin_settings.json on disk
2. Restart the application

This approach ensures security settings cannot be accidentally modified
or exploited via the web interface until proper authentication is implemented.
"""

import json
import os
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Location of the admin settings file on disk
ADMIN_SETTINGS_FILE = "admin_settings.json"

# Safe defaults - very restrictive, requiring explicit configuration for production
DEFAULT_ADMIN_SETTINGS = {
    "cors": {
        "enabled": True,  # Enable CORS by default
        "allowed_origins": [
            "http://localhost",
            "http://localhost:8000",
            "http://127.0.0.1",
            "http://127.0.0.1:8000",
        ],
        "allow_credentials": True,
        "allowed_methods": ["GET", "POST", "DELETE"],
        "allowed_headers": ["Content-Type", "Authorization"],
    },
    "proxy": {
        "is_behind_proxy": False,  # Set to True if behind a reverse proxy
        "proxy_header": "X-Forwarded-For",  # Header to read client IP from
        "trusted_proxies": ["127.0.0.1"],  # Only localhost by default
    },
    "rate_limiting": {
        "enabled": True,
        "max_requests_per_window": 20,
        "window_seconds": 60,
        "max_tracked_ips": 10000,
        "cleanup_interval_seconds": 3600,
    },
    "security": {
        "debug_proxy_headers": False,  # Disable header logging in production
        "validate_ip_format": True,
        "allow_ytdlp_update": False,  # Disable yt-dlp updates by default for security
    },
    "auth": {
        "enabled": False,  # Disabled by default for gradual rollout
        "jwt_algorithm": "HS256",
        "jwt_session_expiry_hours": 24,
        "jwt_key_rotation_days": 7,
        "failed_login_attempts_max": 5,
        "failed_login_lockout_minutes": 30,
        "suspicious_ip_threshold": 3,
        "suspicious_ip_window_hours": 24,
        "require_auth_for_all_endpoints": True,
        "public_endpoints": [
            "/",
            "/favicon.ico",
            "/api/auth/login",
            "/api/auth/setup",
            "/api/auth/check-setup",
            "/api/auth/status",
            "/api/files/download/*",
            "/api/files/thumbnail/*",
            "/api/files/video/*",
            "/api/tools/audio/*",
            "/assets/*"
        ],
    },
}


@dataclass
class CORSConfig:
    """CORS configuration"""
    enabled: bool
    allowed_origins: List[str]
    allow_credentials: bool
    allowed_methods: List[str]
    allowed_headers: List[str]


@dataclass
class ProxyConfig:
    """Proxy trust and header configuration"""
    is_behind_proxy: bool
    proxy_header: str  # e.g., "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"
    trusted_proxies: List[str]  # List of trusted proxy IPs or CIDR ranges


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    enabled: bool
    max_requests_per_window: int
    window_seconds: int
    max_tracked_ips: int
    cleanup_interval_seconds: int


@dataclass
class SecurityConfig:
    """General security configuration"""
    debug_proxy_headers: bool
    validate_ip_format: bool
    allow_ytdlp_update: bool


@dataclass
class AuthConfig:
    """Authentication configuration"""
    enabled: bool
    jwt_algorithm: str
    jwt_session_expiry_hours: int
    jwt_key_rotation_days: int
    failed_login_attempts_max: int
    failed_login_lockout_minutes: int
    suspicious_ip_threshold: int
    suspicious_ip_window_hours: int
    require_auth_for_all_endpoints: bool
    public_endpoints: List[str]


class AdminSettings:
    """
    Read-only admin settings loaded from admin_settings.json at startup.
    
    This class loads settings once during application initialization
    and provides read-only access throughout the application lifecycle.
    
    Changes require:
    1. Modifying admin_settings.json
    2. Restarting the application
    
    This ensures security-critical settings cannot be accidentally modified
    via API or web interface.
    """

    def __init__(self):
        """Initialize by loading settings from disk"""
        self._settings: Dict[str, Any] = self._load_settings()
        self._parse_configs()

    def _load_settings(self) -> Dict[str, Any]:
        """
        Load admin settings from JSON file.
        
        If the file exists, loads it and merges with defaults to ensure all keys are present.
        If the file doesn't exist, uses defaults and logs a warning with template.
        If the file is corrupted, uses defaults and logs an error.
        
        Returns:
            Dictionary of admin settings
        """
        if os.path.exists(ADMIN_SETTINGS_FILE):
            try:
                with open(ADMIN_SETTINGS_FILE, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults - any missing keys get default values
                    # This lets us add new settings without breaking old configs
                    merged = self._deep_merge(DEFAULT_ADMIN_SETTINGS.copy(), loaded)
                    logger.info(f"Loaded admin settings from {ADMIN_SETTINGS_FILE}")
                    return merged
            except json.JSONDecodeError as e:
                logger.error(
                    f"Failed to parse {ADMIN_SETTINGS_FILE}: {e}. "
                    f"Using defaults. Please fix the JSON syntax."
                )
                return DEFAULT_ADMIN_SETTINGS.copy()
            except Exception as e:
                logger.error(
                    f"Failed to read {ADMIN_SETTINGS_FILE}: {e}. "
                    f"Using defaults."
                )
                return DEFAULT_ADMIN_SETTINGS.copy()
        else:
            # File doesn't exist - create it with defaults
            logger.info(
                f"{ADMIN_SETTINGS_FILE} not found. Creating with default settings..."
            )
            try:
                with open(ADMIN_SETTINGS_FILE, 'w') as f:
                    json.dump(DEFAULT_ADMIN_SETTINGS, f, indent=2)
                logger.info(
                    f"Created {ADMIN_SETTINGS_FILE} with default configuration. "
                    f"Authentication is disabled by default. "
                    f"Edit this file to customize settings."
                )
            except Exception as e:
                logger.error(f"Failed to create {ADMIN_SETTINGS_FILE}: {e}. Using defaults in-memory only.")
            return DEFAULT_ADMIN_SETTINGS.copy()

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """
        Recursively merge override dict into base dict.
        
        Allows partial configuration files - missing keys use defaults.
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    def _parse_configs(self):
        """Parse settings into typed config objects"""
        cors_data = self._settings.get("cors", {})
        proxy_data = self._settings.get("proxy", {})
        rate_limit_data = self._settings.get("rate_limiting", {})
        security_data = self._settings.get("security", {})
        auth_data = self._settings.get("auth", {})

        self.cors = CORSConfig(**cors_data)
        self.proxy = ProxyConfig(**proxy_data)
        self.rate_limit = RateLimitConfig(**rate_limit_data)
        self.security = SecurityConfig(**security_data)
        self.auth = AuthConfig(**auth_data)

    def _log_template(self):
        """Log a template of the admin_settings.json that should be created"""
        logger.info("=" * 80)
        logger.info("To configure admin settings, create admin_settings.json with:")
        logger.info("=" * 80)
        logger.info(json.dumps(DEFAULT_ADMIN_SETTINGS, indent=2))
        logger.info("=" * 80)

    def get_raw(self) -> Dict[str, Any]:
        """
        Get raw settings dictionary (for debugging/logging purposes).
        
        WARNING: Do not modify returned dict - settings are read-only.
        """
        return self._settings.copy()

    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validate all settings for correctness.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Import here to avoid circular imports
        from security import (
            validate_cors_origins,
            validate_trusted_proxies,
            validate_cors_methods,
        )

        # Validate CORS origins
        is_valid, error = validate_cors_origins(self.cors.allowed_origins)
        if not is_valid:
            return False, f"CORS configuration error: {error}"

        # Validate CORS methods
        is_valid, error = validate_cors_methods(self.cors.allowed_methods)
        if not is_valid:
            return False, f"CORS methods configuration error: {error}"

        # Validate trusted proxies
        if self.proxy.is_behind_proxy and self.proxy.trusted_proxies:
            is_valid, error = validate_trusted_proxies(self.proxy.trusted_proxies)
            if not is_valid:
                return False, f"Proxy configuration error: {error}"

        # Validate rate limiting settings
        if self.rate_limit.enabled:
            if self.rate_limit.max_requests_per_window < 1:
                return False, "Rate limiting: max_requests_per_window must be at least 1"
            if self.rate_limit.window_seconds < 1:
                return False, "Rate limiting: window_seconds must be at least 1"
            if self.rate_limit.max_tracked_ips < 1:
                return False, "Rate limiting: max_tracked_ips must be at least 1"

        return True, None


# Global singleton instance
_admin_settings: Optional[AdminSettings] = None


def get_admin_settings() -> AdminSettings:
    """
    Get the global admin settings instance.
    
    Initializes on first call, then returns cached instance.
    """
    global _admin_settings
    if _admin_settings is None:
        _admin_settings = AdminSettings()
        
        # Validate settings at startup
        is_valid, error = _admin_settings.validate()
        if not is_valid:
            logger.error(f"Admin settings validation failed: {error}")
            logger.error("Application cannot start with invalid configuration.")
            raise ValueError(f"Invalid admin settings: {error}")
        
        logger.info("Admin settings validated successfully")
    
    return _admin_settings


def reload_admin_settings():
    """
    Force reload of admin settings from disk.
    
    Useful for testing. In production, restart the application to apply changes.
    """
    global _admin_settings
    _admin_settings = None
    return get_admin_settings()
