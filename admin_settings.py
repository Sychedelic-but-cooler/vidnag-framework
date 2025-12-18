"""
Admin-side settings management for the application.
This module handles configurations stored in ( ADMIN_SETTINGS_FILE ).
These settings are not user-configurable and cannot be accessed without auth.
"""

import json
import os
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Location of the admin settings file on disk "folder/filename"
ADMIN_SETTINGS_FILE = "settings/admin_settings.json"
"""
Default settings, used when creating or merging settings files
This application disables most settings by default, admins should be allowed full control over enabling features as needed.
Microsoft can suck it for enabling settings by default.
"""

DEFAULT_ADMIN_SETTINGS = {
    "cors": {
        "enabled": False,  # Defaults to disabled, this should be enabled for public deployments
        "allowed_origins": [ # Defaults to localhost, adds both ways to call localhost
            "http://localhost",
            "http://127.0.0.1",
        ],
        "allow_credentials": True,
        "allowed_methods": ["GET", "POST", "DELETE"],
        "allowed_headers": ["Content-Type", "Authorization"],
    },
    "proxy": {
        "is_behind_proxy": False,  # Set to True if behind a reverse proxy
        "proxy_header": "X-Forwarded-For",  # Header to read Real Client IP from
        "trusted_proxies": ["127.0.0.1"],  # Allows localhost by default
    },
    # These default values should be good for most people, the frontend is designed to sit around 50 requests per minute
    "rate_limiting": {
        "enabled": False, # Disabled by default, enable for public deployments to prevent abuse
        "max_requests_per_window": 70, # Number of requests allowed per window
        "window_seconds": 60, # Tracked in seconds, how long before resetting the request count
        "max_tracked_ips": 10000, # Number of IPS to track for rate limiting, smaller number uses less memory but may allow bruteforcing
        "cleanup_interval_seconds": 3600, # How long to keep an IP tracked in the rate limiter before removing it
    },
    "security": {
        "debug_proxy_headers": False,  # Disable header logging in production, useful when setting up proxies
        "debug_logs": False,  # Enable verbose client-side debug logging in the frontend when true
        "validate_ip_format": True, # Validate that IPs in headers are well-formed, defaults to True for security
        "allow_ytdlp_update": False,  # Disable yt-dlp updates by default for security
    },
    "auth": {
        "enabled": False,  # Disabled by default, PLEASE ENABLE FOR PUBLIC DEPLOYMENTS
        "jwt_algorithm": "HS256", # Probably not worth changing this but hey, more power to the admin
        "jwt_session_expiry_hours": 24, # Default to 24 hours session expiry, increase to allow users to stay logged in longer
        "jwt_key_rotation_days": 7, # How often to rotate the JWT signing key
        "failed_login_attempts_max": 5, # Number of failed login attempts before account lockout
        "failed_login_lockout_minutes": 30, #How long to lockout an account after failures before unlock
        "suspicious_ip_threshold": 3, # Number of failed logins from different IPs to consider an IP suspicious
        "suspicious_ip_window_hours": 24, # How long to keep an IP tracked for suspicious activity, different from rate limiting
        "require_auth_for_all_endpoints": True, # Default to requiring auth for all endpoints, public_endpoints array overrides this
        "public_endpoints": [
            "/", # Root endpoint, content changes based on auth status
            "/favicon.ico", # Favicon for browser titles
            "/api/auth/login", # Login endpoint
            "/api/auth/setup", # Initial setup endpoint, not used after first account is created
            "/api/auth/check-setup", # Intial setup check endpoint, not userd after first account is created
            "/api/auth/status", # Endpoint to check if auth is enabled, used by frontend to determine if login screen is needed
            "/api/files/download/*", # File Download endpoint, must be public to allow public access. Private downloads do not use this and will still be protected
            "/api/files/thumbnail/*", # Thumbnail Image endpoint, must be public to allow public access
            "/api/files/video/*", # Video Conversion endpoint, must be public to allow public access.
            "/api/tools/audio/*", # Audio Conversion endpoint, must be public to allow public access.
            "/assets/*" # Serve static assets like JS/CSS without auth
        ],
    },
}

# Declare Data Classes for Admin Settings
@dataclass
class CORSConfig:
    # CORS Configuration
    enabled: bool
    allowed_origins: List[str]
    allow_credentials: bool
    allowed_methods: List[str]
    allowed_headers: List[str]

@dataclass
class ProxyConfig:
    # Proxy Configuration
    is_behind_proxy: bool
    proxy_header: str
    trusted_proxies: List[str]

@dataclass
class RateLimitConfig:
    # Rate Limiting Configuration
    enabled: bool
    max_requests_per_window: int
    window_seconds: int
    max_tracked_ips: int
    cleanup_interval_seconds: int

@dataclass
class SecurityConfig:
    # General Securitry Configuration
    debug_proxy_headers: bool
    debug_logs: bool
    validate_ip_format: bool
    allow_ytdlp_update: bool

@dataclass
class AuthConfig:
    # Authentication Configuration
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

    def __init__(self):
       # Initialize settings by loading from disk or using default
        self._settings: Dict[str, Any] = self._load_settings()
        self._parse_configs()

    def _load_settings(self) -> Dict[str, Any]:
        # Loads settings if file exists and is readable
        if os.path.exists(ADMIN_SETTINGS_FILE):
            try:
                with open(ADMIN_SETTINGS_FILE, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults - any missing keys get default values - this allows backwards compatibility
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
            # No settings file exists yet, create one with defaults
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
        # Merge with defaults - any missing keys get default values - this allows backwards compatibility
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    def _parse_configs(self):
        # Parse settings into typed config objects
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
        # Log a template of the SETTINGS_FILES that should be created
        logger.info("=" * 80)
        logger.info("To configure admin settings, create admin_settings.json with:")
        logger.info("=" * 80)
        logger.info(json.dumps(DEFAULT_ADMIN_SETTINGS, indent=2))
        logger.info("=" * 80)

    def get_raw(self) -> Dict[str, Any]:
        # Get raw settings dictionary
        return self._settings.copy()

    def validate(self) -> tuple[bool, Optional[str]]:
        # Validate setting values for all data types
        # Import here to avoid circular imports
        from security import (
            validate_cors_origins,
            validate_trusted_proxies,
            validate_cors_methods,
        )

        # Validate CORS Settings
        is_valid, error = validate_cors_origins(self.cors.allowed_origins)
        if not is_valid:
            return False, f"CORS configuration error: {error}"

        # Validate CORS Settings
        is_valid, error = validate_cors_methods(self.cors.allowed_methods)
        if not is_valid:
            return False, f"CORS methods configuration error: {error}"

        # Validate Proxy Settings
        if self.proxy.is_behind_proxy and self.proxy.trusted_proxies:
            is_valid, error = validate_trusted_proxies(self.proxy.trusted_proxies)
            if not is_valid:
                return False, f"Proxy configuration error: {error}"

        # Validate Rate Limiting Settings
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
    # Get the global admin settings instance. Initializes on first call, then returns cached instance.
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
    # Force reload of admin settings from disk. In production, restart the application to apply changes more fully.
    global _admin_settings
    _admin_settings = None
    return get_admin_settings()