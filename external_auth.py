"""
External Authentication Configuration - OIDC/OAuth

This module handles loading and managing OIDC/OAuth configuration
from external_auth.json.
"""

import json
import os
from dataclasses import dataclass
from typing import List, Optional


# Default configuration structure
DEFAULT_EXTERNAL_AUTH_CONFIG = {
    "oidc": {
        "enabled": False,
        "provider_name": "SSO Provider",
        "discovery_url": "",
        "logout_url": "",
        "userinfo_url": "",
        "client_id": "",
        "client_secret": "",
        "scopes": ["openid", "profile", "email"],
        "admin_group_claim": "groups",
        "admin_group_value": "vidnag-admins",
        "use_pkce": True,
        "button_text": "Login with SSO",
        "auto_create_users": False,
        "username_claim": "preferred_username",
        "email_claim": "email"
    }
}


@dataclass
class OIDCConfig:
    """OIDC/OAuth configuration settings"""
    enabled: bool
    provider_name: str
    discovery_url: str
    logout_url: str
    userinfo_url: str
    client_id: str
    client_secret: str
    scopes: List[str]
    admin_group_claim: str
    admin_group_value: str
    use_pkce: bool
    button_text: str
    auto_create_users: bool
    username_claim: str
    email_claim: str


class ExternalAuthConfig:
    """
    Manages external authentication configuration.
    Loads from external_auth.json and provides access to OIDC settings.
    """

    def __init__(self, config_file: str = "external_auth.json"):
        self.config_file = config_file
        self._config = self._load_config()
        self.oidc = self._parse_oidc_config()

    def _load_config(self) -> dict:
        """
        Load configuration from external_auth.json.
        Creates file with defaults if it doesn't exist.
        """
        if not os.path.exists(self.config_file):
            print(f"external_auth.json not found, creating with defaults...")
            self._create_default_config()
            return DEFAULT_EXTERNAL_AUTH_CONFIG.copy()

        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults to ensure all fields exist
                return self._merge_with_defaults(config)
        except json.JSONDecodeError as e:
            print(f"Error parsing external_auth.json: {e}")
            print("Using default configuration")
            return DEFAULT_EXTERNAL_AUTH_CONFIG.copy()
        except Exception as e:
            print(f"Error loading external_auth.json: {e}")
            print("Using default configuration")
            return DEFAULT_EXTERNAL_AUTH_CONFIG.copy()

    def _create_default_config(self):
        """Create external_auth.json with default configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(DEFAULT_EXTERNAL_AUTH_CONFIG, f, indent=2)
            print(f"Created {self.config_file} with default configuration")
        except Exception as e:
            print(f"Error creating default config file: {e}")

    def _merge_with_defaults(self, config: dict) -> dict:
        """
        Merge loaded config with defaults to ensure all fields exist.
        This handles cases where new fields are added in updates.
        """
        merged = DEFAULT_EXTERNAL_AUTH_CONFIG.copy()

        if "oidc" in config:
            for key in DEFAULT_EXTERNAL_AUTH_CONFIG["oidc"]:
                if key in config["oidc"]:
                    merged["oidc"][key] = config["oidc"][key]

        return merged

    def _parse_oidc_config(self) -> OIDCConfig:
        """Parse OIDC configuration into dataclass"""
        oidc_data = self._config.get("oidc", {})

        return OIDCConfig(
            enabled=oidc_data.get("enabled", False),
            provider_name=oidc_data.get("provider_name", "SSO Provider"),
            discovery_url=oidc_data.get("discovery_url", ""),
            logout_url=oidc_data.get("logout_url", ""),
            userinfo_url=oidc_data.get("userinfo_url", ""),
            client_id=oidc_data.get("client_id", ""),
            client_secret=oidc_data.get("client_secret", ""),
            scopes=oidc_data.get("scopes", ["openid", "profile", "email"]),
            admin_group_claim=oidc_data.get("admin_group_claim", "groups"),
            admin_group_value=oidc_data.get("admin_group_value", "vidnag-admins"),
            use_pkce=oidc_data.get("use_pkce", True),
            button_text=oidc_data.get("button_text", "Login with SSO"),
            auto_create_users=oidc_data.get("auto_create_users", False),
            username_claim=oidc_data.get("username_claim", "preferred_username"),
            email_claim=oidc_data.get("email_claim", "email")
        )

    def save_config(self, new_config: dict):
        """
        Save updated configuration to file and reload.

        Args:
            new_config: Complete configuration dictionary to save
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(new_config, f, indent=2)

            # Reload configuration
            self._config = new_config
            self.oidc = self._parse_oidc_config()

            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving configuration: {e}")
            raise

    def reload(self):
        """Reload configuration from file"""
        self._config = self._load_config()
        self.oidc = self._parse_oidc_config()

    def get_public_config(self) -> dict:
        """
        Get public OIDC configuration (safe for frontend).
        Excludes sensitive fields like client_secret.
        """
        return {
            "enabled": self.oidc.enabled,
            "provider_name": self.oidc.provider_name,
            "button_text": self.oidc.button_text
        }

    def get_admin_config(self, redact_secret: bool = True) -> dict:
        """
        Get full OIDC configuration for admin UI.
        Optionally redacts client_secret.
        """
        config = self._config.copy()

        if redact_secret and "oidc" in config:
            config["oidc"]["client_secret"] = "********" if config["oidc"]["client_secret"] else ""

        return config


# Global configuration instance (singleton pattern)
_external_auth_config: Optional[ExternalAuthConfig] = None


def get_external_auth_config() -> ExternalAuthConfig:
    """
    Get global ExternalAuthConfig instance (singleton).
    Creates instance on first call.
    """
    global _external_auth_config

    if _external_auth_config is None:
        _external_auth_config = ExternalAuthConfig()

    return _external_auth_config


def reload_external_auth_config():
    """Force reload of external auth configuration from file"""
    global _external_auth_config

    if _external_auth_config is not None:
        _external_auth_config.reload()
    else:
        _external_auth_config = ExternalAuthConfig()
