"""
Security utilities for the video downloader application
"""
import os
import re
from urllib.parse import urlparse
from typing import Optional
from pathlib import Path


def is_safe_path(base_dir: str, file_path: str) -> bool:
    # Check if a file path is safe and within the base directory.
    # Prevents path traversal attacks where users try to access files outside the allowed directory
    try:
        # Resolve both paths to their absolute, canonical forms
        base = Path(base_dir).resolve()
        target = (Path(base_dir) / file_path).resolve()
        # Verify the target path starts with the base path
        return str(target).startswith(str(base))
    except (ValueError, OSError):
        # If path resolution fails, reject it
        return False


def validate_filename(filename: str) -> bool:
    # Validate that a filename is safe and doesn't contain path traversal attempts.
    # Ensures the filename can only reference a single file in the current directory.
    if not filename:
        return False
    # Reject any path separators ( like video/../secret.txt )
    if '/' in filename or '\\' in filename:
        return False
    # Reject parent directory references ( starting with .. like ../secret.txt )
    if filename == '..':
        return False
    # Reject absolute paths ( like /etc/passwd or C:\Windows\system32 )
    if os.path.isabs(filename):
        return False
    # Reject hidden files ( starting with a dot like .env )
    if filename.startswith('.'):
        return False
    # Enforce filesystem filename length limit
    if len(filename) > 255:
        return False
    return True


def validate_url(url: str) -> tuple[bool, Optional[str]]:
    # Validate that a URL is safe for yt-dlp to process. Helps prevent SSRF attacks
    if not url or not isinstance(url, str):
        return False, "URL is required"
    # Prevent extremely long URLs that could cause issues
    if len(url) > 2048:
        return False, "URL is too long (max 2048 characters)"
    # Parse the URL into components
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    # Ensure the URL has a protocol specified
    if not parsed.scheme:
        return False, "URL must have a scheme (http/https)"
    # Only allow web protocols to prevent file:// or other dangerous schemes
    if parsed.scheme not in ['http', 'https']:
        return False, "Only HTTP and HTTPS URLs are allowed"
    # Verify the URL has a domain name
    if not parsed.netloc:
        return False, "URL must have a valid domain"
    # Block local and private network addresses to prevent SSRF attacks
    localhost_patterns = [
        '127.0.0.0/8',      # Localhost
        '10.0.0.0/8',       # Class A Private network
        '172.16.0.0/12',    # Class B Private network
        '192.168.0.0/16',   # Class C Private network
        '::1/128',          # IPv6 localhost
        '::/128',           # IPv6 unspecified
    ]

    # Extract just the hostname part (remove port if present)
    hostname = parsed.netloc.split(':')[0].lower()
    for pattern in localhost_patterns:
        if hostname.startswith(pattern):
            return False, "Local and private network URLs are not allowed"

    return True, None


def sanitize_url_for_logging(url: str, max_length: int = 100) -> str:
    # Santitize a URL for safe logging by removing sensitive parts and truncating if necessary.
    try:
        parsed = urlparse(url)
        # Remove query string (contains potential secrets) and fragment
        # Keep only the scheme, domain, and path which are safe to log
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Truncate long URLs to keep logs readable
        # Add ellipsis to indicate truncation
        if len(clean_url) > max_length:
            clean_url = clean_url[:max_length] + "..."

        return clean_url
    except Exception:
        # If URL parsing fails, return a safe placeholder
        return "[invalid-url]"


def validate_cookie_filename(filename: str) -> bool:
    # Validate that a cookie filename is safe to use with yt-dlp, these are user provided files and should be treated as unsafe.
    if not filename:
        return False
    # Enforce .txt extension for consistency and safety
    if not filename.endswith('.txt'):
        return False
    # Enforce validate_filename checks that we declared above
    if not validate_filename(filename):
        return False
    # Additional strictness for cookie files used in command execution. Prevents injection when loading cookie files.
    name_without_ext = filename[:-4]  # Remove .txt extension
    if not re.match(r'^[a-zA-Z0-9_-]+$', name_without_ext):
        return False
    return True


def validate_settings_update(updates: dict) -> tuple[bool, Optional[str]]:
    # Validate settings updates for security and correctness. Keeps users from setting invalid values
    # Defines allowed settings and their valid ranges/types.
    allowed_keys = ['max_concurrent_downloads', 'max_concurrent_conversions', 'max_download_speed', 'min_disk_space_mb', 'download_timeout_minutes']

    for key in updates.keys():
        if key not in allowed_keys:
            return False, f"Setting '{key}' is not allowed"
    # Validate concurrent downloads limit
    # Between 1-10 to prevent resource exhaustion while allowing flexibility
    if "max_concurrent_downloads" in updates:
        value = updates["max_concurrent_downloads"]
        if not isinstance(value, int) or value < 1 or value > 10:
            return False, "max_concurrent_downloads must be between 1 and 10"
    # Validate concurrent conversions limit
    # Between 1-5 to prevent resource exhaustion (conversions are CPU-intensive)
    if "max_concurrent_conversions" in updates:
        value = updates["max_concurrent_conversions"]
        if not isinstance(value, int) or value < 1 or value > 5:
            return False, "max_concurrent_conversions must be between 1 and 5"
    # Validate download speed limit
    # Max 1000 to prevent unrealistic settings
    if "max_download_speed" in updates:
        value = updates["max_download_speed"]
        if not isinstance(value, int) or value < 0 or value > 1000:
            return False, "max_download_speed must be between 0 and 1000 MiB/s"
    # Validate minimum disk space threshold
    # Max 100GB to prevent setting unrealistic thresholds
    if "min_disk_space_mb" in updates:
        value = updates["min_disk_space_mb"]
        if not isinstance(value, int) or value < 0 or value > 100000:
            return False, "min_disk_space_mb must be between 0 and 100000 MB"
    # Validate download timeout
    # Between 5 minutes and 8 hours (480 minutes) to prevent too short or too long timeouts
    if "download_timeout_minutes" in updates:
        value = updates["download_timeout_minutes"]
        if not isinstance(value, int) or value < 5 or value > 480:
            return False, "download_timeout_minutes must be between 5 and 480 minutes"
    return True, None


def validate_ip_address(ip: str) -> tuple[bool, Optional[str]]:
    # Validate that a string is a valid IP address (IPv4 or IPv6).
    from ipaddress import ip_address, AddressValueError
    
    try:
        ip_address(ip)
        return True, None
    except (AddressValueError, ValueError) as e:
        return False, f"Invalid IP address '{ip}': {str(e)}"


def validate_cidr_block(cidr: str) -> tuple[bool, Optional[str]]:
    # Validate that a string is a valid CIDR notation (e.g., "
    from ipaddress import ip_network, AddressValueError
    
    try:
        ip_network(cidr, strict=False)
        return True, None
    except (AddressValueError, ValueError) as e:
        return False, f"Invalid CIDR block '{cidr}': {str(e)}"


def validate_trusted_proxies(proxies: list) -> tuple[bool, Optional[str]]:
    # Validate user declared trusted proxy addresses, should follow CIDR or a single IP.
    if not isinstance(proxies, list):
        return False, "trusted_proxies must be a list"
    if not proxies:
        return False, "trusted_proxies list cannot be empty"
    
    for proxy in proxies:
        if not isinstance(proxy, str):
            return False, f"Proxy entry must be a string, got {type(proxy).__name__}"
        
        # Try as single IP first
        if "/" not in proxy:
            is_valid, error = validate_ip_address(proxy)
            if not is_valid:
                return False, f"Invalid proxy entry: {error}"
        else:
            # Try as CIDR block
            is_valid, error = validate_cidr_block(proxy)
            if not is_valid:
                return False, f"Invalid proxy entry: {error}"
    
    return True, None


def validate_cors_origins(origins: list) -> tuple[bool, Optional[str]]:
    # Validate user declared CORS allowed origins, should be valid URLs with http/https schemes.
    if not isinstance(origins, list):
        return False, "allowed_origins must be a list"
    if not origins:
        return False, "allowed_origins list cannot be empty"
    for origin in origins:
        if not isinstance(origin, str):
            return False, f"Origin entry must be a string, got {type(origin).__name__}"
        
        try:
            parsed = urlparse(origin)
            # Must have a scheme
            if not parsed.scheme:
                return False, f"Origin '{origin}' missing scheme (http/https)"
            # Only http and https allowed
            if parsed.scheme not in ("http", "https"):
                return False, f"Origin '{origin}' uses unsupported scheme '{parsed.scheme}' (only http/https allowed)"
            # Must have a netloc (domain)
            if not parsed.netloc:
                return False, f"Origin '{origin}' missing domain"
            # Should not have a path (origins don't include paths)
            if parsed.path and parsed.path != "/":
                return False, f"Origin '{origin}' should not include path (remove '{parsed.path}')"
        
        except Exception as e:
            return False, f"Failed to parse origin '{origin}': {str(e)}"
    return True, None


def validate_cors_methods(methods: list) -> tuple[bool, Optional[str]]:
    # Validate user declared CORS allowed methods, should be valid HTTP methods.
    if not isinstance(methods, list):
        return False, "allowed_methods must be a list"
    if not methods:
        return False, "allowed_methods list cannot be empty"
    
    valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    
    for method in methods:
        if not isinstance(method, str):
            return False, f"Method entry must be a string, got {type(method).__name__}"
        if method.upper() not in valid_methods:
            return False, f"Invalid HTTP method '{method}' (must be one of {valid_methods})"
    return True, None
