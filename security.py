"""
Security utilities for the video downloader application
"""
import os
import re
from urllib.parse import urlparse
from typing import Optional
from pathlib import Path


def is_safe_path(base_dir: str, file_path: str) -> bool:
    """
    Check if a file path is safe and within the base directory.
    Prevents path traversal attacks where users try to access files
    outside the allowed directory using paths like "../../etc/passwd".

    Args:
        base_dir: The base directory that files must be within
        file_path: The file path to check

    Returns:
        True if the path is safe, False otherwise
    """
    try:
        # Resolve both paths to their absolute, canonical forms
        # This handles symbolic links, relative paths, and normalizes the path
        base = Path(base_dir).resolve()
        target = (Path(base_dir) / file_path).resolve()

        # Verify the target path starts with the base path
        # If someone tries "../../../etc/passwd", the resolved path won't match
        return str(target).startswith(str(base))
    except (ValueError, OSError):
        # If path resolution fails (invalid path, permission issues), reject it
        return False


def validate_filename(filename: str) -> bool:
    """
    Validate that a filename is safe and doesn't contain path traversal attempts.
    Ensures the filename can only reference a single file in the current directory.

    Args:
        filename: The filename to validate

    Returns:
        True if the filename is safe, False otherwise
    """
    if not filename:
        return False

    # Reject any path separators (prevents accessing other directories)
    # Covers both Unix (/) and Windows (\) separators
    if '/' in filename or '\\' in filename:
        return False

    # Reject parent directory references (prevents path traversal)
    # We already reject slashes above, so ".." alone would be the parent directory reference
    # However, we need to allow "..." (ellipsis) in filenames like "video...part1.mp4"
    # Only reject if the filename IS exactly ".." (not "...", "..abc", "abc..", etc.)
    if filename == '..':
        return False

    # Reject absolute paths (prevents accessing specific system locations)
    # Catches things like "C:\Windows" or "/etc/passwd"
    if os.path.isabs(filename):
        return False

    # Reject hidden files (prevents accessing config files like .env)
    # Most hidden files on Unix systems start with a dot
    if filename.startswith('.'):
        return False

    # Enforce filesystem filename length limit
    # Most filesystems have a 255 character limit for filenames
    if len(filename) > 255:
        return False

    return True


def validate_url(url: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a URL is safe for yt-dlp to process.
    Prevents Server-Side Request Forgery (SSRF) attacks by blocking
    local network access and ensures only web URLs are downloaded.

    Args:
        url: The URL to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url or not isinstance(url, str):
        return False, "URL is required"

    # Prevent extremely long URLs that could cause issues
    # 2048 is a common browser limit and reasonable for video URLs
    if len(url) > 2048:
        return False, "URL is too long (max 2048 characters)"

    # Parse the URL into components (scheme, domain, path, etc.)
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
    # This stops attackers from making the server access internal resources
    localhost_patterns = [
        'localhost',      # Standard localhost name
        '127.',           # Loopback addresses (127.0.0.0/8)
        '0.0.0.0',        # All interfaces binding
        '10.',            # Private network (10.0.0.0/8)
        '172.16.',        # Private network range start (172.16.0.0/12)
        '172.17.',        # Continue through the 172.16.0.0/12 range
        '172.18.',
        '172.19.',
        '172.20.',
        '172.21.',
        '172.22.',
        '172.23.',
        '172.24.',
        '172.25.',
        '172.26.',
        '172.27.',
        '172.28.',
        '172.29.',
        '172.30.',
        '172.31.',        # Private network range end
        '192.168.',       # Private network (192.168.0.0/16)
        '[::1]',          # IPv6 localhost
        '[::]',           # IPv6 all interfaces
    ]

    # Extract just the hostname part (remove port if present)
    hostname = parsed.netloc.split(':')[0].lower()
    for pattern in localhost_patterns:
        if hostname.startswith(pattern):
            return False, "Local and private network URLs are not allowed"

    return True, None


def sanitize_url_for_logging(url: str, max_length: int = 100) -> str:
    """
    Sanitize a URL for safe logging by removing sensitive parts.
    Prevents accidentally logging authentication tokens or private data
    that might be in query parameters (like ?token=secret).

    Args:
        url: The URL to sanitize
        max_length: Maximum length of the sanitized URL

    Returns:
        Sanitized URL safe for logging
    """
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
    """
    Validate that a cookie filename is safe.
    Cookie files need extra validation since they're user-provided
    and referenced in yt-dlp command execution.

    Args:
        filename: The cookie filename to validate

    Returns:
        True if the filename is safe, False otherwise
    """
    if not filename:
        return False

    # Enforce .txt extension for consistency and safety
    # yt-dlp expects cookie files in Netscape format (text files)
    if not filename.endswith('.txt'):
        return False

    # Apply general filename validation rules (no paths, no hidden files, etc.)
    if not validate_filename(filename):
        return False

    # Additional strictness for cookie files used in command execution
    # Only allow letters, numbers, dashes, and underscores to prevent injection
    name_without_ext = filename[:-4]  # Remove .txt extension
    if not re.match(r'^[a-zA-Z0-9_-]+$', name_without_ext):
        return False

    return True


def validate_settings_update(updates: dict) -> tuple[bool, Optional[str]]:
    """
    Validate settings updates for security and correctness.
    Prevents users from modifying internal settings or setting invalid values
    that could break the application or cause resource exhaustion.

    Args:
        updates: Dictionary of settings to update

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Whitelist of settings that users can modify through the API
    # Internal settings like zip_compression_samples are not included
    allowed_keys = ['max_concurrent_downloads', 'max_download_speed', 'min_disk_space_mb']

    for key in updates.keys():
        if key not in allowed_keys:
            return False, f"Setting '{key}' is not allowed"

    # Validate concurrent downloads limit
    # Between 1-10 to prevent resource exhaustion while allowing flexibility
    if "max_concurrent_downloads" in updates:
        value = updates["max_concurrent_downloads"]
        if not isinstance(value, int) or value < 1 or value > 10:
            return False, "max_concurrent_downloads must be between 1 and 10"

    # Validate download speed limit
    # 0 = unlimited, max 1000 MiB/s to prevent unrealistic values
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

    return True, None


def validate_ip_address(ip: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip: The IP address string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    from ipaddress import ip_address, AddressValueError
    
    try:
        ip_address(ip)
        return True, None
    except (AddressValueError, ValueError) as e:
        return False, f"Invalid IP address '{ip}': {str(e)}"


def validate_cidr_block(cidr: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a string is a valid CIDR notation (e.g., "10.0.0.0/8").
    
    Args:
        cidr: The CIDR notation string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    from ipaddress import ip_network, AddressValueError
    
    try:
        ip_network(cidr, strict=False)
        return True, None
    except (AddressValueError, ValueError) as e:
        return False, f"Invalid CIDR block '{cidr}': {str(e)}"


def validate_trusted_proxies(proxies: list) -> tuple[bool, Optional[str]]:
    """
    Validate a list of trusted proxy addresses.
    
    Each proxy can be:
    - A single IP address (e.g., "127.0.0.1", "::1")
    - A CIDR block (e.g., "10.0.0.0/8", "2001:db8::/32")
    
    Args:
        proxies: List of proxy addresses/CIDR blocks to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
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
    """
    Validate a list of CORS allowed origins.
    
    Each origin should be a valid URL with scheme (http/https).
    
    Args:
        origins: List of CORS origin URLs to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
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
    """
    Validate a list of CORS allowed HTTP methods.
    
    Args:
        methods: List of HTTP method names to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
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
