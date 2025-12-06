#!/usr/bin/env python
"""Quick test of admin settings and validation functions"""

from security import (
    validate_cors_origins,
    validate_trusted_proxies,
    validate_ip_address,
)
from admin_settings import get_admin_settings

print("Testing validation functions...")

# Test valid CORS origin
is_valid, err = validate_cors_origins(["https://example.com"])
print(f"Valid CORS origin: {is_valid}")
assert is_valid, f"Should be valid, got error: {err}"

# Test invalid CORS origin (missing scheme)
is_valid, err = validate_cors_origins(["example.com"])
print(f"Invalid CORS (no scheme) correctly rejected: {not is_valid}")
assert not is_valid, "Should be invalid"

# Test valid trusted proxies
is_valid, err = validate_trusted_proxies(["127.0.0.1", "10.0.0.0/8"])
print(f"Valid trusted proxies: {is_valid}")
assert is_valid, f"Should be valid, got error: {err}"

# Test invalid trusted proxies (bad CIDR)
is_valid, err = validate_trusted_proxies(["10.0.0.0/33"])
print(f"Invalid CIDR correctly rejected: {not is_valid}")
assert not is_valid, "Should be invalid"

# Test valid IP
is_valid, err = validate_ip_address("192.168.1.1")
print(f"Valid IP address: {is_valid}")
assert is_valid, f"Should be valid, got error: {err}"

# Test invalid IP
is_valid, err = validate_ip_address("999.999.999.999")
print(f"Invalid IP correctly rejected: {not is_valid}")
assert not is_valid, "Should be invalid"

print("\nTesting admin settings loading...")
try:
    admin_settings = get_admin_settings()
    print(f"  Admin settings loaded successfully")
    print(f"  - CORS origins: {admin_settings.cors.allowed_origins}")
    print(f"  - Trusted proxies: {admin_settings.proxy.trusted_proxies}")
    print(f"  - Rate limit enabled: {admin_settings.rate_limit.enabled}")
    print(f"  - Max requests per window: {admin_settings.rate_limit.max_requests_per_window}")
except Exception as e:
    print(f" Failed to load admin settings: {e}")
    raise

print("\n All tests passed!")
