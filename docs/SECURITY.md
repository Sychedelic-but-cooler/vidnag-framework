# Security Implementation Guide

This document outlines the security measures implemented in the YT-DLP WebUI application to protect against common web vulnerabilities and attacks.

## Overview

The application implements security controls at multiple layers:
- Input validation and sanitization
- Path traversal prevention
- Server-Side Request Forgery (SSRF) protection
- Rate limiting
- CORS configuration (file-based, not web UI exposed)
- Secure file handling
- Command injection prevention
- Trusted proxy configuration (file-based, not web UI exposed)

## Admin Settings Configuration (File-Based, No Web UI Access)

**Important**: All security-critical settings are stored in `admin_settings.json` and are **NOT exposed via the web UI** until secure authentication is implemented. This prevents unauthorized modification of security parameters.

### Settings Separation Strategy

The application maintains two separate configuration files:

| Setting | Storage | Web UI Access | Modification | Requires Restart |
|---------|---------|---------------|--------------|-----------------|
| Download concurrency, disk space, compression | `settings.json` | `/api/settings/queue` ✓ | Yes, via API | No |
| CORS origins, trusted proxies, rate limits | `admin_settings.json` | **None** ✗ | File-only | Yes |

This separation ensures security-sensitive parameters cannot be modified without direct server access and application restart.

### Admin Settings File

**Location**: `admin_settings.json` (root directory)

**Loading Behavior**:
- Loaded **once at application startup** before any requests are processed
- Validated immediately - invalid configuration causes startup failure
- Requires application restart to apply changes
- If file is missing, safe restrictive defaults are used with warning logged

**Example Default Config** (used if `admin_settings.json` not found):
```json
{
  "cors": {
    "allowed_origins": ["http://localhost", "http://localhost:8000"],
    "allow_credentials": true,
    "allowed_methods": ["GET", "POST", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  },
  "proxy": {
    "enabled": true,
    "trusted_proxies": ["127.0.0.1"],
    "trust_x_forwarded_for": true,
    "trust_x_real_ip": true,
    "trust_forwarded_header": true,
    "max_proxy_hops": 2,
    "require_https": false
  },
  "rate_limiting": {
    "enabled": true,
    "max_requests_per_window": 20,
    "window_seconds": 60,
    "max_tracked_ips": 10000,
    "cleanup_interval_seconds": 3600
  },
  "security": {
    "debug_proxy_headers": false,
    "validate_ip_format": true
  }
}
```

### Configuration Examples by Proxy Type

#### Nginx Proxy Manager

```json
{
  "cors": {
    "allowed_origins": ["https://yourdomain.com"],
    "allow_credentials": true,
    "allowed_methods": ["GET", "POST", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  },
  "proxy": {
    "enabled": true,
    "trusted_proxies": ["127.0.0.1"],
    "trust_x_forwarded_for": true,
    "trust_x_real_ip": false,
    "trust_forwarded_header": true,
    "max_proxy_hops": 1,
    "require_https": true
  },
  "rate_limiting": {
    "enabled": true,
    "max_requests_per_window": 50,
    "window_seconds": 60,
    "max_tracked_ips": 10000,
    "cleanup_interval_seconds": 3600
  },
  "security": {
    "debug_proxy_headers": false,
    "validate_ip_format": true
  }
}
```

#### Caddy Reverse Proxy

```json
{
  "cors": {
    "allowed_origins": ["https://yourdomain.com"],
    "allow_credentials": true,
    "allowed_methods": ["GET", "POST", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  },
  "proxy": {
    "enabled": true,
    "trusted_proxies": ["127.0.0.1"],
    "trust_x_forwarded_for": true,
    "trust_x_real_ip": true,
    "trust_forwarded_header": true,
    "max_proxy_hops": 1,
    "require_https": true
  },
  "rate_limiting": {
    "enabled": true,
    "max_requests_per_window": 30,
    "window_seconds": 60,
    "max_tracked_ips": 5000,
    "cleanup_interval_seconds": 1800
  },
  "security": {
    "debug_proxy_headers": false,
    "validate_ip_format": true
  }
}
```

#### Load Balancer with Multiple Proxies

```json
{
  "cors": {
    "allowed_origins": ["https://api.yourdomain.com", "https://app.yourdomain.com"],
    "allow_credentials": true,
    "allowed_methods": ["GET", "POST", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  },
  "proxy": {
    "enabled": true,
    "trusted_proxies": ["10.0.0.0/8", "172.16.0.0/12"],
    "trust_x_forwarded_for": true,
    "trust_x_real_ip": true,
    "trust_forwarded_header": true,
    "max_proxy_hops": 2,
    "require_https": true
  },
  "rate_limiting": {
    "enabled": true,
    "max_requests_per_window": 100,
    "window_seconds": 60,
    "max_tracked_ips": 50000,
    "cleanup_interval_seconds": 3600
  },
  "security": {
    "debug_proxy_headers": false,
    "validate_ip_format": true
  }
}
```

#### Local Development (No Proxy)

```json
{
  "cors": {
    "allowed_origins": ["http://localhost", "http://localhost:8000", "http://127.0.0.1"],
    "allow_credentials": true,
    "allowed_methods": ["GET", "POST", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  },
  "proxy": {
    "enabled": false,
    "trusted_proxies": [],
    "trust_x_forwarded_for": false,
    "trust_x_real_ip": false,
    "trust_forwarded_header": false,
    "max_proxy_hops": 0,
    "require_https": false
  },
  "rate_limiting": {
    "enabled": false,
    "max_requests_per_window": 20,
    "window_seconds": 60,
    "max_tracked_ips": 10000,
    "cleanup_interval_seconds": 3600
  },
  "security": {
    "debug_proxy_headers": true,
    "validate_ip_format": true
  }
}
```

### Trusted Proxies Configuration

The `trusted_proxies` list in the `proxy` section controls which IP addresses/networks are trusted to set proxy headers.

**Supported Formats**:
- Single IP: `"127.0.0.1"` (IPv4) or `"::1"` (IPv6)
- CIDR notation: `"10.0.0.0/8"` (IPv4) or `"2001:db8::/32"` (IPv6)

**Common Values**:
- Localhost: `["127.0.0.1"]`
- Private networks: `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]`
- IPv6 localhost: `["::1"]`
- IPv6 private: `["fc00::/7"]`

**Security Impact**: Only clients whose connection originates from a trusted proxy can set proxy headers. Other clients cannot spoof `X-Forwarded-For` headers, preventing rate limit bypass and false IP address logging.

### Configuration Application

To change security settings:

1. **Edit `admin_settings.json`** on the server with new configuration
2. **Restart the application** for changes to take effect
3. **Check logs** for validation errors (app will refuse to start if config is invalid)

Example validation errors that cause startup failure:
- Invalid IP address: `"192.168.1.256"` (256 is out of range)
- Invalid CIDR: `"10.0.0.0/33"` (33 exceeds maximum)
- Invalid URL in CORS: `"example.com"` (missing `http://` or `https://` scheme)
- Empty CORS origins list (must have at least one origin)

### Implementation

Admin settings are implemented in:
- **`admin_settings.py`** - Load, parse, validate, and expose admin settings globally
- **`security.py`** - Validation functions for CORS origins, trusted proxies, IP addresses
- **`main.py`** - CORS middleware, proxy middleware, and rate limiting use admin settings

Code references:
- Admin settings module initialization: `main.py` lifespan function
- CORS configuration: `main.py` lines ~165
- Proxy middleware: `main.py` lines ~180-270
- Rate limiting: `main.py` lines ~302-375

---

## 1. Input Validation & Sanitization

### 1.1 Filename Validation

**Purpose**: Prevent path traversal attacks and ensure filesystem compatibility.

**Implementation** ([`security.py` lines 38-76](security.py)):
- Rejects path separators (`/` and `\`) to prevent directory traversal
- Blocks parent directory references (`..`) 
- Rejects absolute paths (e.g., `C:\Windows`, `/etc/passwd`)
- Rejects hidden files (starting with `.`) to prevent access to config files like `.env`
- Enforces maximum filename length of 255 characters

**Usage** ([`main.py` lines 1403-1410, 1439-1456, 1473-1483, 1527-1535](main.py)):
All file serving endpoints validate filenames before access:
- Thumbnail retrieval (`/api/files/thumbnail/{filename}`)
- Video streaming (`/api/files/video/{filename}`)
- File downloads (`/api/files/download/{filename}`)
- File deletion (`/api/files/{filename}`)

**Example Attack Blocked**:
```
Request: GET /api/files/download/../../etc/passwd
Result: HTTP 400 - Invalid filename
Logged: "Invalid filename rejected: ../../etc/passwd"
```

### 1.2 URL Validation

**Purpose**: Prevent Server-Side Request Forgery (SSRF) attacks and ensure only web URLs are processed.

**Implementation** ([`security.py` lines 80-154](security.py)):
- Enforces maximum URL length of 2048 characters to prevent DoS
- Validates URL format using `urlparse`
- Requires HTTP/HTTPS schemes only (blocks `file://`, `ftp://`, etc.)
- Blocks all private and local network addresses:
  - Localhost patterns: `localhost`, `127.x.x.x`, `0.0.0.0`
  - Private networks: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
  - IPv6 loopback: `[::1]`, `[::]`
- Provides detailed error messages for logging

**Usage** ([`main.py` lines 1017-1033](main.py)):
Validated on every download request before processing:
```python
is_valid, error_msg = validate_url(request.url)
if not is_valid:
    await emit_log("WARNING", "API", f"Invalid URL rejected: {error_msg}")
    raise HTTPException(status_code=400, detail=f"Invalid URL: {error_msg}")
```

**Example Attack Blocked**:
```
Request: POST /api/download with url="http://192.168.1.1/admin"
Result: HTTP 400 - "Local and private network URLs are not allowed"
Logged: WARNING log with client IP for audit trail
```

### 1.3 Cookie Filename Validation

**Purpose**: Prevent injection attacks when cookie files are passed to yt-dlp commands.

**Implementation** ([`security.py` lines 184-210](security.py)):
- Enforces `.txt` extension requirement (yt-dlp format)
- Applies general filename validation rules
- Restricts characters to alphanumeric, dashes, and underscores only
- Pattern: `^[a-zA-Z0-9_-]+$` (before `.txt` extension)

**Usage** ([`main.py` lines 1017-1051](main.py)):
Validated when cookie file is provided with download request.

**Example Attack Blocked**:
```
Request: POST /api/download with cookies_file="test; rm -rf /"
Result: HTTP 400 - "Invalid cookie file"
Logged: WARNING log with attempted injection
```

### 1.4 Settings Update Validation

**Purpose**: Prevent users from modifying internal settings or setting invalid values that could cause resource exhaustion.

**Implementation** ([`security.py` lines 218-253](security.py)):
- **Whitelist approach**: Only allows modification of specific keys:
  - `max_concurrent_downloads` (1-10 range)
  - `max_download_speed` (0 or positive MiB/s)
  - `min_disk_space_mb` (minimum 100 MB)
- Validates data types and ranges
- Rejects any attempt to modify internal settings like `zip_avg_compression_ratio`

**Usage** ([`main.py` lines 1341-1348](main.py)):
```python
is_valid, error_msg = validate_settings_update(updates)
if not is_valid:
    await emit_log("WARNING", "Settings", f"Invalid settings update rejected: {error_msg}")
    raise HTTPException(status_code=400, detail=error_msg)
```

## 2. Path Traversal Prevention

**Purpose**: Ensure all file operations remain within the `downloads/` directory.

**Implementation** ([`security.py` lines 10-35](security.py)):

The `is_safe_path()` function uses canonical path resolution:
1. Resolves both base directory and target file to absolute paths
2. Handles symbolic links by resolving them
3. Normalizes paths to prevent tricks like `downloads/./files/../../etc/`
4. Verifies target path starts with base path

```python
def is_safe_path(base_dir: str, file_path: str) -> bool:
    base = Path(base_dir).resolve()
    target = (Path(base_dir) / file_path).resolve()
    return str(target).startswith(str(base))
```

**Usage**: All file operations verify safety:
- ZIP downloads ([`main.py` lines 1583-1629](main.py))
- File deletion ([`main.py` lines 1527-1575](main.py))
- Thumbnail serving ([`main.py` lines 1403-1428](main.py))
- Video streaming ([`main.py` lines 1439-1468](main.py))

**Example Attack Blocked**:
```
Request: GET /api/files/video/../../etc/passwd
Processing: 
  1. Input: "../../etc/passwd"
  2. Validation: /absolute/path/downloads/etc/passwd
  3. Check: Does not start with /absolute/path/downloads
  4. Result: HTTP 403 - "Access denied"
  5. Logged: WARNING - "Path traversal attempt blocked"
```

## 3. Rate Limiting

**Purpose**: Prevent abuse and brute force attacks on the API.

**Implementation** ([`main.py` lines 302-375](main.py)):
- Tracks requests per IP address using a sliding window algorithm
- Configuration loaded from `admin_settings.json` at startup
- Configurable parameters:
  - `max_requests_per_window`: Maximum requests allowed per IP
  - `window_seconds`: Time window for requests
  - `max_tracked_ips`: Maximum IPs to track (prevents memory exhaustion)
  - `cleanup_interval_seconds`: How often to clean up inactive IPs
- Uses client IP from proxy middleware (validated against trusted proxies)

```python
def check_rate_limit(client_ip: str) -> bool:
    # Load parameters from admin_settings
    # Remove expired timestamps outside current window
    # Check if request count exceeds limit
    # Return True if allowed, False if rate limited
```

**Usage** ([`main.py` lines 1125-1130](main.py)):
Applied to download endpoint:
```python
if not check_rate_limit(client_ip):
    await emit_log("WARNING", "API", f"Rate limit exceeded for IP: {client_ip}")
    raise HTTPException(status_code=429, detail="Rate limit exceeded...")
```

**Configuration** (from `admin_settings.json`):
```json
{
  "rate_limiting": {
    "enabled": true,
    "max_requests_per_window": 20,
    "window_seconds": 60,
    "max_tracked_ips": 10000,
    "cleanup_interval_seconds": 3600
  }
}
```

**Memory Management**: 
- Inactive IPs are automatically removed after `cleanup_interval_seconds` of inactivity
- Total tracked IPs is limited to `max_tracked_ips` to prevent memory exhaustion
- In-memory store, resets on application restart (suitable for single-instance deployments; multi-instance deployments should consider external state store)

## 4. CORS Configuration

**Purpose**: Control which origins can access the API.

**Implementation** ([`main.py` lines ~165](main.py)):
- Allowed origins configured in `admin_settings.json` (loaded at startup)
- NOT accessible or modifiable via web UI - file-based only
- Configuration parameters:
  - `allowed_origins`: List of approved domain origins (must include scheme: `https://` or `http://`)
  - `allow_credentials`: Allow cookies and auth headers in cross-origin requests
  - `allowed_methods`: HTTP methods permitted (typically `GET`, `POST`, `DELETE`)
  - `allowed_headers`: Request headers permitted (typically `Content-Type`, `Authorization`)

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=admin_settings.cors.allowed_origins,
    allow_credentials=admin_settings.cors.allow_credentials,
    allow_methods=admin_settings.cors.allowed_methods,
    allow_headers=admin_settings.cors.allowed_headers,
)
```

**Configuration** (from `admin_settings.json`):
```json
{
  "cors": {
    "allowed_origins": ["https://yourdomain.com"],
    "allow_credentials": true,
    "allowed_methods": ["GET", "POST", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"]
  }
}
```

**Security Benefit**:
- Prevents unauthorized cross-origin requests from malicious websites
- Requires explicit configuration for each deployment domain
- Changes require application restart and file access on server (prevents accidental misconfiguration)
- See Admin Settings Configuration section (above) for deployment-specific examples

## 5. Command Injection Prevention

### 5.1 yt-dlp Command Execution

**Purpose**: Prevent shell injection when executing yt-dlp with user-provided inputs.

**Implementation** ([`main.py` lines 818-944](main.py)):
- Uses `subprocess.run()` with `shell=False` (default)
- Constructs command as a list, not a string
- Validated inputs only:
  - URL: validated by `validate_url()` ([`security.py` lines 80-154](security.py))
  - Cookie file: validated by `validate_cookie_filename()` ([`security.py` lines 184-210](security.py))

```python
command = [
    "yt-dlp",
    "--quiet",
    "--no-warnings",
    "-o", output_template,
    "-f", format_selection,
]
if cookies_file:
    command.extend(["--cookies", cookies_file])
command.append(url)

# Safe execution - no shell interpretation
process = await asyncio.create_subprocess_exec(*command, ...)
```

**Timeout Protection** ([`main.py` lines 1380-1391](main.py)):
yt-dlp update command includes 60-second timeout to prevent hanging:
```python
result = subprocess.run(
    ["python3.12", "-m", "pip", "install", "--upgrade", "yt-dlp"],
    capture_output=True,
    text=True,
    timeout=60  # Security: Add timeout
)
```

### 5.2 pip Command Execution (Disabled by Default)

**Purpose**: Prevent unauthorized system package installation.

**Implementation** ([`main.py` lines 1357-1396](main.py)):
- Feature disabled by default (requires `ALLOW_YTDLP_UPDATE=true` environment variable)
- Uses full path to Python: `python3.12 -m pip`
- Hardcodes package name (no variable substitution)
- Returns HTTP 403 if not explicitly enabled

```python
allow_update = os.environ.get("ALLOW_YTDLP_UPDATE", "false").lower() == "true"
if not allow_update:
    raise HTTPException(status_code=403, 
        detail="yt-dlp updates are disabled for security...")
```

## 6. Filename Sanitization

**Purpose**: Handle special characters, emojis, and filesystem-incompatible characters in downloaded filenames.

**Implementation** ([`main.py` lines 379-442](main.py)):
1. **Unicode normalization**: Converts composed characters (é) to base + accent
2. **Unsafe character replacement**: Replaces `/ \ : * ? " < > | \n \r \t` with underscores
3. **Control character removal**: Strips invisible characters that cause filesystem issues
4. **Whitespace normalization**: Removes leading/trailing spaces and dots
5. **Duplicate underscore collapsing**: Prevents filenames like `video____title`
6. **Length enforcement**: UTF-8 byte limit of 200 characters (filesystem limit is 255)
7. **Fallback naming**: Uses `"video"` if entire filename is stripped

**Process Flow** ([`main.py` lines 846-870](main.py)):
When yt-dlp downloads a file:
1. Captures original filename from yt-dlp output
2. Applies `sanitize_filename()` transformation
3. If sanitized name differs, renames the file
4. Prevents filename collisions with counter suffixes
5. Logs the sanitization for audit trail

**Example Transformation**:
```
Input:  "Video: 🎬 [2024] - Special!??.mp4"
Output: "Video_2024_Special.mp4"
Logged: INFO - "Renamed file from '...' to '...'"
```

## 7. Secure File Serving

### 7.1 Video Streaming Security

**Implementation** ([`main.py` lines 1439-1468](main.py)):
- Validates filename before serving
- Checks path safety to prevent directory traversal
- Restricts file extensions to video types only:
  - `.mp4`, `.webm`, `.mkv`, `.avi`, `.mov`, `.flv`, `.wmv`, `.m4v`
- Returns correct MIME type based on extension
- Uses `FileResponse` (safe, doesn't execute files)

### 7.2 Thumbnail Serving Security

**Implementation** ([`main.py` lines 1403-1428](main.py)):
- Validates filename and path safety
- Restricts file extensions to image types only:
  - `.jpg`, `.jpeg`, `.png`, `.webp`
- Returns appropriate image MIME types

### 7.3 File Download Security

**Implementation** ([`main.py` lines 1473-1490](main.py)):
- Validates filename and path safety
- Uses `octet-stream` MIME type to force download
- Prevents browser from executing files

### 7.4 ZIP Download Security

**Implementation** ([`main.py` lines 1630-1681](main.py)):
- Validates each filename in the request
- Checks path safety for each file
- Skips files that fail validation (doesn't raise error, prevents info leakage)
- Streams ZIP directly without disk temp files
- Sets appropriate Content-Disposition header

```python
for filename in request.filenames:
    filepath = os.path.join("downloads", filename)
    
    # Security check: ensure the file is in the downloads directory
    real_path = os.path.realpath(filepath)
    downloads_dir = os.path.realpath("downloads")
    if not real_path.startswith(downloads_dir):
        continue  # Skip invalid files silently
```

## 8. Logging & Audit Trail

### 8.1 Security Event Logging

**Purpose**: Track security-relevant events for auditing and incident response.

**Implemented Logging** ([`main.py` lines 448-495](main.py)):

Security events logged with context:
- **Invalid URL rejection**: URL, reason, client IP
- **Rate limit exceeded**: Client IP, request count
- **Path traversal attempts**: Filename, type of attempt
- **Invalid cookie file**: Provided filename, attempt details
- **Settings update rejection**: Invalid key/value, reason
- **File access attempts**: Success/failure, filename
- **Command execution**: Results, errors
- **System startup/shutdown**: Configuration, status

**Log Entry Structure**:
```python
log_entry = LogEntry(
    sequence=log_sequence,        # Unique incrementing ID
    timestamp=datetime.now(timezone.utc).isoformat(),  # ISO 8601 UTC
    level=level,                  # DEBUG, INFO, SUCCESS, WARNING, ERROR
    component=component,          # System, API, Download, Settings, etc.
    message=message,              # Human-readable message
    download_id=download_id       # Optional download context
)
```

### 8.2 Log Retention

**Implementation** ([`main.py` lines 51-77](main.py)):
- **Rotation**: Logs rotate daily at midnight
- **Retention**: 3 days of backup logs (automatic deletion after 3 days)
- **Location**: `logs/application.log` and `logs/application.log.YYYY-MM-DD`
- **Cleanup**: Old logs removed on application startup ([`main.py` lines 51-77](main.py))

**Purpose**: Prevents disk space exhaustion from long-running applications while maintaining recent audit history.

### 8.3 Sensitive Information Filtering

**Implementation** ([`security.py` lines 154-182](security.py)):
- `sanitize_url_for_logging()` removes query parameters from URLs before logging
- Prevents accidental logging of authentication tokens
- Maintains path and domain for debugging purposes

```python
def sanitize_url_for_logging(url: str, max_length: int = 100) -> str:
    # Removes query string (contains potential secrets)
    # Returns only: scheme://domain/path
```

## 9. Database Security

### 9.1 SQL Injection Prevention

**Implementation** ([`database.py` lines 1-100](database.py)):
- Uses SQLAlchemy ORM which prevents SQL injection through parameterized queries
- All queries use ORM methods, not raw SQL strings
- Example ([`main.py` lines 1074-1088](main.py)):

```python
download = DatabaseService.get_download_by_id(db, download_id)
# SQLAlchemy handles: db.query(Download).filter(Download.id == download_id)
# Parameters are safely bound, not concatenated into SQL
```

### 9.2 Database File Permissions

**Implementation** ([`database.py` lines 94-120](database.py)):
- Database file: `data.db` (SQLite)
- Should be configured with restricted permissions in production
- Recommendation: `chmod 600 data.db` (owner read/write only)

## 10. Dependency Security

**Implementation** ([`requirements.txt`](requirements.txt)):
All dependencies pinned to specific versions:
- `fastapi==0.115.5`
- `uvicorn[standard]==0.32.1`
- `sqlalchemy==2.0.36`
- `yt-dlp==2024.12.3`
- `python-multipart==0.0.20`
- `aiofiles==24.1.0`
- `websockets==14.1`

**Security Benefit**:
- Prevents automatic updates to versions with unknown changes
- Allows controlled, tested upgrades
- Reduces supply chain attack surface

**Recommendations**:
- Regularly audit for security updates in dependencies
- Test updates in staging before production deployment
- Use `pip-audit` or similar tools to check for known vulnerabilities

## 11. Information Disclosure Prevention

### 11.1 Error Message Sanitization

**Implementation** ([`main.py` lines 979-988](main.py)):
- Generic error message returned to client: `"Internal server error"`
- Detailed error information logged server-side for debugging
- Prevents leaking system information to attackers

```python
try:
    # Process request
except Exception as exc:
    await emit_log("ERROR", "System", f"Detailed error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}  # Generic message
    )
```

### 11.2 Directory Listing Prevention

**Implementation**:
- Only specific endpoints serve files (no directory listing)
- Direct directory access returns 404
- Hidden files (starting with `.`) are blocked from access

## 12. WebSocket Security

**Implementation** ([`main.py` lines 1251-1284](main.py)):
- WebSocket endpoint for log streaming: `/ws/logs`
- Same CORS configuration applies
- Automatic heartbeat every 30 seconds to detect disconnections
- All clients receive all logs (no per-user filtering)

**Limitation**: Currently not used in production (HTTP polling used instead for proxy compatibility). If enabled in future:
- Verify CORS whitelist is updated
- Ensure firewall rules allow WebSocket upgrade
- Consider rate limiting WebSocket messages

## 13. Recommendations for Deployment

### 13.1 HTTPS/TLS

- **Must**: Use HTTPS in production
- Proxy headers middleware ([`main.py` lines 200-217](main.py)) supports HTTPS proxies
- Ensure reverse proxy (e.g., Nginx) has valid SSL certificate
- Update CORS `allow_origins` to use `https://` scheme

### 13.2 Environment Variables

- Set `ALLOW_YTDLP_UPDATE=false` (default, do not enable in production)
- Configure `DEBUG_MODE` if implemented
- Use strong database paths

### 13.3 File Permissions

- Download directory: `755` (user can read/write, others read only)
- Database file: `600` (owner read/write only)
- Log directory: `755`
- Application files: `644` (readable)

### 13.4 Reverse Proxy Configuration

- Use Nginx Proxy Manager or similar with:
  - SSL/TLS termination
  - Rate limiting at proxy level
  - Request size limits
  - XSS and injection attack filtering
  - Request logging for security monitoring

### 13.5 Network Security

- Restrict API access to intended networks
- Use firewall rules to limit access
- Consider IP whitelisting for administrative endpoints
- Monitor for suspicious access patterns

### 13.6 Monitoring & Logging

- Export logs to centralized logging system (ELK, Splunk)
- Set up alerts for:
  - Multiple rate limit violations from same IP
  - Repeated path traversal attempts
  - Invalid URL rejections
  - Unexpected errors
- Regular log review for security incidents

### 13.7 Regular Updates

- Keep yt-dlp updated (use `pip install --upgrade yt-dlp` in safe environment)
- Update FastAPI and dependencies after testing
- Monitor security advisories for dependencies
- Test updates in staging environment before production

## Security Testing Checklist

- [ ] Verify path traversal attempts are blocked (test with `../` patterns)
- [ ] Verify SSRF is blocked (test with `http://localhost`, `http://192.168.x.x`)
- [ ] Verify rate limiting works (rapid requests from single IP)
- [ ] Verify CORS enforcement (requests from unauthorized origins)
- [ ] Verify invalid filenames are rejected (special characters, paths)
- [ ] Verify logs contain security event details
- [ ] Verify no sensitive data in error responses
- [ ] Verify cookie files can only have `.txt` extension
- [ ] Verify command injection is prevented (test with `; rm -rf /`)
- [ ] Verify database is not web-accessible

## Incident Response

If a security issue is suspected:

1. **Stop the application** if active attack is ongoing
2. **Collect logs** from `logs/` directory
3. **Review audit trail** for timeline of events
4. **Identify affected downloads** using download IDs in logs
5. **Quarantine affected files** if necessary
6. **Update filter rules** if attack pattern identified
7. **Patch and redeploy** after verification
8. **Document incident** for future reference

## Acknowledgments

Security implementation informed by:
- OWASP Top 10 vulnerabilities
- OWASP Path Traversal prevention guidelines
- CWE-22 (Path Traversal)
- CWE-78 (OS Command Injection)
- CWE-352 (Cross-Site Request Forgery)

---

**Document Version**: 1.0  
**Last Updated**: 2025  
**Review Frequency**: Quarterly or after significant changes

