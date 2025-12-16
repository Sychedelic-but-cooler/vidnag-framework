# Admin Settings Web UI Implementation Plan

## Current Settings Analysis

### 1. CORS Configuration (4 settings)
```json
"cors": {
  "allowed_origins": ["http://localhost", ...],
  "allow_credentials": true,
  "allowed_methods": ["GET", "POST", "DELETE"],
  "allowed_headers": ["Content-Type", "Authorization"]
}
```

**Assessment**:
- ✅ Keep: `allowed_origins` - Important for production deployments
- ❌ Remove from UI: `allow_credentials` - Should always be true for auth
- ❌ Remove from UI: `allowed_methods` - Application determines this
- ❌ Remove from UI: `allowed_headers` - Application determines this

**Rationale**: Only origins need to be configurable. Methods and headers are application-specific and shouldn't be changed without code changes.

---

### 2. Proxy Configuration (3 settings)
```json
"proxy": {
  "is_behind_proxy": true,
  "proxy_header": "X-Forwarded-For",
  "trusted_proxies": ["192.168.8.125"]
}
```

**Assessment**:
- ✅ Keep: `is_behind_proxy` - Essential toggle
- ✅ Keep: `proxy_header` - Different proxies use different headers
- ✅ Keep: `trusted_proxies` - Security critical

**Rationale**: All three settings are deployment-specific and security-critical. Users need to configure these based on their infrastructure.

---

### 3. Rate Limiting Configuration (5 settings)
```json
"rate_limiting": {
  "enabled": true,
  "max_requests_per_window": 20,
  "window_seconds": 60,
  "max_tracked_ips": 10000,
  "cleanup_interval_seconds": 3600
}
```

**Assessment**:
- ✅ Keep: `enabled` - Toggle feature on/off
- ✅ Keep: `max_requests_per_window` - Tunable per deployment
- ✅ Keep: `window_seconds` - Tunable per deployment
- ⚠️ Advanced: `max_tracked_ips` - Most users don't need to change this
- ⚠️ Advanced: `cleanup_interval_seconds` - Most users don't need to change this

**Rationale**: Enable/window/max_requests are common tuning parameters. IP tracking and cleanup are advanced settings.

---

### 4. Security Configuration (3 settings)
```json
"security": {
  "debug_proxy_headers": true,
  "validate_ip_format": true,
  "allow_ytdlp_update": false
}
```

**Assessment**:
- ✅ Keep: `debug_proxy_headers` - Useful for troubleshooting
- ✅ Keep: `validate_ip_format` - Security toggle
- ✅ Keep: `allow_ytdlp_update` - Security policy decision

**Rationale**: All three are security-related toggles that admins may need to adjust.

---

### 5. Authentication Configuration (10 settings)
```json
"auth": {
  "enabled": true,
  "jwt_algorithm": "HS256",
  "jwt_session_expiry_hours": 24,
  "jwt_key_rotation_days": 7,
  "failed_login_attempts_max": 5,
  "failed_login_lockout_minutes": 30,
  "suspicious_ip_threshold": 3,
  "suspicious_ip_window_hours": 24,
  "require_auth_for_all_endpoints": true,
  "public_endpoints": ["/", "/favicon.ico", ...]
}
```

**Assessment**:
- ✅ Keep: `enabled` - Master toggle
- ❌ Remove from UI: `jwt_algorithm` - Should not be changed without understanding crypto
- ✅ Keep: `jwt_session_expiry_hours` - Common tuning parameter
- ⚠️ Advanced: `jwt_key_rotation_days` - Advanced security feature
- ✅ Keep: `failed_login_attempts_max` - Security policy
- ✅ Keep: `failed_login_lockout_minutes` - Security policy
- ✅ Keep: `suspicious_ip_threshold` - Security policy
- ✅ Keep: `suspicious_ip_window_hours` - Security policy
- ❌ Remove from UI: `require_auth_for_all_endpoints` - Application architecture decision
- ❌ Remove from UI: `public_endpoints` - Application architecture decision

**Rationale**:
- JWT algorithm requires cryptographic knowledge to change safely
- Session expiry and security thresholds are common admin adjustments
- Public endpoints and auth requirements are defined by application architecture

---

## Proposed Web UI Organization

### Location: Security Management → App Config Tab

**Tab Structure**:
```
App Config (Security Management → Tab 1)
├── Authentication Settings
├── Security Policies
├── Network & Proxy
└── Advanced Settings (Collapsible)
```

---

## Detailed UI Layout

### **Section 1: Authentication Settings**
*Controls for the authentication system*

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| **Enable Authentication** | Toggle | Enable/disable authentication system | `false` |
| **Session Duration** | Number + Dropdown | How long sessions last before re-login<br>Options: 1hr, 6hrs, 12hrs, 24hrs, 48hrs, 7days | `24 hours` |

**Notes**:
- Show warning when disabling auth
- Session duration in hours (dropdown with common values + custom input)

---

### **Section 2: Security Policies**
*Brute force protection and security thresholds*

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| **Failed Login Limit** | Number | Max failed attempts before lockout | `5` |
| **Lockout Duration** | Number + Unit | How long to lock account<br>Options: 15min, 30min, 1hr, 2hrs, 24hrs | `30 minutes` |
| **Suspicious IP Threshold** | Number | Failed attempts from IP before flagging | `3` |
| **Suspicious IP Window** | Number + Unit | Time window for tracking suspicious IPs<br>Options: 1hr, 6hrs, 12hrs, 24hrs | `24 hours` |
| **Validate IP Addresses** | Toggle | Reject malformed IP addresses | `true` |
| **Allow yt-dlp Updates** | Toggle | Allow updating yt-dlp from web UI | `false` |

**Notes**:
- Group failed login settings together
- Show current lockout count in UI if applicable

---

### **Section 3: Network & Proxy**
*Configure reverse proxy and CORS*

#### Proxy Settings

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| **Behind Reverse Proxy** | Toggle | Is app behind Nginx/Caddy/etc? | `false` |
| **Client IP Header** | Dropdown + Custom | Which header contains real client IP<br>Options: X-Forwarded-For, X-Real-IP, CF-Connecting-IP, Custom | `X-Forwarded-For` |
| **Trusted Proxy IPs** | List | IP addresses/CIDRs of trusted proxies | `["127.0.0.1"]` |

**Notes**:
- Show "Add Proxy IP" button for list management
- Validate IP/CIDR format
- Show help text: "Only trust proxies you control"

#### CORS Settings

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| **Allowed Origins** | List | Domains that can access the API | `["http://localhost:8000"]` |

**Notes**:
- Show "Add Origin" button
- Validate URL format
- Show help text: "Add domains that host your frontend"

---

### **Section 4: Advanced Settings** (Collapsible/Hidden by Default)
*Technical settings most users don't need to change*

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| **Rate Limiting Enabled** | Toggle | Enable API rate limiting | `true` |
| **Rate Limit - Requests** | Number | Max requests per window | `20` |
| **Rate Limit - Window** | Number + Unit | Time window for rate limiting<br>Options: 30s, 60s, 5min | `60 seconds` |
| **JWT Key Rotation** | Number + Unit | How often to rotate JWT keys<br>Options: 1day, 7days, 30days, Never | `7 days` |
| **Debug Proxy Headers** | Toggle | Log proxy headers (first 5 requests) | `false` |
| **Max Tracked IPs** | Number | Memory limit for rate limiting | `10000` |
| **Cleanup Interval** | Number + Unit | How often to cleanup rate limit data<br>Options: 30min, 1hr, 6hrs | `1 hour` |

**Notes**:
- Collapsed by default with "Show Advanced Settings" link
- Warning: "Only change these if you understand the implications"

---

## Settings to REMOVE from JSON (Hidden from UI)

These are application architecture decisions and should not be exposed:

```json
{
  "cors": {
    "allow_credentials": true,  // Always true with auth
    "allowed_methods": [...],    // Determined by application
    "allowed_headers": [...]     // Determined by application
  },
  "auth": {
    "jwt_algorithm": "HS256",    // Crypto decision, don't expose
    "require_auth_for_all_endpoints": true,  // Architecture decision
    "public_endpoints": [...]    // Architecture decision
  }
}
```

**Rationale**: These settings require understanding of application internals and should only be changed with code changes.

---

## UI/UX Considerations

### Form Design
- **Section Cards**: Each section in a glass-morphism card
- **Inline Help**: Small info icons (ⓘ) with tooltips
- **Validation**: Real-time validation with error messages
- **Warnings**: Show warnings for dangerous changes (disable auth, allow updates)
- **Save Button**: Single "Save Configuration" button at bottom
- **Restart Notice**: "Configuration changes require application restart"

### Validation Rules
1. **Proxy IPs**: Must be valid IP or CIDR notation
2. **CORS Origins**: Must be valid URLs or "*"
3. **Numbers**: Must be positive integers within reasonable ranges
4. **Session Duration**: Min 1 hour, Max 30 days
5. **Failed Login Limit**: Min 1, Max 20
6. **Lockout Duration**: Min 5 minutes, Max 24 hours

### Save Flow
1. User clicks "Save Configuration"
2. Frontend validates all fields
3. POST to `/api/admin/settings/update`
4. Backend validates and writes to `admin_settings.json`
5. Show success toast with restart reminder
6. Optionally: Add "Restart Application" button

---

## API Endpoints Needed

### 1. Get Current Settings
```
GET /api/admin/settings
Returns: Current admin_settings.json (filtered for UI-editable fields only)
```

### 2. Update Settings
```
POST /api/admin/settings/update
Body: Updated settings object
Returns: Success/failure with validation errors
```

### 3. Restart Application (Optional)
```
POST /api/admin/restart
Returns: Success message
Notes: Requires careful implementation, may need external supervisor
```

---

## Implementation Phases

### Phase 1: Read-Only Display
- Load settings from `/api/admin/settings`
- Display in organized sections
- No editing yet, just show current values

### Phase 2: Authentication & Security Sections
- Implement editable forms for auth and security settings
- Add validation
- Implement save functionality

### Phase 3: Network & Proxy Section
- Implement list management for trusted proxies and CORS origins
- Add proxy header dropdown

### Phase 4: Advanced Settings
- Implement collapsible advanced section
- Add rate limiting and technical settings

### Phase 5: Polish & Testing
- Add restart functionality
- Improve validation messages
- Test edge cases
- Add export/import config feature

---

## Summary: Settings Kept vs. Removed

### ✅ Keep in UI (19 settings)
**Authentication (2)**:
- enabled
- jwt_session_expiry_hours

**Security Policies (6)**:
- failed_login_attempts_max
- failed_login_lockout_minutes
- suspicious_ip_threshold
- suspicious_ip_window_hours
- validate_ip_format
- allow_ytdlp_update

**Network & Proxy (4)**:
- is_behind_proxy
- proxy_header
- trusted_proxies (list)
- allowed_origins (list)

**Advanced (7)**:
- rate_limiting.enabled
- rate_limiting.max_requests_per_window
- rate_limiting.window_seconds
- jwt_key_rotation_days
- debug_proxy_headers
- max_tracked_ips
- cleanup_interval_seconds

### ❌ Remove from UI (7 settings)
- cors.allow_credentials
- cors.allowed_methods
- cors.allowed_headers
- auth.jwt_algorithm
- auth.require_auth_for_all_endpoints
- auth.public_endpoints

**Total**: 19 editable settings organized into 4 sections
