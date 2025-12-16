# Admin Privilege Security

## Overview
This document demonstrates that `is_admin` cannot be manipulated to gain unauthorized admin access.

## Security Layers

### 1. Frontend (localStorage)
**Status**: ✅ Secure
- Only `auth_token` is stored in localStorage
- `username` and `is_admin` are NOT stored (removed for security)
- Old entries are automatically cleaned up

### 2. Frontend (Memory)
**Status**: ⚠️ Can be manipulated, but SAFE
- `AUTH._userInfo.is_admin` is stored in JavaScript memory
- **Can be edited in browser console**, BUT this only affects the UI
- Example attack that FAILS:
  ```javascript
  // Open browser console (F12)
  AUTH._userInfo.is_admin = true;
  // UI might show admin buttons, but...
  ```

### 3. Backend (Database) - THE SECURITY BOUNDARY
**Status**: ✅ Secure - THIS IS WHAT MATTERS
- **Every API request checks the database, not the JWT payload or frontend**
- Even if someone manipulates the frontend, admin API calls will return `403 Forbidden`

## How Admin Verification Works

### Step 1: Token Validation
```python
# main.py:2302 - Validate JWT signature
payload = JWTService.decode_token(credentials.credentials, db, admin_settings)
```

### Step 2: Database Lookup
```python
# main.py:2311 - Query database for REAL user info
user = db.query(User).filter(User.id == payload["sub"]).first()
```

### Step 3: Return DATABASE Value (NOT JWT claim)
```python
# main.py:2321-2326 - SECURITY: Always use database value
return {
    "sub": user.id,
    "user_id": user.id,
    "username": user.username,
    "is_admin": user.is_admin  # ← From database, NOT from JWT
}
```

### Step 4: Admin Check
```python
# main.py:2329 - Admin endpoints check this value
if not current_user.get("is_admin", False):
    raise HTTPException(status_code=403, detail="Admin privileges required")
```

## Attack Scenarios (All Fail)

### ❌ Attack 1: Edit localStorage
```javascript
localStorage.setItem('is_admin', 'true');
```
**Result**: Does nothing - backend doesn't read localStorage

### ❌ Attack 2: Edit Memory
```javascript
AUTH._userInfo.is_admin = true;
```
**Result**: UI might change, but API calls check database:
```
GET /api/users → 403 Forbidden
POST /api/settings/update-ytdlp → 403 Forbidden
DELETE /api/users/123 → 403 Forbidden
```

### ❌ Attack 3: Forge JWT with is_admin=true
**Result**:
1. If secret leaked: JWT validates, but backend ignores JWT's `is_admin` claim
2. Backend queries database for real `is_admin` value
3. Database says `is_admin=false` → 403 Forbidden

### ❌ Attack 4: Modify Request
```javascript
fetch('/api/users', {
    headers: {
        'Authorization': 'Bearer ' + token,
        'X-Is-Admin': 'true'  // Try to inject admin flag
    }
})
```
**Result**: Backend ignores all headers except Authorization, checks database

## Admin-Protected Endpoints

All these endpoints require `Depends(get_current_admin_user)`:

- `POST /api/users` - Create user
- `GET /api/users` - List users
- `PATCH /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user
- `POST /api/settings/update-ytdlp` - Update yt-dlp
- `POST /api/settings/clear-ytdlp-cache` - Clear cache
- `POST /api/settings/cookies/upload` - Upload cookies
- `DELETE /api/settings/cookies/{filename}` - Delete cookies
- `GET /api/hardware/info` - Hardware info
- `POST /api/hardware/refresh` - Refresh hardware

## Privilege Demotion

If an admin is demoted to regular user:

1. Admin updates database: `UPDATE users SET is_admin=false WHERE id='123'`
2. User still has valid JWT with `is_admin: true` claim
3. User makes admin API request
4. Backend validates JWT ✅ (token is valid)
5. Backend queries database → sees `is_admin=false`
6. Backend returns 403 Forbidden ✅

**No need to revoke JWT** - database is always the source of truth.

## Best Practices

✅ **DO**: Trust backend validation
✅ **DO**: Use frontend `is_admin` only for UI purposes (show/hide buttons)
✅ **DO**: Always protect sensitive endpoints with `Depends(get_current_admin_user)`

❌ **DON'T**: Trust anything from the frontend (localStorage, memory, console)
❌ **DON'T**: Use JWT claims for authorization (use database)
❌ **DON'T**: Rely on frontend validation for security

## Summary

**Frontend manipulation is HARMLESS** because:
1. Frontend is only for UI/UX
2. All security decisions happen on the backend
3. Backend always checks the database
4. Database is the single source of truth

Even if someone:
- Edits localStorage
- Modifies AUTH._userInfo in console
- Tampers with JavaScript code
- Forges HTTP requests

**They cannot perform admin actions** because the backend verifies every request against the database.
