"""
Authentication Services for Vidnag Framework
"""

import bcrypt
import jwt
import secrets
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from database import User, UserLoginHistory, JWTKey, FailedLoginAttempt, AuthAuditLog


class PasswordService:
    # Service for secure password hashing and verification using bcrypt.
    @staticmethod
    def hash_password(password: str) -> str:
        # Hash a password using bcrypt with a salt.
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        # Verify a password against its hash using constant-time comparison.
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except Exception:
            return False


class JWTService:
    # Service for JWT token generation, validation, and key rotation.
    @staticmethod
    def generate_secret_key() -> str:
        return base64.b64encode(secrets.token_bytes(64)).decode('utf-8')

    @staticmethod
    def get_active_key(db: Session) -> Optional[JWTKey]:
        return db.query(JWTKey).filter(
            JWTKey.is_active == True,
            JWTKey.expires_at > datetime.now(timezone.utc)
        ).order_by(JWTKey.created_at.desc()).first()

    @staticmethod
    def create_new_key(db: Session, admin_settings) -> JWTKey:
        # Create a new JWT signing key with configured expiry.
        key_value = JWTService.generate_secret_key()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=admin_settings.auth.jwt_key_rotation_days
        )

        jwt_key = JWTKey(
            key_value=key_value,
            expires_at=expires_at,
            is_active=True
        )
        db.add(jwt_key)
        db.commit()
        db.refresh(jwt_key)
        return jwt_key

    @staticmethod
    def rotate_keys_if_needed(db: Session, admin_settings) -> JWTKey:
        # Check if key rotation is needed and rotate if necessary or if expiry time is < 1 day.
        active_key = JWTService.get_active_key(db)
        if not active_key:
            # No active key exists, create one
            return JWTService.create_new_key(db, admin_settings)

        # Check if key is about to expire (within 1 day)
        one_day_from_now = datetime.now(timezone.utc) + timedelta(days=1)
        if active_key.expires_at <= one_day_from_now:
            # Deactivate old key
            active_key.is_active = False
            active_key.revoked_at = datetime.now(timezone.utc)
            db.commit()

            # Create new key
            return JWTService.create_new_key(db, admin_settings)

        return active_key

    @staticmethod
    def create_access_token(
        user_id: str,
        username: str,
        is_admin: bool,
        db: Session,
        admin_settings
    ) -> str:
        # Create a JWT access token for a user and ensure we have an active key
        jwt_key = JWTService.rotate_keys_if_needed(db, admin_settings)

        # Create token payload
        expiry = datetime.now(timezone.utc) + timedelta(
            hours=admin_settings.auth.jwt_session_expiry_hours
        )

        payload = {
            "sub": user_id,  # Subject: user ID
            "username": username,
            "is_admin": is_admin,
            "exp": expiry,  # Expiration time
            "iat": datetime.now(timezone.utc),  # Issued at
            "jti": str(uuid.uuid4())  # JWT ID
        }

        # Sign and return token
        return jwt.encode(
            payload,
            jwt_key.key_value,
            algorithm=admin_settings.auth.jwt_algorithm
        )

    @staticmethod
    def decode_token(token: str, db: Session, admin_settings) -> Optional[Dict[str, Any]]:
        # Decode and validate a JWT token.
        try:
            # Get active key
            jwt_key = JWTService.get_active_key(db)
            if not jwt_key:
                return None

            # Decode and validate
            payload = jwt.decode(
                token,
                jwt_key.key_value,
                algorithms=[admin_settings.auth.jwt_algorithm]
            )

            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None


class AuthService:
    # Service for authentication operations including login, lockout, and IP tracking.
    @staticmethod
    def check_account_lockout(username: str, db: Session) -> Tuple[bool, Optional[datetime]]:
        # Check if account is locked due to failed login attempts.
        recent_lockout = db.query(FailedLoginAttempt).filter(
            FailedLoginAttempt.username == username,
            FailedLoginAttempt.lockout_until.isnot(None),
            FailedLoginAttempt.lockout_until > datetime.now(timezone.utc)
        ).order_by(FailedLoginAttempt.attempt_time.desc()).first()

        if recent_lockout:
            return True, recent_lockout.lockout_until

        return False, None

    @staticmethod
    def record_failed_attempt(
        username: str,
        ip_address: str,
        db: Session,
        admin_settings
    ) -> bool:
        # Record a failed login attempt and lock account if threshold reached.
        attempt = FailedLoginAttempt(
            username=username,
            ip_address=ip_address
        )
        db.add(attempt)

        # Count recent failed attempts (within lockout window)
        cutoff = datetime.now(timezone.utc) - timedelta(
            minutes=admin_settings.auth.failed_login_lockout_minutes
        )

        recent_failures = db.query(FailedLoginAttempt).filter(
            FailedLoginAttempt.username == username,
            FailedLoginAttempt.attempt_time > cutoff
        ).count()

        # Check if we've hit the threshold
        if recent_failures >= admin_settings.auth.failed_login_attempts_max:
            # Lock the account
            lockout_until = datetime.now(timezone.utc) + timedelta(
                minutes=admin_settings.auth.failed_login_lockout_minutes
            )
            attempt.lockout_until = lockout_until
            db.commit()
            return True  # Account locked

        db.commit()
        return False  # Not locked yet

    @staticmethod
    def clear_failed_attempts(username: str, db: Session):
        # Clear failed login attempts after successful login.
        db.query(FailedLoginAttempt).filter(
            FailedLoginAttempt.username == username
        ).delete()
        db.commit()

    @staticmethod
    def check_suspicious_ip_activity(
        user_id: str,
        current_ip: str,
        db: Session,
        admin_settings
    ) -> Tuple[bool, int]:
        # Check if user has logged in from too many different IPs, botnet/bruteforce protection.
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=admin_settings.auth.suspicious_ip_window_hours
        )

        # Get unique IPs from recent successful logins
        recent_ips = db.query(UserLoginHistory.ip_address).filter(
            UserLoginHistory.user_id == user_id,
            UserLoginHistory.login_time > cutoff,
            UserLoginHistory.success == True
        ).distinct().all()

        unique_ips = {ip[0] for ip in recent_ips}
        unique_ips.add(current_ip)  # Include current attempt

        ip_count = len(unique_ips)
        is_suspicious = ip_count > admin_settings.auth.suspicious_ip_threshold

        return is_suspicious, ip_count

    @staticmethod
    def authenticate_user(
        username: str,
        password: str,
        ip_address: str,
        user_agent: str,
        db: Session,
        admin_settings
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        # Authenticate a user after checking lockout and return result.
        is_locked, lockout_until = AuthService.check_account_lockout(username, db)
        if is_locked:
            minutes_remaining = int((lockout_until - datetime.now(timezone.utc)).total_seconds() / 60)
            return False, None, f"Account locked. Try again in {minutes_remaining} minutes."

        # Look up user
        user = db.query(User).filter(User.username == username).first()
        if not user:
            # User doesn't exist - record failed attempt
            AuthService.record_failed_attempt(username, ip_address, db, admin_settings)
            return False, None, "Invalid username or password"

        # Check if account is disabled
        if user.is_disabled:
            return False, None, "Account is disabled"

        # Verify password
        if not PasswordService.verify_password(password, user.password_hash):
            # Wrong password - record failed attempt
            was_locked = AuthService.record_failed_attempt(username, ip_address, db, admin_settings)
            if was_locked:
                return False, None, f"Account locked due to too many failed attempts. Try again in {admin_settings.auth.failed_login_lockout_minutes} minutes."
            return False, None, "Invalid username or password"

        # Check for suspicious IP activity
        is_suspicious, ip_count = AuthService.check_suspicious_ip_activity(
            user.id, ip_address, db, admin_settings
        )

        if is_suspicious:
            # Disable account and log the event
            user.is_disabled = True
            db.commit()
            return False, None, f"Account disabled due to suspicious activity (logins from {ip_count} different IPs within {admin_settings.auth.suspicious_ip_window_hours} hours)"

        # Authentication successful
        # Clear any old failed attempts
        AuthService.clear_failed_attempts(username, db)

        # Update last login time
        user.last_login = datetime.now(timezone.utc)
        db.commit()

        return True, user, None


class AuditLogService:
    # Service for recording authentication events in the audit log.
    @staticmethod
    def log_event(
        event_type: str,
        ip_address: str,
        db: Session,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        audit_entry = AuthAuditLog(
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            details=json.dumps(details) if details else None
        )
        db.add(audit_entry)
        db.commit()
