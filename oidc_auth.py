"""
OIDC/OAuth Authentication Service
"""

import hashlib
import secrets
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlencode

import httpx
from sqlalchemy.orm import Session

from database import User, OIDCAuthState
from external_auth import OIDCConfig


class OIDCService:
    # Service for handling OIDC/OAuth authentication

    @staticmethod
    async def get_oidc_metadata(discovery_url: str) -> Dict[str, Any]:
        # Fetch OIDC provider metadata from discovery URL.
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            return response.json()

    @staticmethod
    def generate_pkce_pair() -> Tuple[str, str]:
        # Generate PKCE code_verifier and code_challenge pair, random code_verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

        # Create code_challenge = BASE64URL(SHA256(code_verifier))
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

        return code_verifier, code_challenge

    @staticmethod
    def create_auth_state(
        db: Session,
        redirect_uri: str,
        code_verifier: Optional[str],
        ip_address: str
    ) -> str:
        # Create OIDC auth state for CSRF protection, generate random state token
        state = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

        # Create auth state record
        auth_state = OIDCAuthState(
            state=state,
            code_verifier=code_verifier or "",
            redirect_uri=redirect_uri,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            ip_address=ip_address
        )

        db.add(auth_state)
        db.commit()

        return state

    @staticmethod
    def validate_and_consume_state(
        db: Session,
        state: str,
        ip_address: str
    ) -> Optional[OIDCAuthState]:
        # Validate OIDC state and consume it (one-time use).
        auth_state = db.query(OIDCAuthState).filter(OIDCAuthState.state == state).first()

        if not auth_state:
            return None

        # Check expiry
        if auth_state.expires_at < datetime.now(timezone.utc):
            db.delete(auth_state)
            db.commit()
            return None

        # Check IP address match (prevents session fixation attacks)
        if auth_state.ip_address != ip_address:
            db.delete(auth_state)
            db.commit()
            return None

        # State is valid - delete it (one-time use)
        result = auth_state
        db.delete(auth_state)
        db.commit()

        return result

    @staticmethod
    async def exchange_code_for_tokens(
        code: str,
        redirect_uri: str,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
       # Exchange authorization code for access token and ID token, supports both PKCE and non-PKCE flows.
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret
        }

        # Add PKCE code_verifier if using PKCE
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    async def get_userinfo(userinfo_endpoint: str, access_token: str) -> Dict[str, Any]:
        # Fetch user info from OIDC provider.
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    def determine_admin_status(userinfo: Dict[str, Any], config: OIDCConfig) -> bool:
        # Determine if user should be admin based on OIDC groups, admin claim is admin configurable.
        # Get groups/roles from configured claim
        groups = userinfo.get(config.admin_group_claim, [])

        # Handle both list and string values
        if isinstance(groups, str):
            groups = [groups]
        elif not isinstance(groups, list):
            groups = []

        # Check if admin group is present
        return config.admin_group_value in groups

    @staticmethod
    def find_or_create_user(
        db: Session,
        userinfo: Dict[str, Any],
        config: OIDCConfig,
        provider_name: str
    ) -> Tuple[Optional[User], Optional[str]]:
        # Find existing OIDC user or create new one.
        oidc_subject = userinfo.get("sub")
        if not oidc_subject:
            return None, "OIDC provider did not return 'sub' claim"

        # Check if user already exists by oidc_subject
        existing_user = db.query(User).filter(User.oidc_subject == oidc_subject).first()
        if existing_user:
            return existing_user, None

        # Extract username from OIDC claim
        username = userinfo.get(config.username_claim)
        if not username:
            return None, f"OIDC provider did not return '{config.username_claim}' claim"

        # Check if username already exists (conflict - requires manual linking)
        username_conflict = db.query(User).filter(User.username == username).first()
        if username_conflict:
            return None, f"Username '{username}' already exists. Contact admin to link accounts."

        # Auto-create user if enabled
        if not config.auto_create_users:
            return None, "User does not exist and auto-creation is disabled"

        # Determine admin status from OIDC groups
        is_admin = OIDCService.determine_admin_status(userinfo, config)

        # Extract email
        oidc_email = userinfo.get(config.email_claim)

        # Create new OIDC user
        new_user = User(
            username=username,
            password_hash=None,  # OIDC-only user, no local password
            is_admin=is_admin,
            is_disabled=False,
            oidc_provider=provider_name,
            oidc_subject=oidc_subject,
            oidc_email=oidc_email,
            oidc_linked_at=datetime.now(timezone.utc),
            admin_override=False,  # Not manually overridden yet
            last_login=None
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return new_user, None

    @staticmethod
    def build_authorization_url(
        authorization_endpoint: str,
        client_id: str,
        redirect_uri: str,
        scopes: list,
        state: str,
        code_challenge: Optional[str] = None
    ) -> str:
        # Build OIDC authorization URL for redirect.
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state
        }

        # Add PKCE challenge if using PKCE
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        return f"{authorization_endpoint}?{urlencode(params)}"

    @staticmethod
    def cleanup_expired_states(db: Session) -> int:
        # Clean up expired OIDC auth states.
        now = datetime.now(timezone.utc)
        expired_states = db.query(OIDCAuthState).filter(OIDCAuthState.expires_at < now).all()

        count = len(expired_states)
        for state in expired_states:
            db.delete(state)

        db.commit()
        return count
