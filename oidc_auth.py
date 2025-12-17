"""
OIDC/OAuth Authentication Service

Handles all OIDC/OAuth authentication flows including:
- Authorization Code Flow with PKCE
- Authorization Code Flow without PKCE
- User info retrieval
- Admin status determination
- User account management
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
    """Service for handling OIDC/OAuth authentication"""

    @staticmethod
    async def get_oidc_metadata(discovery_url: str) -> Dict[str, Any]:
        """
        Fetch OIDC provider metadata from discovery URL.

        Args:
            discovery_url: OIDC discovery endpoint URL
                         (e.g., https://auth.example.com/.well-known/openid-configuration)

        Returns:
            Dictionary containing OIDC metadata (endpoints, supported features, etc.)

        Raises:
            httpx.HTTPError: If metadata fetch fails
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            return response.json()

    @staticmethod
    def generate_pkce_pair() -> Tuple[str, str]:
        """
        Generate PKCE code_verifier and code_challenge pair.

        PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate random code_verifier (43-128 characters)
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
        """
        Create OIDC auth state for CSRF protection.

        Stores temporary state in database for validation during callback.
        State expires after 10 minutes.

        Args:
            db: Database session
            redirect_uri: Redirect URI used in authorization request
            code_verifier: PKCE code_verifier (None if not using PKCE)
            ip_address: IP address of user initiating login

        Returns:
            Generated state token
        """
        # Generate random state token
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
        """
        Validate OIDC state and consume it (one-time use).

        Security checks:
        1. State exists in database
        2. State hasn't expired
        3. IP address matches (prevents session fixation)
        4. State is deleted after validation (one-time use)

        Args:
            db: Database session
            state: State token from callback
            ip_address: IP address of user completing login

        Returns:
            OIDCAuthState if valid, None if invalid
        """
        # Find state in database
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
        """
        Exchange authorization code for access token and ID token.

        Supports both PKCE and non-PKCE flows.

        Args:
            code: Authorization code from callback
            redirect_uri: Same redirect_uri used in authorization request
            token_endpoint: OIDC token endpoint URL
            client_id: OAuth client ID
            client_secret: OAuth client secret
            code_verifier: PKCE code_verifier (None if not using PKCE)

        Returns:
            Token response containing access_token, id_token, etc.

        Raises:
            httpx.HTTPError: If token exchange fails
        """
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
        """
        Fetch user info from OIDC provider.

        Args:
            userinfo_endpoint: OIDC userinfo endpoint URL
            access_token: Access token from token exchange

        Returns:
            User info dictionary (sub, email, preferred_username, groups, etc.)

        Raises:
            httpx.HTTPError: If userinfo fetch fails
        """
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    def determine_admin_status(userinfo: Dict[str, Any], config: OIDCConfig) -> bool:
        """
        Determine if user should be admin based on OIDC groups.

        Checks if the configured admin group is present in the user's groups/roles.

        Args:
            userinfo: User info from OIDC provider
            config: OIDC configuration

        Returns:
            True if user should be admin, False otherwise
        """
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
        """
        Find existing OIDC user or create new one.

        Flow:
        1. Check if oidc_subject exists -> return existing user
        2. Extract username from OIDC claim
        3. Check if username exists -> return error (conflict - requires manual linking)
        4. Auto-create user if enabled
        5. Set is_admin from OIDC groups

        Args:
            db: Database session
            userinfo: User info from OIDC provider
            config: OIDC configuration
            provider_name: Provider name (e.g., "keycloak")

        Returns:
            Tuple of (User, error_message)
            - (user, None) if successful
            - (None, error) if failed
        """
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
        """
        Build OIDC authorization URL for redirect.

        Args:
            authorization_endpoint: OIDC authorization endpoint URL
            client_id: OAuth client ID
            redirect_uri: Callback URL
            scopes: List of OAuth scopes (e.g., ["openid", "profile", "email"])
            state: CSRF protection state token
            code_challenge: PKCE code_challenge (None if not using PKCE)

        Returns:
            Complete authorization URL
        """
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
        """
        Clean up expired OIDC auth states.

        Should be called periodically (e.g., hourly) to prevent table bloat.

        Args:
            db: Database session

        Returns:
            Number of states deleted
        """
        now = datetime.now(timezone.utc)
        expired_states = db.query(OIDCAuthState).filter(OIDCAuthState.expires_at < now).all()

        count = len(expired_states)
        for state in expired_states:
            db.delete(state)

        db.commit()
        return count
