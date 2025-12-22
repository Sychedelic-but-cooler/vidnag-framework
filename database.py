from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Enum, Boolean, event, ForeignKey, or_, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator
from contextlib import contextmanager
from datetime import datetime, timezone
import enum
import uuid
from config import DATABASE_FILE


class UTCDateTime(TypeDecorator):
    # Custom SQLAlchemy type that ensures all datetime values are timezone-aware (UTC).
    # This fixes an issue where frontend Javascript interprets timestamps as local time instead of UTC.
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        # Convert datetime to UTC before saving to database
        if value is not None:
            if value.tzinfo is None:
                # If naive datetime, assume it's UTC
                value = value.replace(tzinfo=timezone.utc)
            else:
                # Convert to UTC if it has a different timezone
                value = value.astimezone(timezone.utc)
            # Return as naive datetime for SQLite (it doesn't support timezone storage)
            return value.replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        # Attach UTC timezone when loading from database
        if value is not None:
            # SQLite returns naive datetime - attach UTC timezone
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        return value

# SQLite database file location (uses central config)
DATABASE_URL = f"sqlite:///./{DATABASE_FILE}"

# Create the database engine with SQLite-specific configuration
# check_same_thread=False allows multiple threads to share the connection
# StaticPool keeps a single connection for better SQLite performance
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

# Enable WAL mode for better concurrency, readers don't block writers
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

# Session factory for creating database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all database models
Base = declarative_base()


class DownloadStatus(str, enum.Enum):
    # Possible states for a download job
    QUEUED = "queued"           # Waiting in queue to start
    DOWNLOADING = "downloading" # Currently downloading
    COMPLETED = "completed"     # Successfully finished
    FAILED = "failed"           # Failed with error


class ConversionStatus(str, enum.Enum):
    # Possible states for a tool conversion job
    QUEUED = "queued"           # Waiting in queue to start
    CONVERTING = "converting"   # Currently converting
    COMPLETED = "completed"     # Successfully finished
    FAILED = "failed"           # Failed with error


class Download(Base):
    # Database model for tracking video downloads. Stores everything about a download
    __tablename__ = "downloads"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String, nullable=False)
    status = Column(Enum(DownloadStatus), default=DownloadStatus.QUEUED, nullable=False)
    progress = Column(Float, default=0.0)

    # User-facing filename for display purposes
    filename = Column(String, nullable=True)

    # Internal UUID-based filename stored on disk - isolates file operations from user-generated names
    internal_filename = Column(String, nullable=True)

    thumbnail = Column(String, nullable=True)

    # Internal UUID-based thumbnail filename stored on disk
    internal_thumbnail = Column(String, nullable=True)

    file_size = Column(Integer, nullable=True)
    error_message = Column(String, nullable=True)
    cookies_file = Column(String, nullable=True)

    # User ownership and visibility
    user_id = Column(String, ForeignKey('users.id'), nullable=True, index=True)
    is_public = Column(Boolean, default=True, nullable=False, index=True)

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False) # When the job was added to queue
    started_at = Column(UTCDateTime, nullable=True) # When the job was moved from queued to downloading
    completed_at = Column(UTCDateTime, nullable=True) # When the download finished (success or failure)


class ToolConversion(Base):
    # Database model for tracking tool conversion status and settings.
    __tablename__ = "tool_conversions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_download_id = Column(String, nullable=False)
    tool_type = Column(String, nullable=False)
    status = Column(Enum(ConversionStatus), default=ConversionStatus.QUEUED, nullable=False)
    progress = Column(Float, default=0.0)

    # User-facing output filename for display purposes
    output_filename = Column(String, nullable=True)

    # Internal UUID-based output filename stored on disk
    internal_output_filename = Column(String, nullable=True)

    output_size = Column(Integer, nullable=True)

    # Audio quality for MP3 conversions (bitrate in kbps: 96, 128, 192, etc.)
    audio_quality = Column(Integer, nullable=True)

    error_message = Column(String, nullable=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(UTCDateTime, nullable=True)


class User(Base):
    # Database model for user accounts. Stores user credentials and authentication settings.
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=True)  # Nullable for OIDC-only users
    is_disabled = Column(Boolean, default=False, nullable=False, index=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    last_login = Column(UTCDateTime, nullable=True) # A future system could use this for disabling inactive accounts
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # OIDC/OAuth fields
    oidc_provider = Column(String, nullable=True)  # Provider Name, where did the account come from
    oidc_subject = Column(String, nullable=True, unique=True, index=True)  # OIDC 'sub' claim (unique identifier)
    oidc_email = Column(String, nullable=True)  # Email from OIDC provider
    oidc_linked_at = Column(UTCDateTime, nullable=True)  # When OIDC was linked to this account
    admin_override = Column(Boolean, default=False, nullable=False)  # True if admin manually changed is_admin (prevents OIDC group sync)


class OIDCAuthState(Base):
    # Temporary store for OIDC state tokens and PKCE verifiers for OAuth flow. States automatically expire after 10 minutes.
    __tablename__ = "oidc_auth_state"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    state = Column(String, unique=True, nullable=False, index=True)  # OAuth 'state' parameter (CSRF protection)
    code_verifier = Column(String, nullable=False)  # PKCE code_verifier
    redirect_uri = Column(String, nullable=False)  # Original redirect_uri used in auth request
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    expires_at = Column(UTCDateTime, nullable=False)  # States expire after 10 minutes
    ip_address = Column(String, nullable=False)  # IP that initiated login (security check)


class UserLoginHistory(Base):
    # Database model for tracking login attempts, used for IP tracking and suspicious activity detection.
    __tablename__ = "user_login_history"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True, index=True)  # Nullable in case user doesn't exist
    ip_address = Column(String, nullable=False)
    login_time = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)


class JWTKey(Base):
    # Database model for JWT signing keys. Supports key rotation for enhanced security.
    __tablename__ = "jwt_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_value = Column(String, nullable=False)  # Base64-encoded secret key
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    expires_at = Column(UTCDateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    revoked_at = Column(UTCDateTime, nullable=True)


class AuthAuditLog(Base):
    # Database model for authentication audit trail. Records all authentication-related events for security monitoring.
    # Uses database instead of file logging for long term storage and easier querying.
    __tablename__ = "auth_audit_log"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String, nullable=False, index=True)  # login_success, login_failed, logout, etc.
    user_id = Column(String, nullable=True, index=True)  # Nullable if user lookup failed
    username = Column(String, nullable=True)
    ip_address = Column(String, nullable=False)
    details = Column(String, nullable=True)  # JSON string with additional context
    timestamp = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class FailedLoginAttempt(Base):
    # Database model for tracking failed login attempts. Used for account lockout after too many failures.
    __tablename__ = "failed_login_attempts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    attempt_time = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    lockout_until = Column(UTCDateTime, nullable=True)  # Set when threshold reached


class SystemSettings(Base):
    # System-level settings and flags stored in the database. Used for tracking system state like first-time setup completion.
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, default=1)  # Always 1
    first_time_setup = Column(Boolean, default=True, nullable=False)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class ShareToken(Base):
    # Database model for shareable video links. Only public videos can be shared.
    __tablename__ = "share_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    token = Column(String, unique=True, nullable=False, index=True)  # Random string for URL
    download_id = Column(String, ForeignKey('downloads.id'), nullable=False, index=True)
    created_by = Column(String, ForeignKey('users.id'), nullable=True)  # User who created the share
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    view_count = Column(Integer, default=0, nullable=False)  # Track how many times it's been viewed
    last_viewed_at = Column(UTCDateTime, nullable=True)  # Last time someone viewed this share


def init_db():
    # Initialize the database schema. Creates all tables defined by the above models if they don't exist yet.
    # This will not recreate existing tables or modify existing schemas.
    Base.metadata.create_all(bind=engine)

    # Ensure SystemSettings singleton exists
    with get_db() as db:
        settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()
        if not settings:
            settings = SystemSettings(id=1, first_time_setup=True)
            db.add(settings)
            db.commit()


@contextmanager
def get_db():
    # Context manager for database sessions with transaction handling.
    # Commits on success, rolls back on errors, always closes the session.
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_session():
    # FastAPI dependency injection for database sessions. Does not auto-commit - caller is responsible for commits.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
