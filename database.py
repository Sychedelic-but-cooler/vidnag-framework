from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Enum, Boolean, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator
from contextlib import contextmanager
from datetime import datetime, timezone
import enum
import uuid


class UTCDateTime(TypeDecorator):
    """
    Custom SQLAlchemy type that ensures all datetime values are timezone-aware (UTC).

    SQLite stores datetime as strings without timezone info. This type ensures:
    - When saving: datetime is converted to UTC
    - When loading: naive datetime from DB is assumed to be UTC and made timezone-aware

    This fixes the issue where frontend receives timestamps without timezone info,
    causing JavaScript to interpret them as local time instead of UTC.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert datetime to UTC before saving to database"""
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
        """Attach UTC timezone when loading from database"""
        if value is not None:
            # SQLite returns naive datetime - attach UTC timezone
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        return value

# SQLite database file location
DATABASE_URL = "sqlite:///./downloads.db"

# Create the database engine with SQLite-specific configuration
# check_same_thread=False allows multiple threads to share the connection
# StaticPool keeps a single connection for better SQLite performance
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

# Enable WAL mode for better concurrency (readers don't block writers)
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Set SQLite pragmas: WAL mode for concurrency, NORMAL synchronous for performance."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

# Session factory for creating database sessions
# autocommit=False means we manually control transaction commits
# autoflush=False prevents automatic flushing before queries
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all database models
Base = declarative_base()


class DownloadStatus(str, enum.Enum):
    """Possible states for a download job"""
    QUEUED = "queued"           # Waiting in queue to start
    DOWNLOADING = "downloading" # Currently downloading
    COMPLETED = "completed"     # Successfully finished
    FAILED = "failed"           # Failed with error


class ConversionStatus(str, enum.Enum):
    """Possible states for a tool conversion job"""
    QUEUED = "queued"           # Waiting in queue to start
    CONVERTING = "converting"   # Currently converting
    COMPLETED = "completed"     # Successfully finished
    FAILED = "failed"           # Failed with error


class Download(Base):
    """
    Database model for tracking video downloads.
    Stores everything about a download from URL to final file location.
    """
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
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(UTCDateTime, nullable=True)  # When download actually started (not when queued)
    completed_at = Column(UTCDateTime, nullable=True)


class ToolConversion(Base):
    """
    Database model for tracking tool conversion jobs (e.g., video to MP3).
    Links to source video and tracks conversion progress.
    """
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
    """
    Database model for user accounts.
    Stores user credentials and authentication settings.
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_disabled = Column(Boolean, default=False, nullable=False, index=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    last_login = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class UserLoginHistory(Base):
    """
    Database model for tracking all login attempts (successful and failed).
    Used for IP tracking and suspicious activity detection.
    """
    __tablename__ = "user_login_history"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True, index=True)  # Nullable in case user doesn't exist
    ip_address = Column(String, nullable=False)
    login_time = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)


class JWTKey(Base):
    """
    Database model for JWT signing keys.
    Supports key rotation for enhanced security.
    """
    __tablename__ = "jwt_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_value = Column(String, nullable=False)  # Base64-encoded secret key
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    expires_at = Column(UTCDateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    revoked_at = Column(UTCDateTime, nullable=True)


class AuthAuditLog(Base):
    """
    Database model for authentication audit trail.
    Records all authentication-related events for security monitoring.
    """
    __tablename__ = "auth_audit_log"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String, nullable=False, index=True)  # login_success, login_failed, logout, etc.
    user_id = Column(String, nullable=True, index=True)  # Nullable if user lookup failed
    username = Column(String, nullable=True)
    ip_address = Column(String, nullable=False)
    details = Column(String, nullable=True)  # JSON string with additional context
    timestamp = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class FailedLoginAttempt(Base):
    """
    Database model for tracking failed login attempts.
    Used for account lockout after too many failures.
    """
    __tablename__ = "failed_login_attempts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    attempt_time = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    lockout_until = Column(UTCDateTime, nullable=True)  # Set when threshold reached


class SystemSettings(Base):
    """
    System-level settings and flags stored in the database.

    Used for tracking system state like first-time setup completion.
    This table should only ever have ONE row (singleton pattern).
    """
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, default=1)  # Always 1
    first_time_setup = Column(Boolean, default=True, nullable=False)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


def init_db():
    """
    Initialize the database schema.
    Creates all tables defined by our models if they don't exist yet.
    Safe to call multiple times - won't recreate existing tables.

    Also ensures SystemSettings singleton row exists with first_time_setup flag.
    """
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
    """
    Context manager for database sessions with automatic transaction handling.
    Commits on success, rolls back on errors, always closes the session.
    """
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
    """
    FastAPI dependency injection for database sessions.
    Does not auto-commit - caller is responsible for commits.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
