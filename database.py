from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from datetime import datetime, timezone
import enum
import uuid

# SQLite database file location
DATABASE_URL = "sqlite:///./downloads.db"

# Create the database engine with SQLite-specific configuration
# check_same_thread=False allows multiple threads to share the connection
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

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


class Download(Base):
    """
    Database model for tracking video downloads.
    Stores everything about a download from URL to final file location.
    """
    __tablename__ = "downloads"

    # Unique identifier generated automatically using UUID4
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    # Original video URL provided by user
    url = Column(String, nullable=False)

    # Current status of the download (queued, downloading, completed, failed)
    status = Column(Enum(DownloadStatus), default=DownloadStatus.QUEUED, nullable=False)

    # Download progress as percentage (0.0 to 100.0)
    progress = Column(Float, default=0.0)

    # User-facing filename for display purposes (original/sanitized name from video)
    filename = Column(String, nullable=True)

    # Internal UUID-based filename stored on disk (e.g., "550e8400-e29b-41d4-a716-446655440000.mp4")
    # This isolates file operations from user-generated names, eliminating sanitization concerns
    internal_filename = Column(String, nullable=True)

    # User-facing thumbnail filename for display
    thumbnail = Column(String, nullable=True)

    # Internal UUID-based thumbnail filename stored on disk
    internal_thumbnail = Column(String, nullable=True)

    # Size of the downloaded file in bytes
    file_size = Column(Integer, nullable=True)

    # Error message if download failed (null for successful downloads)
    error_message = Column(String, nullable=True)

    # Optional cookies file used for this download (for authenticated content)
    cookies_file = Column(String, nullable=True)

    # Timestamp when download was created (always in UTC timezone)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Timestamp when download completed (null until finished)
    completed_at = Column(DateTime, nullable=True)


def init_db():
    """
    Initialize the database schema.
    Creates all tables defined by our models if they don't exist yet.
    Safe to call multiple times - won't recreate existing tables.
    """
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db():
    """
    Context manager for database sessions with automatic transaction handling.
    Use this in regular Python code (not FastAPI endpoints).

    Usage:
        with get_db() as db:
            downloads = db.query(Download).all()

    Automatically commits on success and rolls back on errors.
    Always closes the session when done.
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
    Generator for FastAPI dependency injection.
    Use this with FastAPI's Depends() to get a database session in endpoints.

    Usage:
        @app.get("/api/downloads")
        def get_downloads(db: Session = Depends(get_db_session)):
            return db.query(Download).all()

    Note: Does not auto-commit - caller is responsible for commits.
    Always closes the session when the request is done.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
