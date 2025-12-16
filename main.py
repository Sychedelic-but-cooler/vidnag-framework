"""
Vidnag Framework - Main Application
A FastAPI-based web application for downloading videos using yt-dlp.
Provides a web interface for managing video downloads with queue management,
file browsing, and comprehensive logging.
"""

# FastAPI and web framework imports
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request, UploadFile, File, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Data validation and database
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

# Date and time handling (always use timezone-aware datetimes)
from datetime import datetime, timedelta, timezone

# Type hints for better code clarity
from typing import Optional, List, Dict, Any
from pathlib import Path

# Data structures and utilities
from collections import deque
from contextlib import asynccontextmanager
import asyncio
import subprocess
import os
import shutil
import json
import re
import logging
import zipfile
import io
import unicodedata
import time
import uuid
import platform

# Application modules
from database import init_db, get_db_session, Download, DownloadStatus, ToolConversion, ConversionStatus, get_db, User, UserLoginHistory, FailedLoginAttempt
from settings import settings
from admin_settings import get_admin_settings
from security import (
    is_safe_path,
    validate_filename,
    validate_url,
    sanitize_url_for_logging,
    validate_cookie_filename,
    validate_settings_update
)
from auth import PasswordService, JWTService, AuthService, AuditLogService

# Application version (Major.Minor.Bugfix-ReleaseMonth)
APP_VERSION = "2.0.0-12"

def cleanup_old_logs():
    """
    Remove log files older than 3 days on application startup.
    Works in conjunction with TimedRotatingFileHandler to manage disk space.
    Searches the logs directory and removes any file older than 3 days.
    """
    try:
        logs_dir = "logs"
        if not os.path.exists(logs_dir):
            return

        # Get current time for age calculations
        now = time.time()
        three_days = 3 * 24 * 60 * 60  # Convert 3 days to seconds
        removed_count = 0

        # Scan all files in the logs directory
        for filename in os.listdir(logs_dir):
            filepath = os.path.join(logs_dir, filename)
            if os.path.isfile(filepath):
                # Calculate how old the file is
                file_age = now - os.path.getmtime(filepath)
                if file_age > three_days:
                    try:
                        os.remove(filepath)
                        logger.info(f"Removed old log file: {filename} (age: {file_age / 86400:.1f} days)")
                        removed_count += 1
                    except Exception as e:
                        logger.error(f"Failed to remove log file {filename}: {e}")

        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} old log file(s)")
    except Exception as e:
        logger.error(f"Error during log cleanup: {e}")


def set_directory_permissions():
    """
    Set file permissions: downloads/logs (755), cookies (700), db/config (600).
    Ensures proper security on Linux/macOS (no-op on Windows).
    """
    try:
        import stat

        # Public directories: 755 (owner rwx, others rx)
        for dir_path in ["downloads", "logs", "assets", "backups"]:
            if os.path.exists(dir_path):
                try:
                    os.chmod(dir_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                    logger.debug(f"Set permissions 755 on {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {dir_path}: {e}")

        # Private directories: 700 (owner rwx only)
        for dir_path in ["cookies"]:
            if os.path.exists(dir_path):
                try:
                    os.chmod(dir_path, stat.S_IRWXU)
                    logger.debug(f"Set permissions 700 on {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {dir_path}: {e}")

        # Private files: 600 (owner rw only)
        for file_path in ["data.db", "admin_settings.json"]:
            if os.path.exists(file_path):
                try:
                    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
                    logger.debug(f"Set permissions 600 on {file_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {file_path}: {e}")

        logger.info("Directory permissions set successfully")

    except Exception as e:
        logger.error(f"Error setting directory permissions: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan event handler.
    Runs initialization code on startup and cleanup code on shutdown.
    FastAPI calls this when the application starts and stops.
    """
    # Startup sequence - runs when the application starts
    init_db()  # Create database tables if they don't exist

    # Create all required directories if they don't exist
    os.makedirs("downloads", exist_ok=True)  # Video download storage
    os.makedirs("cookies", exist_ok=True)    # Cookie files for authenticated downloads
    os.makedirs("logs", exist_ok=True)       # Application logs
    os.makedirs("backups", exist_ok=True)    # Database backups (future use)

    # Set proper file permissions on critical directories
    set_directory_permissions()

    # Load and validate admin settings from admin_settings.json
    # This must happen before any middleware or endpoints are initialized
    try:
        admin_settings = get_admin_settings()
        await emit_log("INFO", "System", "Admin settings loaded and validated successfully")
    except ValueError as e:
        await emit_log("ERROR", "System", f"Failed to load admin settings: {e}")
        raise

    # Clean up old log files to prevent disk space issues
    cleanup_old_logs()

    # Start the download queue processor
    download_queue.start_processing()

    # Restore pending downloads from database
    await download_queue.restore_from_database()

    # Start the conversion queue processor
    conversion_queue.start_processing()

    # Restore pending conversions from database
    await conversion_queue.restore_from_database()

    # Detect hardware and populate cache at startup
    global hardware_acceleration, hardware_info_cache
    hardware_info_cache = await collect_hardware_info()
    hardware_acceleration = hardware_info_cache["acceleration"]

    if hardware_acceleration["detected_encoders"]:
        await emit_log("INFO", "System", f"Hardware acceleration detected: {', '.join(hardware_acceleration['detected_encoders'])}")
    else:
        await emit_log("INFO", "System", "No hardware acceleration detected - using CPU encoding")

    # Log startup information for diagnostics
    await emit_log("INFO", "System", "Application started successfully")
    await emit_log("INFO", "System", f"Vidnag Framework version: {APP_VERSION}")
    await emit_log("INFO", "System", f"Download queue started (max concurrent: {settings.get('max_concurrent_downloads', 2)})")
    await emit_log("INFO", "System", f"Conversion queue started (max concurrent: {settings.get('max_concurrent_conversions', 1)})")
    await emit_log("INFO", "System", f"Python version: {os.sys.version}")
    await emit_log("INFO", "System", f"Working directory: {os.getcwd()}")
    await emit_log("INFO", "System", "Log files: rotated daily, kept for 3 days in logs/ directory")

    # Yield control back to FastAPI - application runs normally from here
    yield

    # Shutdown sequence - runs when the application stops
    # Currently no cleanup needed, but this is where it would go
    pass

# Create the FastAPI application instance with our lifespan handler
app = FastAPI(title="Vidnag Framework API", lifespan=lifespan)

# Configure Python's built-in logging system
# This sets up console logging for debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Set up file-based logging for application logs
# This creates persistent log files that rotate daily
os.makedirs("logs", exist_ok=True)

from logging.handlers import TimedRotatingFileHandler

# Create a rotating file handler
# - Rotates logs at midnight each day
# - Keeps 3 days of backup logs (backupCount=3)
# - Automatically deletes logs older than 3 days
file_handler = TimedRotatingFileHandler(
    filename="logs/application.log",
    when="midnight",         # Rotate at midnight
    interval=1,              # Every 1 day
    backupCount=3,           # Keep 3 days of logs
    encoding="utf-8"
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

# Create a separate logger for application logs
# This prevents application logs from interfering with FastAPI's logs
app_file_logger = logging.getLogger("app_logs")
app_file_logger.setLevel(logging.INFO)
app_file_logger.addHandler(file_handler)
app_file_logger.propagate = False  # Don't send logs to parent logger

# Configure Cross-Origin Resource Sharing (CORS)
# This allows the frontend to make API requests from different domains
# Necessary when the frontend is served from a different origin than the API
# Configuration is loaded from admin_settings.json
admin_settings_instance = get_admin_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=admin_settings_instance.cors.allowed_origins,
    allow_credentials=admin_settings_instance.cors.allow_credentials,
    allow_methods=admin_settings_instance.cors.allowed_methods,
    allow_headers=admin_settings_instance.cors.allowed_headers,
)

# Proxy Headers Middleware
# Configuration loaded from admin_settings.json
# Supports flexible proxy architectures (Nginx, Caddy, etc.)
@app.middleware("http")
async def trust_proxy_headers(request: Request, call_next):
    """
    Extract client IP from proxy headers based on admin configuration.
    
    Supports multiple proxy types by reading trusted proxy configuration
    from admin_settings.json. This enables deployment flexibility across
    different reverse proxy architectures.
    """
    admin_settings = get_admin_settings()
    
    # If proxy support is disabled, use direct connection IP only
    if not admin_settings.proxy.enabled:
        client_ip = request.client.host if request.client else "unknown"
        request.state.client_ip = client_ip
        return await call_next(request)
    
    # Extract proxy headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = request.headers.get("X-Real-IP")
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    forwarded_host = request.headers.get("X-Forwarded-Host")
    direct_ip = request.client.host if request.client else None

    # Determine client IP based on trusted proxy configuration
    client_ip = direct_ip or "unknown"
    
    # Only trust proxy headers if they come from a trusted proxy
    from ipaddress import ip_address as parse_ip, ip_network, AddressValueError
    
    try:
        if direct_ip and admin_settings.proxy.trusted_proxies:
            # Check if direct connection is from a trusted proxy
            is_trusted = False
            try:
                direct_ip_obj = parse_ip(direct_ip)
                for trusted in admin_settings.proxy.trusted_proxies:
                    if "/" in trusted:
                        if direct_ip_obj in ip_network(trusted, strict=False):
                            is_trusted = True
                            break
                    else:
                        if direct_ip_obj == parse_ip(trusted):
                            is_trusted = True
                            break
            except (AddressValueError, ValueError):
                pass
            
            if is_trusted:
                # Connection is from trusted proxy, extract real IP
                if admin_settings.proxy.trust_x_forwarded_for and forwarded_for:
                    # X-Forwarded-For may contain multiple IPs (client, proxy1, proxy2, ...)
                    # Take the first one (leftmost) which is the original client
                    client_ip = forwarded_for.split(',')[0].strip()
                elif admin_settings.proxy.trust_x_real_ip and real_ip:
                    client_ip = real_ip
    except Exception:
        # If IP parsing fails, fall back to safe behavior
        pass

    # Validate IP format if enabled
    if admin_settings.security.validate_ip_format:
        from security import validate_ip_address
        is_valid, _ = validate_ip_address(client_ip)
        if not is_valid and client_ip != "unknown":
            client_ip = "unknown"

    # Store the resolved IP in request state for use by endpoints
    request.state.client_ip = client_ip

    # Debug logging for proxy setup validation
    # Controlled by admin_settings to prevent header leakage in production
    if not hasattr(trust_proxy_headers, 'logged_count'):
        trust_proxy_headers.logged_count = 0

    if admin_settings.security.debug_proxy_headers and trust_proxy_headers.logged_count < 5:
        logger.info(f"Proxy Headers Debug - Direct IP: {direct_ip}")
        logger.info(f"  X-Forwarded-For: {forwarded_for}")
        logger.info(f"  X-Real-IP: {real_ip}")
        logger.info(f"  X-Forwarded-Proto: {forwarded_proto}")
        logger.info(f"  X-Forwarded-Host: {forwarded_host}")
        logger.info(f"  Resolved Client IP: {client_ip}")
        trust_proxy_headers.logged_count += 1

    response = await call_next(request)
    return response


# Mount static files (HTML, CSS, JS) to be served by FastAPI
# Requests to /assets/* will serve files from the assets directory
app.mount("/assets", StaticFiles(directory="assets"), name="assets")

# WebSocket connections per download for real-time progress updates
active_connections: dict[str, list[WebSocket]] = {}
# WebSocket connections for real-time log streaming
log_websockets: list[WebSocket] = []

# WebSocket connection limits to prevent memory exhaustion
MAX_LOG_WEBSOCKET_CONNECTIONS = 100
WEBSOCKET_IDLE_TIMEOUT = 300  # 5 minutes in seconds - disconnect idle connections

# In-memory circular buffer for logs
# Stores last 1000 log entries for quick retrieval by the frontend
# maxlen=1000 means old logs are automatically dropped when buffer fills
log_buffer = deque(maxlen=1000)

# Global sequence counter for logs
# This never resets, unlike buffer index which wraps at 1000
# Allows frontend to track logs even after buffer wraparound
log_sequence = 0

# Rate limiting data structures
from collections import defaultdict
from datetime import datetime

# Store request timestamps per IP address for rate limiting
# Each IP gets a deque of recent request timestamps
# Configuration (max capacity, cleanup) comes from admin_settings
rate_limit_store: dict[str, deque] = {}
last_cleanup_time = 0


def check_rate_limit(client_ip: str) -> bool:
    """
    Check if a client has exceeded the rate limit using a sliding window.
    Prevents abuse by limiting requests per IP address.
    
    Rate limit parameters are loaded from admin_settings.json:
    - max_requests_per_window
    - window_seconds
    - max_tracked_ips (cleanup if exceeded)
    - cleanup_interval_seconds

    Args:
        client_ip: The client's IP address

    Returns:
        True if request is allowed, False if rate limited
    """
    global last_cleanup_time
    
    admin_settings = get_admin_settings()
    
    # If rate limiting is disabled, allow all requests
    if not admin_settings.rate_limit.enabled:
        return True
    
    now = datetime.now(timezone.utc).timestamp()
    window_seconds = admin_settings.rate_limit.window_seconds
    max_requests = admin_settings.rate_limit.max_requests_per_window
    
    # Cleanup old IPs periodically to prevent unbounded memory growth
    if now - last_cleanup_time > admin_settings.rate_limit.cleanup_interval_seconds:
        _cleanup_rate_limit_store()
        last_cleanup_time = now
    
    # Limit number of tracked IPs to prevent memory exhaustion
    if len(rate_limit_store) >= admin_settings.rate_limit.max_tracked_ips:
        _cleanup_rate_limit_store()
    
    # Get or create request deque for this IP
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = deque(maxlen=max_requests)
    
    requests = rate_limit_store[client_ip]

    # Remove old request timestamps outside the current time window
    # This implements a sliding window rate limit
    cutoff = now - window_seconds
    while requests and requests[0] < cutoff:
        requests.popleft()

    # Check if client has exceeded the limit
    if len(requests) >= max_requests:
        return False

    # Add current request timestamp and allow the request
    requests.append(now)
    return True


def _cleanup_rate_limit_store():
    """
    Remove IPs with no recent activity from the rate limit store.
    
    Prevents unbounded memory growth in long-running applications
    by removing inactive IPs. Triggered by time interval or IP count.
    
    Uses two-tier cleanup:
    - First: Remove IPs inactive for 30 minutes
    - If still over 5000 IPs: Aggressively remove IPs inactive for 5 minutes
    """
    global rate_limit_store
    now = datetime.now(timezone.utc).timestamp()
    
    # First pass: Remove IPs with no requests in the last 30 minutes
    cutoff_time = now - 1800  # 30 minutes
    expired_ips = [
        ip for ip, reqs in rate_limit_store.items()
        if reqs and reqs[-1] < cutoff_time
    ]
    
    for ip in expired_ips:
        del rate_limit_store[ip]
    
    removed_count = len(expired_ips)
    if removed_count > 0:
        logger.debug(f"Rate limit cleanup: removed {removed_count} inactive IPs (30+ min)")
    
    # Second pass: If still too many IPs, do aggressive cleanup (5 minutes)
    if len(rate_limit_store) > 5000:
        aggressive_cutoff = now - 300  # 5 minutes
        expired_ips = [
            ip for ip, reqs in rate_limit_store.items()
            if reqs and reqs[-1] < aggressive_cutoff
        ]
        
        for ip in expired_ips:
            del rate_limit_store[ip]
        
        if expired_ips:
            logger.warning(f"Rate limit aggressive cleanup: removed {len(expired_ips)} IPs (5+ min) - store was at {len(rate_limit_store) + len(expired_ips)} entries")


# Download timeout configuration (in seconds)
# Prevent hung downloads from consuming resources indefinitely
# Most video downloads complete within this timeframe
DOWNLOAD_TIMEOUT_SECONDS = 3600  # 1 hour


async def download_with_timeout(download_id: str, url: str, cookies_file: Optional[str] = None):
    """
    Wrapper that adds timeout to download operations.
    Prevents hung downloads from consuming resources indefinitely.

    If timeout is exceeded, the download is forcefully terminated.
    """
    try:
        await asyncio.wait_for(
            YtdlpService.download_video(download_id, url, cookies_file),
            timeout=DOWNLOAD_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        # Mark download as failed with timeout message
        timeout_minutes = DOWNLOAD_TIMEOUT_SECONDS / 60
        error_msg = f"Download exceeded timeout limit ({timeout_minutes:.0f} minutes) and was terminated"

        await emit_log("ERROR", "Download", error_msg, download_id)

        # Update database status to failed
        with get_db() as db:
            DatabaseService.mark_failed(db, download_id, error_msg)

        # Broadcast failure to WebSocket clients
        await YtdlpService.broadcast_progress(download_id, {
            "type": "failed",
            "status": "failed",
            "error": error_msg
        })

        # Re-raise to let the wrapper handle cleanup
        raise


# Download Queue Manager
class DownloadQueueManager:
    """
    Manages the download queue with concurrent download limiting.
    Ensures only a limited number of downloads run simultaneously
    to prevent resource exhaustion.
    """

    def __init__(self):
        # AsyncIO queue for pending downloads
        self.queue: asyncio.Queue = asyncio.Queue()

        # Set of currently running download IDs
        self.active_downloads: set = set()

        # Background task that processes the queue
        self.processing_task: Optional[asyncio.Task] = None

    async def add_to_queue(self, download_id: str, url: str, cookies_file: Optional[str] = None):
        """
        Add a download to the queue.
        Downloads are processed in FIFO order when capacity is available.
        """
        await self.queue.put((download_id, url, cookies_file))
        await emit_log("INFO", "Queue", f"Download {download_id[:8]}... added to queue. Queue size: {self.queue.qsize()}", download_id)

    async def process_queue(self):
        """
        Continuously process downloads from the queue.
        Respects max_concurrent_downloads setting and disk space limits.
        This runs as a background task for the entire application lifetime.
        """
        while True:
            try:
                # Wait for a download to be added to the queue (blocking)
                download_id, url, cookies_file = await self.queue.get()

                # Wait until we have capacity for another download
                # This enforces the max_concurrent_downloads limit
                max_concurrent = settings.get("max_concurrent_downloads", 2)
                while len(self.active_downloads) >= max_concurrent:
                    await asyncio.sleep(1)

                # Check if we have enough free disk space before starting
                # This prevents filling up the disk completely
                free_space_mb = shutil.disk_usage("downloads").free / (1024 * 1024)
                min_space = settings.get("min_disk_space_mb", 1000)

                if free_space_mb < min_space:
                    # Not enough space - mark download as failed and skip it
                    await emit_log("WARNING", "Queue", f"Insufficient disk space ({free_space_mb:.1f}MB free, {min_space}MB required). Pausing download.", download_id)
                    with get_db() as db:
                        DatabaseService.mark_failed(db, download_id, f"Insufficient disk space. Need {min_space}MB free, only {free_space_mb:.1f}MB available.")
                    self.queue.task_done()
                    continue

                # Start the download
                self.active_downloads.add(download_id)
                await emit_log("INFO", "Queue", f"Starting download {download_id[:8]}... ({len(self.active_downloads)}/{max_concurrent} active)", download_id)

                # Create a new async task for the download (runs in background)
                # This allows the queue processor to continue handling other downloads
                # Wrapped with timeout to prevent hung downloads
                asyncio.create_task(self._download_wrapper(download_id, url, cookies_file))

                # Mark this queue item as processed
                self.queue.task_done()

            except Exception as e:
                # Log queue processing errors and continue
                # Don't let a single error crash the entire queue system
                await emit_log("ERROR", "Queue", f"Queue processing error: {str(e)}")
                await asyncio.sleep(1)

    async def _download_wrapper(self, download_id: str, url: str, cookies_file: Optional[str]):
        """
        Wrapper around the actual download function.
        Ensures the download is always removed from active_downloads
        even if the download fails or throws an exception.
        Includes timeout protection to prevent hung downloads.
        """
        try:
            await download_with_timeout(download_id, url, cookies_file)
        except asyncio.TimeoutError:
            # Already logged in download_with_timeout
            pass
        except Exception as e:
            # Catch any other exceptions
            logger.error(f"Download wrapper error for {download_id}: {e}")
        finally:
            # Always remove from active downloads, even if download failed
            self.active_downloads.discard(download_id)
            await emit_log("INFO", "Queue", f"Download {download_id[:8]}... finished. Active downloads: {len(self.active_downloads)}", download_id)

    async def restore_from_database(self):
        """
        Restore queued and downloading items from database on startup.
        This allows recovery from application crashes or restarts.
        """
        try:
            with get_db() as db:
                # Find all downloads that were queued or downloading when app stopped
                pending_downloads = db.query(Download).filter(
                    Download.status.in_([DownloadStatus.QUEUED, DownloadStatus.DOWNLOADING])
                ).order_by(Download.created_at).all()

                if pending_downloads:
                    await emit_log("INFO", "Queue",
                                 f"Restoring {len(pending_downloads)} pending download(s) from database")

                    for download in pending_downloads:
                        # Reset downloading status back to queued
                        if download.status == DownloadStatus.DOWNLOADING:
                            download.status = DownloadStatus.QUEUED
                            download.progress = 0.0
                            db.commit()

                        # Re-add to queue
                        await self.add_to_queue(download.id, download.url, download.cookies_file)

                    await emit_log("INFO", "Queue", f"Queue restored with {len(pending_downloads)} download(s)")
                else:
                    await emit_log("INFO", "Queue", "No pending downloads to restore")

        except Exception as e:
            logger.error(f"Failed to restore queue from database: {e}")
            await emit_log("ERROR", "Queue", f"Failed to restore queue: {str(e)}")

    def start_processing(self):
        """
        Start the background queue processor task.
        Called once during application startup.
        """
        if self.processing_task is None or self.processing_task.done():
            self.processing_task = asyncio.create_task(self.process_queue())

# Global queue manager instance used throughout the application
download_queue = DownloadQueueManager()


# Conversion Queue Manager
class ConversionQueueManager:
    """
    Manages the conversion queue for both MP3 conversions and video transforms.
    Ensures only a limited number of conversions run simultaneously
    to prevent resource exhaustion.
    Both job types are processed in FIFO order.
    """

    def __init__(self):
        # AsyncIO queue for pending conversions
        # Items: (job_type, conversion_id, job_params)
        self.queue: asyncio.Queue = asyncio.Queue()

        # Set of currently running conversion IDs
        self.active_conversions: set = set()

        # Background task that processes the queue
        self.processing_task: Optional[asyncio.Task] = None

    async def add_to_queue(self, job_type: str, conversion_id: str, **job_params):
        """
        Add a conversion job to the queue.
        Jobs are processed in FIFO order when capacity is available.

        Args:
            job_type: Either "mp3" or "video_transform"
            conversion_id: UUID of the conversion record
            **job_params: Job-specific parameters
                For mp3: source_path, output_path, bitrate
                For video_transform: download_id, source_path, transform_type, internal_filename
        """
        await self.queue.put((job_type, conversion_id, job_params))
        await emit_log("INFO", "ConversionQueue",
                     f"{job_type.upper()} job {conversion_id[:8]}... added to queue. Queue size: {self.queue.qsize()}",
                     conversion_id)

    async def process_queue(self):
        """
        Continuously process conversions from the queue.
        Handles both MP3 conversions and video transforms.
        Respects max_concurrent_conversions setting and disk space limits.
        This runs as a background task for the entire application lifetime.
        """
        while True:
            try:
                # Wait for a job to be added to the queue (blocking)
                job_type, conversion_id, job_params = await self.queue.get()

                # Wait until we have capacity for another conversion
                # Default to 1 concurrent conversion (CPU-intensive FFmpeg operations)
                max_concurrent = settings.get("max_concurrent_conversions", 1)
                while len(self.active_conversions) >= max_concurrent:
                    await asyncio.sleep(1)

                # Check if we have enough free disk space before starting
                free_space_mb = shutil.disk_usage("downloads").free / (1024 * 1024)
                min_space = settings.get("min_disk_space_mb", 1000)

                if free_space_mb < min_space:
                    # Not enough space - mark conversion as failed and skip it
                    await emit_log("WARNING", "ConversionQueue",
                                 f"Insufficient disk space ({free_space_mb:.1f}MB free, {min_space}MB required).",
                                 conversion_id)
                    with get_db() as db:
                        conversion = db.query(ToolConversion).filter(
                            ToolConversion.id == conversion_id
                        ).first()
                        if conversion:
                            conversion.status = ConversionStatus.FAILED
                            conversion.error_message = f"Insufficient disk space. Need {min_space}MB free, only {free_space_mb:.1f}MB available."
                            db.commit()
                    self.queue.task_done()
                    continue

                # Start the conversion
                self.active_conversions.add(conversion_id)
                await emit_log("INFO", "ConversionQueue",
                             f"Starting {job_type} job {conversion_id[:8]}... ({len(self.active_conversions)}/{max_concurrent} active)",
                             conversion_id)

                # Create a new async task for the conversion (runs in background)
                asyncio.create_task(self._job_wrapper(job_type, conversion_id, job_params))

                # Mark this queue item as processed
                self.queue.task_done()

            except Exception as e:
                # Log queue processing errors and continue
                await emit_log("ERROR", "ConversionQueue", f"Queue processing error: {str(e)}")
                await asyncio.sleep(1)

    async def _job_wrapper(self, job_type: str, conversion_id: str, job_params: dict):
        """
        Wrapper around the actual job processing function.
        Ensures the job is always removed from active_conversions
        even if the job fails or throws an exception.

        Args:
            job_type: Either "mp3" or "video_transform"
            conversion_id: UUID of the conversion record
            job_params: Dictionary of job-specific parameters
        """
        try:
            if job_type == "mp3":
                # MP3 conversion job
                await ToolConversionService.convert_video_to_mp3(
                    conversion_id,
                    job_params['source_path'],
                    job_params['output_path'],
                    job_params['bitrate']
                )
            elif job_type == "video_transform":
                # Video transformation job
                await VideoTransformService.process_transform(
                    conversion_id,
                    job_params['download_id'],
                    job_params['source_path'],
                    job_params['transform_type'],
                    job_params['internal_filename']
                )
            else:
                logger.error(f"Unknown job type: {job_type}")
                await emit_log("ERROR", "ConversionQueue", f"Unknown job type: {job_type}", conversion_id)
        except Exception as e:
            logger.error(f"Job wrapper error for {conversion_id}: {e}")
        finally:
            # Always remove from active conversions, even if job failed
            self.active_conversions.discard(conversion_id)
            await emit_log("INFO", "ConversionQueue",
                         f"{job_type.upper()} job {conversion_id[:8]}... finished. Active conversions: {len(self.active_conversions)}",
                         conversion_id)

    async def restore_from_database(self):
        """
        Restore queued and converting items from database on startup.
        This allows recovery from application crashes or restarts.
        """
        try:
            with get_db() as db:
                # Find all conversions that were queued or converting when app stopped
                pending_conversions = db.query(ToolConversion).filter(
                    ToolConversion.status.in_([ConversionStatus.QUEUED, ConversionStatus.CONVERTING])
                ).order_by(ToolConversion.created_at).all()

                if pending_conversions:
                    await emit_log("INFO", "ConversionQueue",
                                 f"Restoring {len(pending_conversions)} pending conversion(s) from database")

                    for conversion in pending_conversions:
                        # Reset converting status back to queued
                        if conversion.status == ConversionStatus.CONVERTING:
                            conversion.status = ConversionStatus.QUEUED
                            conversion.progress = 0.0
                            db.commit()

                        # Determine job type and parameters
                        if conversion.tool_type == "video_to_mp3":
                            # Find source download
                            source_download = db.query(Download).filter(
                                Download.id == conversion.source_download_id
                            ).first()

                            if source_download:
                                source_path = os.path.join("downloads", source_download.internal_filename)
                                output_path = os.path.join("downloads", conversion.internal_output_filename)

                                # Re-add to queue
                                await self.add_to_queue(
                                    job_type="mp3",
                                    conversion_id=conversion.id,
                                    source_path=source_path,
                                    output_path=output_path,
                                    bitrate=conversion.audio_quality or 192
                                )
                        elif conversion.tool_type.startswith("video_transform_"):
                            # Find source download
                            source_download = db.query(Download).filter(
                                Download.id == conversion.source_download_id
                            ).first()

                            if source_download:
                                source_path = os.path.join("downloads", source_download.internal_filename)
                                transform_type = conversion.tool_type.replace("video_transform_", "")

                                # Re-add to queue
                                await self.add_to_queue(
                                    job_type="video_transform",
                                    conversion_id=conversion.id,
                                    download_id=conversion.source_download_id,
                                    source_path=source_path,
                                    transform_type=transform_type,
                                    internal_filename=source_download.internal_filename
                                )

                    await emit_log("INFO", "ConversionQueue", f"Queue restored with {len(pending_conversions)} conversion(s)")
                else:
                    await emit_log("INFO", "ConversionQueue", "No pending conversions to restore")

        except Exception as e:
            logger.error(f"Failed to restore conversion queue from database: {e}")
            await emit_log("ERROR", "ConversionQueue", f"Failed to restore queue: {str(e)}")

    def start_processing(self):
        """
        Start the background queue processor task.
        Called once during application startup.
        """
        if self.processing_task is None or self.processing_task.done():
            self.processing_task = asyncio.create_task(self.process_queue())


# Global conversion queue manager instance
conversion_queue = ConversionQueueManager()

# Global hardware acceleration cache (detected at startup)
hardware_acceleration = {
    "nvenc": False,
    "amf": False,
    "qsv": False,
    "vaapi": False,
    "videotoolbox": False,
    "detected_encoders": []
}

# Global dictionary to track active conversion processes for cancellation
# Key: conversion_id, Value: (process, temp_output_path)
active_conversion_processes = {}

# Global cache for all hardware information (populated at startup)
# Clients fetch this once and cache in browser localStorage
hardware_info_cache = None


# Filename sanitization
def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to handle special characters, emojis, and problematic characters.
    This is critical for:
    - Filesystem compatibility across different operating systems
    - URL encoding when serving files for download
    - Preventing security issues with path traversal or special characters
    """
    if not filename:
        return filename

    # Split filename into base name and extension
    # We preserve the extension to maintain file type information
    base, ext = os.path.splitext(filename)

    # Normalize unicode characters
    # NFKD breaks down combined characters (like é) into base + accent
    # This helps with filesystem compatibility
    base = unicodedata.normalize('NFKD', base)

    # Replace filesystem-unsafe characters with underscores
    # These characters have special meaning in filesystems or cause issues
    unsafe_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\n', '\r', '\t']
    for char in unsafe_chars:
        base = base.replace(char, '_')

    # Remove control characters (invisible characters that can cause issues)
    # unicodedata.category(char)[0] returns the general category (C = control)
    base = ''.join(char for char in base if unicodedata.category(char)[0] != 'C')

    # Remove leading/trailing spaces and dots
    # Windows has issues with filenames starting/ending with these
    base = base.strip('. ')

    # Collapse multiple consecutive underscores or spaces into a single underscore
    # This prevents filenames like "video___title____here"
    base = re.sub(r'[_\s]+', '_', base)

    # Limit filename length to prevent filesystem issues
    # 255 is the limit on most filesystems, we use 200 to leave room for extensions
    max_length = 200
    if len(base.encode('utf-8')) > max_length:
        # Truncate at byte level to handle multi-byte UTF-8 characters correctly
        # errors='ignore' handles partial multi-byte characters at the cut point
        base = base.encode('utf-8')[:max_length].decode('utf-8', errors='ignore')
        base = base.rstrip('_')

    # Ensure we have at least some content for the filename
    # If everything was stripped out, use a default name
    if not base or base == '_':
        base = 'video'

    return base + ext


async def embed_thumbnail_in_video(video_path: str, thumbnail_path: str, download_id: Optional[str] = None) -> bool:
    """
    Embed a thumbnail image into a video file as cover art/poster frame.
    This allows the thumbnail to be displayed in file explorers and video players.

    Args:
        video_path: Path to the video file
        thumbnail_path: Path to the thumbnail image
        download_id: Optional download ID for logging

    Returns:
        True if successful, False otherwise
    """
    try:
        # Create a temporary output file path
        temp_output = f"{video_path}.temp.mp4"

        await emit_log("INFO", "Thumbnail", f"Embedding thumbnail into video: {os.path.basename(video_path)}", download_id)

        # Use ffmpeg to embed the thumbnail as cover art
        # -i video_path: input video
        # -i thumbnail_path: input thumbnail
        # -map 0: map all streams from first input (video)
        # -map 1: map the thumbnail as an additional stream
        # -c copy: copy all streams without re-encoding
        # -c:v:1 mjpeg: encode the thumbnail stream as MJPEG (required for cover art)
        # -disposition:v:1 attached_pic: mark the thumbnail as an attached picture/cover art
        embed_process = await asyncio.create_subprocess_exec(
            'ffmpeg',
            '-i', video_path,
            '-i', thumbnail_path,
            '-map', '0',
            '-map', '1',
            '-c', 'copy',
            '-c:v:1', 'mjpeg',
            '-disposition:v:1', 'attached_pic',
            temp_output,
            '-y',  # Overwrite output file if it exists
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Wait for the process to complete with a timeout
        stdout, stderr = await asyncio.wait_for(embed_process.communicate(), timeout=60)

        # Check if the process was successful
        if embed_process.returncode == 0 and os.path.exists(temp_output):
            # Replace the original video with the new one that has the embedded thumbnail
            os.replace(temp_output, video_path)
            await emit_log("SUCCESS", "Thumbnail", "Thumbnail successfully embedded into video", download_id)
            return True
        else:
            # Log the error but don't fail the download
            error_msg = stderr.decode().strip() if stderr else "Unknown error"
            await emit_log("WARNING", "Thumbnail", f"Failed to embed thumbnail: {error_msg}", download_id)
            # Clean up temp file if it exists
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except:
                    pass
            return False

    except asyncio.TimeoutError:
        await emit_log("WARNING", "Thumbnail", "Thumbnail embedding timed out after 60 seconds", download_id)
        # Clean up temp file if it exists
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except:
                pass
        return False
    except Exception as e:
        await emit_log("WARNING", "Thumbnail", f"Thumbnail embedding failed: {str(e)}", download_id)
        # Clean up temp file if it exists
        if 'temp_output' in locals() and os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except:
                pass
        return False


# Logging system
class LogEntry(BaseModel):
    """
    Data model for a single log entry.
    Used by Pydantic for validation and serialization.
    """
    sequence: int          # Ever-increasing sequence number
    timestamp: str         # ISO 8601 timestamp in UTC
    level: str            # INFO, WARNING, ERROR, etc.
    component: str        # Which part of the system generated the log
    message: str          # The actual log message
    download_id: Optional[str] = None  # Associated download ID (if applicable)


async def emit_log(level: str, component: str, message: str, download_id: Optional[str] = None):
    """
    Emit a log entry to all logging destinations.
    Logs go to:
    - In-memory buffer (for frontend display)
    - Log file (for persistence)
    This is the central logging function used throughout the application.
    """
    global log_sequence
    log_sequence += 1

    # Create a structured log entry
    log_entry = LogEntry(
        sequence=log_sequence,  # Unique, incrementing sequence number
        timestamp=datetime.now(timezone.utc).isoformat(),
        level=level,
        component=component,
        message=message,
        download_id=download_id
    )

    # Add to in-memory circular buffer
    # This is what the frontend polls to display logs
    log_buffer.append(log_entry.model_dump())

    # Write to file logger
    # Map our custom log levels to Python's logging levels
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "SUCCESS": logging.INFO,  # SUCCESS is treated as INFO in file logs
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR
    }
    file_log_level = log_level_map.get(level, logging.INFO)

    # Format the message for file logging
    # Include download ID if present for easier tracking
    log_msg = message
    if download_id:
        log_msg = f"[{download_id[:8]}] {message}"

    app_file_logger.log(file_log_level, log_msg, extra={'component': component})

    # Debug logging to console for troubleshooting
    # Track how many logs have been emitted using a function attribute
    if not hasattr(emit_log, 'call_count'):
        emit_log.call_count = 0
    emit_log.call_count += 1

    # Log to console selectively to avoid spam
    # Show first 20 logs to verify logging works, then every 50th log
    if emit_log.call_count <= 20 or emit_log.call_count % 50 == 0:
        logger.info(f"[LOG #{emit_log.call_count}] {level} | {component} | {message[:100]}")
        logger.info(f"[LOG] Log sequence: {log_sequence}")

    # Broadcast to WebSocket clients (if any are connected)
    # Note: Currently WebSocket logging is not used, switched to HTTP polling
    disconnected = []
    for ws in log_websockets:
        try:
            await ws.send_json(log_entry.model_dump())
        except Exception as e:
            logger.error(f"[LOG] Failed to send to WebSocket: {e}")
            disconnected.append(ws)

    # Remove any disconnected WebSocket clients
    for ws in disconnected:
        if ws in log_websockets:
            log_websockets.remove(ws)
            logger.info(f"[LOG] Removed disconnected WebSocket. Remaining: {len(log_websockets)}")


# Pydantic schemas for API request/response validation
# These models validate incoming requests and serialize outgoing responses

class DownloadRequest(BaseModel):
    """Request body for creating a new download"""
    url: str                                # Video URL to download
    cookies_file: Optional[str] = None      # Optional cookies file for authentication


class DownloadResponse(BaseModel):
    """Response model for download information"""
    model_config = ConfigDict(from_attributes=True)  # Allows creation from ORM objects

    id: str
    url: str
    status: str
    progress: float                         # 0.0 to 100.0
    filename: Optional[str]                 # Set after download completes
    thumbnail: Optional[str]                # Thumbnail filename
    file_size: Optional[int]                # Size in bytes
    error_message: Optional[str]            # Error message if failed
    created_at: datetime                    # When job was created/queued
    started_at: Optional[datetime]          # When download actually started
    completed_at: Optional[datetime]        # When download finished


class VersionInfo(BaseModel):
    """System version information"""
    ytdlp_version: str                      # yt-dlp version string
    app_version: str                        # Application version


class DiskSpaceInfo(BaseModel):
    """Disk space information"""
    total: int                              # Total disk space in bytes
    used: int                               # Used disk space in bytes
    free: int                               # Free disk space in bytes
    percent: float                          # Percentage used


class CleanupStats(BaseModel):
    """Statistics from cleanup operation"""
    downloads_removed: int                  # Number of database entries removed
    files_removed: int                      # Number of files deleted
    space_freed: int                        # Space freed in bytes


class ConversionCleanupStats(BaseModel):
    """Statistics from conversion cleanup operation"""
    conversions_removed: int                # Number of conversion entries removed
    files_removed: int                      # Number of files deleted
    space_freed: int                        # Space freed in bytes


class FileInfo(BaseModel):
    """Information about a downloaded file"""
    id: str                                  # Download ID for API operations
    filename: str                            # Display filename (user-friendly name)
    size: int                               # File size in bytes


class DownloadZipRequest(BaseModel):
    """Request body for downloading multiple files as ZIP"""
    download_ids: List[str]                 # List of download IDs to include


# Tool Conversion API Models
class VideoToMp3Request(BaseModel):
    """Request body for video to MP3 conversion"""
    source_download_id: str                 # UUID of source video
    audio_quality: int = 128                # Audio bitrate in kbps (96, 128, 192)


class ToolConversionResponse(BaseModel):
    """Response model for tool conversion status"""
    model_config = ConfigDict(from_attributes=True)

    id: str                                  # Conversion ID
    source_download_id: str                  # Source video ID
    tool_type: str                           # Type of conversion
    status: str                              # Current status
    progress: float                          # Progress percentage
    output_filename: Optional[str] = None    # Display filename
    output_size: Optional[int] = None        # Output file size in bytes
    audio_quality: Optional[int] = None      # Audio quality setting
    error_message: Optional[str] = None      # Error message if failed
    created_at: datetime                     # When conversion was created
    completed_at: Optional[datetime] = None  # When conversion completed


class VideoTransformRequest(BaseModel):
    """Request body for video transformation"""
    download_id: str                         # UUID of video to transform
    transform_type: str                      # Type of transformation (hflip, vflip, rotate90, rotate180, rotate270)


# Authentication Pydantic Models
class LoginRequest(BaseModel):
    """Request body for user login"""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Response body for successful login"""
    access_token: str
    token_type: str
    expires_in: int  # seconds
    username: str
    is_admin: bool


class UserInfoResponse(BaseModel):
    """Response body for current user info"""
    user_id: str
    username: str
    is_admin: bool
    last_login: Optional[datetime]


class UserResponse(BaseModel):
    """Response model for user data"""
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    is_admin: bool
    is_disabled: bool
    created_at: datetime
    last_login: Optional[datetime]


class CreateUserRequest(BaseModel):
    """Request body for creating a new user"""
    username: str
    password: str
    is_admin: bool = False


class UpdateUserRequest(BaseModel):
    """Request body for updating a user"""
    is_admin: Optional[bool] = None
    is_disabled: Optional[bool] = None
    new_password: Optional[str] = None


# Database Service - Handles all database operations
class DatabaseService:
    """
    Static service class for database operations.
    Provides methods for querying and updating download records.
    All methods take a database session as the first parameter.
    """
    @staticmethod
    def get_all_downloads(db: Session) -> List[Download]:
        return db.query(Download).order_by(Download.created_at.desc()).all()

    @staticmethod
    def get_download_by_id(db: Session, download_id: str) -> Optional[Download]:
        return db.query(Download).filter(Download.id == download_id).first()

    @staticmethod
    def get_downloads_by_status(db: Session, status: DownloadStatus) -> List[Download]:
        return db.query(Download).filter(Download.status == status).all()

    @staticmethod
    def get_failed_downloads_older_than(db: Session, days: int) -> List[Download]:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        return db.query(Download).filter(
            Download.status == DownloadStatus.FAILED,
            Download.created_at < cutoff_date
        ).all()

    @staticmethod
    def create_download(db: Session, url: str, cookies_file: Optional[str] = None) -> Download:
        download = Download(url=url, cookies_file=cookies_file)
        db.add(download)
        db.commit()
        db.refresh(download)
        return download

    @staticmethod
    def update_progress(db: Session, download_id: str, progress: float):
        download = DatabaseService.get_download_by_id(db, download_id)
        if download:
            download.progress = progress
            if progress > 0 and download.status == DownloadStatus.QUEUED:
                download.status = DownloadStatus.DOWNLOADING
            db.commit()

    @staticmethod
    def update_status(db: Session, download_id: str, status: DownloadStatus):
        download = DatabaseService.get_download_by_id(db, download_id)
        if download:
            download.status = status
            # Set started_at timestamp when download actually begins
            if status == DownloadStatus.DOWNLOADING and download.started_at is None:
                download.started_at = datetime.now(timezone.utc)
            db.commit()

    @staticmethod
    def mark_completed(db: Session, download_id: str, filename: str, file_size: int,
                      thumbnail: Optional[str] = None, internal_filename: Optional[str] = None,
                      internal_thumbnail: Optional[str] = None):
        download = DatabaseService.get_download_by_id(db, download_id)
        if download:
            download.status = DownloadStatus.COMPLETED
            download.progress = 100.0
            download.filename = filename
            download.file_size = file_size
            download.thumbnail = thumbnail
            download.internal_filename = internal_filename
            download.internal_thumbnail = internal_thumbnail
            download.completed_at = datetime.now(timezone.utc)
            db.commit()

    @staticmethod
    def mark_failed(db: Session, download_id: str, error_message: str):
        download = DatabaseService.get_download_by_id(db, download_id)
        if download:
            download.status = DownloadStatus.FAILED
            download.error_message = error_message
            download.completed_at = datetime.now(timezone.utc)
            db.commit()

    @staticmethod
    def delete_download(db: Session, download_id: str):
        download = DatabaseService.get_download_by_id(db, download_id)
        if download:
            db.delete(download)
            db.commit()

    @staticmethod
    def find_orphaned_files() -> List[str]:
        """Find files in downloads/ that don't have database entries"""
        if not os.path.exists("downloads"):
            return []

        with get_db() as db:
            # Get internal filenames (UUIDs) from database - these are the actual files on disk
            downloads = db.query(Download.internal_filename, Download.internal_thumbnail).all()
            db_filenames = set()

            for d in downloads:
                if d.internal_filename:
                    db_filenames.add(d.internal_filename)
                if d.internal_thumbnail:
                    db_filenames.add(d.internal_thumbnail)

        all_files = os.listdir("downloads")
        orphaned = [f for f in all_files if f not in db_filenames]
        return orphaned

    @staticmethod
    def remove_orphaned_files() -> tuple[int, int]:
        """Remove orphaned files and return (count, bytes_freed)"""
        orphaned = DatabaseService.find_orphaned_files()
        bytes_freed = 0

        for filename in orphaned:
            filepath = os.path.join("downloads", filename)
            try:
                size = os.path.getsize(filepath)
                os.remove(filepath)
                bytes_freed += size
            except Exception:
                pass

        return len(orphaned), bytes_freed


# YT-DLP Service
class YtdlpService:
    """
    Service for interacting with yt-dlp to download videos.
    Handles the subprocess execution, progress tracking, and file management.
    All output from yt-dlp is parsed and logged for the frontend to display.
    """

    @staticmethod
    async def download_video(download_id: str, url: str, cookies_file: Optional[str] = None):
        """
        Download a video using yt-dlp as a subprocess.

        This method:
        - Constructs the yt-dlp command with appropriate flags
        - Spawns the download process
        - Monitors stdout/stderr for progress and errors
        - Updates database with progress and completion status
        - Logs all activity for frontend display
        - Handles errors and marks downloads as failed if needed

        The download runs asynchronously so multiple downloads can run concurrently.
        """

        await emit_log("INFO", "Download", f"Starting download for URL: {url}", download_id)

        cmd = [
            "yt-dlp",
            "-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best[height>=360]",
            "-o", f"downloads/%(title)s-%(id)s.%(ext)s",
            "--merge-output-format", "mp4",
            "--write-thumbnail",
            "--convert-thumbnails", "jpg",
            "--no-playlist",
            "--newline",
            "--restrict-filenames",  # Restrict filenames to ASCII characters and common safe characters
            url
        ]

        # Add download speed limit if configured
        max_speed = settings.get("max_download_speed", 0)
        if max_speed > 0:
            cmd.extend(["--limit-rate", f"{max_speed}M"])
            await emit_log("INFO", "Download", f"Download speed limited to {max_speed}MiB/s", download_id)
        else:
            await emit_log("INFO", "Download", "Download speed unlimited (no rate limit applied)", download_id)

        if cookies_file and os.path.exists(f"cookies/{cookies_file}"):
            cmd.extend(["--cookies", f"cookies/{cookies_file}"])
            await emit_log("INFO", "Download", f"Using cookies file: {cookies_file}", download_id)

        try:
            await emit_log("DEBUG", "Download", f"Executing command: {' '.join(cmd)}", download_id)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            with get_db() as db:
                DatabaseService.update_status(db, download_id, DownloadStatus.DOWNLOADING)

            await emit_log("INFO", "Download", "Download process started", download_id)
            filename = None
            last_progress_log = 0

            # Read stdout and stderr concurrently
            async def read_stdout():
                nonlocal filename, last_progress_log
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break

                    line_str = line.decode().strip()
                    if not line_str:
                        continue

                    # Log all yt-dlp output
                    await emit_log("DEBUG", "YT-DLP", line_str, download_id)

                    # Log format selection
                    if "[info]" in line_str:
                        await emit_log("INFO", "YT-DLP", line_str, download_id)

                    # Parse progress and speed
                    progress_match = re.search(r'(\d+\.\d+)%', line_str)
                    if progress_match:
                        progress = float(progress_match.group(1))
                        with get_db() as db:
                            DatabaseService.update_progress(db, download_id, progress)

                        # Parse download speed (e.g., "2.34MiB/s" or "1.23KiB/s")
                        speed_str = None
                        speed_match = re.search(r'at\s+([\d.]+\s*[KMG]iB/s)', line_str)
                        if speed_match:
                            speed_str = speed_match.group(1).strip()

                        # Determine status based on progress
                        status = "processing" if progress >= 99 else "downloading"

                        # Send progress via WebSocket
                        await YtdlpService.broadcast_progress(download_id, {
                            "type": "progress",
                            "progress": progress,
                            "status": status,
                            "speed": speed_str
                        })

                        # Log progress milestones (every 10% to avoid spam)
                        if int(progress / 10) > int(last_progress_log / 10) or progress >= 99:
                            speed_info = f" at {speed_str}" if speed_str else ""
                            await emit_log("INFO", "Download", f"Progress: {progress:.1f}%{speed_info}", download_id)
                            last_progress_log = progress

                    # Parse destination filename
                    if "[download] Destination:" in line_str:
                        filename = line_str.split("Destination:")[-1].strip()
                        await emit_log("INFO", "Download", f"Destination file: {filename}", download_id)
                    elif "[Merger] Merging formats into" in line_str:
                        filename = line_str.split("into")[-1].strip().strip('"')
                        await emit_log("INFO", "Download", f"Merging formats into: {filename}", download_id)
                    elif "[download]" in line_str and "has already been downloaded" in line_str:
                        await emit_log("WARNING", "YT-DLP", line_str, download_id)
                    elif "ERROR:" in line_str or "WARNING:" in line_str:
                        level = "ERROR" if "ERROR:" in line_str else "WARNING"
                        await emit_log(level, "YT-DLP", line_str, download_id)

            async def read_stderr():
                while True:
                    line = await process.stderr.readline()
                    if not line:
                        break

                    line_str = line.decode().strip()
                    if not line_str:
                        continue

                    # Log all stderr as warnings or errors
                    level = "ERROR" if "error" in line_str.lower() else "WARNING"
                    await emit_log(level, "YT-DLP", line_str, download_id)

            # Run both readers concurrently
            await asyncio.gather(read_stdout(), read_stderr())

            await process.wait()

            if process.returncode == 0:
                # Success
                if filename and os.path.exists(filename):
                    file_size = os.path.getsize(filename)
                    original_basename = os.path.basename(filename)

                    # Apply additional sanitization to the filename for display
                    sanitized_basename = sanitize_filename(original_basename)

                    # Generate UUID-based internal filename for storage
                    # This isolates file operations from user-generated names
                    # Use same UUID for both video and thumbnail
                    file_uuid = str(uuid.uuid4())
                    file_ext = os.path.splitext(original_basename)[1]  # Keep original extension
                    internal_basename = f"{file_uuid}{file_ext}"
                    internal_path = os.path.join("downloads", internal_basename)

                    # Rename the file to UUID-based name on disk
                    try:
                        os.rename(filename, internal_path)
                        await emit_log("INFO", "Download", f"File stored as: {internal_basename} (display: {sanitized_basename})", download_id)
                        filename = internal_path
                    except Exception as e:
                        await emit_log("WARNING", "Download", f"Could not rename to UUID: {str(e)}. Using original name.", download_id)
                        sanitized_basename = original_basename
                        internal_basename = original_basename

                    basename = sanitized_basename  # Display name for user
                    internal_filename_only = internal_basename  # UUID name on disk

                    # Look for thumbnail file with various possible extensions and patterns
                    # Thumbnails are created based on the ORIGINAL downloaded filename (before UUID rename)
                    thumbnail_display_name = None
                    internal_thumbnail_only = None
                    original_base_without_ext = os.path.splitext(os.path.join("downloads", original_basename))[0]

                    # Try multiple thumbnail patterns based on original filename
                    possible_thumbs = [
                        f"{original_base_without_ext}.jpg",
                        f"{original_base_without_ext}.webp",
                        f"{original_base_without_ext}.png",
                    ]

                    for possible_thumb in possible_thumbs:
                        if os.path.exists(possible_thumb):
                            # Generate UUID-based thumbnail name using SAME UUID as video
                            # This makes it easy to find matching thumbnails
                            thumb_ext = os.path.splitext(possible_thumb)[1]
                            internal_thumb_basename = f"{file_uuid}{thumb_ext}"
                            internal_thumb_path = os.path.join("downloads", internal_thumb_basename)

                            # Sanitize original thumbnail name for display
                            thumb_basename = os.path.basename(possible_thumb)
                            sanitized_thumb = sanitize_filename(thumb_basename)

                            try:
                                # Rename thumbnail to UUID
                                os.rename(possible_thumb, internal_thumb_path)
                                thumbnail_display_name = sanitized_thumb
                                internal_thumbnail_only = internal_thumb_basename
                                await emit_log("INFO", "Download", f"Thumbnail stored as: {internal_thumb_basename} (display: {sanitized_thumb})", download_id)
                            except Exception as e:
                                await emit_log("WARNING", "Download", f"Could not rename thumbnail to UUID: {str(e)}", download_id)
                                thumbnail_display_name = thumb_basename
                                internal_thumbnail_only = thumb_basename
                            break

                    # Embed thumbnail into video if we found one
                    if thumbnail_display_name and internal_thumbnail_only:
                        await embed_thumbnail_in_video(internal_path, internal_thumb_path, download_id)

                    if not thumbnail_display_name:
                        await emit_log("WARNING", "Download", "No thumbnail found for video", download_id)

                    with get_db() as db:
                        DatabaseService.mark_completed(db, download_id, basename, file_size,
                                                      thumbnail_display_name, internal_filename_only,
                                                      internal_thumbnail_only)

                    await emit_log("SUCCESS", "Download", f"Download completed: {basename} ({file_size} bytes)", download_id)

                    await YtdlpService.broadcast_progress(download_id, {
                        "type": "completed",
                        "progress": 100.0,
                        "status": "completed",
                        "filename": basename
                    })
                else:
                    # Couldn't determine filename, but download succeeded
                    with get_db() as db:
                        DatabaseService.mark_completed(db, download_id, "unknown", 0)

                    await emit_log("WARNING", "Download", "Download completed but filename unknown", download_id)

                    await YtdlpService.broadcast_progress(download_id, {
                        "type": "completed",
                        "progress": 100.0,
                        "status": "completed"
                    })
            else:
                # Failed
                stderr = await process.stderr.read()
                error_msg = stderr.decode().strip()

                with get_db() as db:
                    DatabaseService.mark_failed(db, download_id, error_msg or "Download failed")

                await emit_log("ERROR", "Download", f"Download failed: {error_msg or 'Unknown error'}", download_id)

                await YtdlpService.broadcast_progress(download_id, {
                    "type": "failed",
                    "status": "failed",
                    "error": error_msg or "Download failed"
                })

        except Exception as e:
            # Ensure process is terminated if still running
            if 'process' in locals() and process and not process.returncode:
                try:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        # Force kill if terminate didn't work
                        process.kill()
                        await process.wait()
                except Exception as cleanup_error:
                    logger.error(f"Error terminating process for {download_id}: {cleanup_error}")
            
            with get_db() as db:
                DatabaseService.mark_failed(db, download_id, str(e))

            await emit_log("ERROR", "Download", f"Exception occurred: {str(e)}", download_id)

            await YtdlpService.broadcast_progress(download_id, {
                "type": "failed",
                "status": "failed",
                "error": str(e)
            })

    @staticmethod
    async def broadcast_progress(download_id: str, message: dict):
        """Broadcast progress to all connected WebSocket clients for this download"""
        if download_id in active_connections:
            disconnected = []
            for websocket in active_connections[download_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    disconnected.append(websocket)

            # Clean up disconnected clients
            for ws in disconnected:
                active_connections[download_id].remove(ws)

            if not active_connections[download_id]:
                del active_connections[download_id]


# Tool Conversion Service - Handles video to MP3 conversions
class ToolConversionService:
    @staticmethod
    async def convert_video_to_mp3(conversion_id: str, source_path: str,
                                   output_path: str, bitrate: int):
        """
        Extract audio from video using FFmpeg with progress tracking.
        Uses async subprocess to avoid blocking the event loop.

        Args:
            conversion_id: UUID of the conversion record
            source_path: Path to source video file
            output_path: Path for output MP3 file
            bitrate: Audio bitrate in kbps (96, 128, 192, etc.)
        """
        try:
            # Update status to converting
            with get_db() as db:
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.CONVERTING
                    conversion.progress = 0.0
                    db.commit()

            # Get video duration for progress calculation using async subprocess
            duration_process = await asyncio.create_subprocess_exec(
                'ffprobe', '-v', 'error',
                '-show_entries', 'format=duration',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                source_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            duration_stdout, _ = await asyncio.wait_for(
                duration_process.communicate(),
                timeout=30
            )

            try:
                total_duration = float(duration_stdout.decode().strip())
            except ValueError:
                total_duration = 0.0

            await emit_log("INFO", "ToolConversion",
                         f"Starting MP3 conversion: {bitrate} kbps", conversion_id)

            # FFmpeg command for MP3 conversion with progress output
            # Using async subprocess to keep event loop responsive
            process = await asyncio.create_subprocess_exec(
                'ffmpeg', '-y',  # Overwrite output file
                '-i', source_path,
                '-vn',  # No video
                '-acodec', 'libmp3lame',  # MP3 encoder
                '-b:a', f'{bitrate}k',  # Audio bitrate
                '-progress', 'pipe:1',  # Progress to stdout
                output_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Register process for cancellation tracking
            active_conversion_processes[conversion_id] = (process, output_path)

            # Parse FFmpeg progress output asynchronously
            stderr_data = b''
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                line_str = line.decode().strip()

                # Look for out_time_ms to calculate progress
                if line_str.startswith('out_time_ms='):
                    try:
                        out_time_ms = int(line_str.split('=')[1])
                        out_time_s = out_time_ms / 1_000_000  # Convert microseconds to seconds

                        if total_duration > 0:
                            progress = min((out_time_s / total_duration) * 100, 99.9)

                            # Update progress in database
                            with get_db() as db:
                                conversion = db.query(ToolConversion).filter(
                                    ToolConversion.id == conversion_id
                                ).first()
                                if conversion:
                                    conversion.progress = progress
                                    db.commit()
                    except (ValueError, IndexError):
                        pass

            # Wait for process to complete and collect stderr
            await process.wait()
            stderr_data = await process.stderr.read()

            if process.returncode != 0:
                stderr_output = stderr_data.decode()
                raise Exception(f"FFmpeg failed: {stderr_output}")

            # Get output file size
            output_size = os.path.getsize(output_path)

            # Mark as completed
            with get_db() as db:
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.COMPLETED
                    conversion.progress = 100.0
                    conversion.output_size = output_size
                    conversion.completed_at = datetime.now(timezone.utc)
                    db.commit()

            await emit_log("SUCCESS", "ToolConversion",
                         f"MP3 conversion completed: {output_size} bytes", conversion_id)

        except Exception as e:
            # Clean up output file if it exists
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass

            # Mark conversion as failed
            with get_db() as db:
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.FAILED
                    conversion.error_message = str(e)
                    db.commit()

            await emit_log("ERROR", "ToolConversion",
                         f"MP3 conversion failed: {str(e)}", conversion_id)
        finally:
            # Always unregister process from tracking
            if conversion_id in active_conversion_processes:
                del active_conversion_processes[conversion_id]


# Video Transform Service - Handles video flipping and rotation
class VideoTransformService:
    @staticmethod
    async def transform_video(download_id: str, transform_type: str):
        """
        Queue a video transformation job.
        Validates inputs, creates a ToolConversion record, and adds to queue.

        Args:
            download_id: UUID of the download record
            transform_type: Type of transformation (hflip, vflip, rotate90, rotate180, rotate270)

        Returns:
            ToolConversion: The created conversion record
        """
        # Validate transform type
        valid_transforms = ['hflip', 'vflip', 'rotate90', 'rotate180', 'rotate270']
        if transform_type not in valid_transforms:
            raise HTTPException(status_code=400, detail="Invalid transformation type")

        # Get download record and create conversion record
        with get_db() as db:
            download = db.query(Download).filter(Download.id == download_id).first()
            if not download:
                raise HTTPException(status_code=404, detail="Video not found")

            if download.status != DownloadStatus.COMPLETED:
                raise HTTPException(status_code=400, detail="Video download not completed")

            # Extract data we need from download object before session closes
            internal_filename = download.internal_filename
            display_filename = download.filename

            # Build file path
            source_path = os.path.join("downloads", internal_filename)

            if not os.path.exists(source_path):
                raise HTTPException(status_code=404, detail="Video file not found on disk")

            # Create ToolConversion record for progress tracking
            conversion = ToolConversion(
                source_download_id=download_id,
                tool_type=f"video_transform_{transform_type}",
                status=ConversionStatus.QUEUED,
                progress=0.0,
                output_filename=display_filename  # Same file, will be replaced
            )
            db.add(conversion)
            db.commit()
            db.refresh(conversion)
            conversion_id = conversion.id

        await emit_log("INFO", "VideoTransform",
                     f"Queued {transform_type} transformation for {display_filename}",
                     conversion_id)

        # Add to conversion queue
        await conversion_queue.add_to_queue(
            job_type="video_transform",
            conversion_id=conversion_id,
            download_id=download_id,
            source_path=source_path,
            transform_type=transform_type,
            internal_filename=internal_filename
        )

        # Return conversion record (similar to MP3 endpoint)
        return conversion

    @staticmethod
    async def process_transform(conversion_id: str, download_id: str, source_path: str,
                                transform_type: str, internal_filename: str):
        """
        Process a video transformation (called from queue).
        Applies the transformation using FFmpeg and updates the original file.

        Args:
            conversion_id: UUID of the conversion record
            download_id: UUID of the download record
            source_path: Path to the source video file
            transform_type: Type of transformation (hflip, vflip, rotate90, rotate180, rotate270)
            internal_filename: Internal filename of the video
        """

        # Create temp output path
        file_uuid = str(uuid.uuid4())
        file_ext = os.path.splitext(internal_filename)[1]
        temp_output_path = os.path.join("downloads", f"{file_uuid}_temp{file_ext}")

        try:
            # Update status to converting
            with get_db() as db:
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.CONVERTING
                    conversion.progress = 10.0
                    db.commit()

            await emit_log("INFO", "VideoTransform",
                         f"Starting {transform_type} transformation", download_id)

            # Get video duration for progress calculation
            duration_process = await asyncio.create_subprocess_exec(
                'ffprobe', '-v', 'error',
                '-show_entries', 'format=duration',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                source_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            duration_stdout, _ = await asyncio.wait_for(
                duration_process.communicate(),
                timeout=30
            )

            try:
                total_duration = float(duration_stdout.decode().strip())
            except ValueError:
                total_duration = 0.0

            # Build FFmpeg command based on transform type
            if transform_type == 'hflip':
                vf_filter = "hflip"
            elif transform_type == 'vflip':
                vf_filter = "vflip"
            elif transform_type == 'rotate90':
                vf_filter = "transpose=1"  # 90° clockwise
            elif transform_type == 'rotate180':
                vf_filter = "transpose=1,transpose=1"  # 180°
            elif transform_type == 'rotate270':
                vf_filter = "transpose=2"  # 90° counter-clockwise

            # Select video encoder based on available hardware acceleration
            video_encoder = 'libx264'  # Default CPU encoder
            encoder_preset = []  # Additional encoder-specific options

            if hardware_acceleration["nvenc"]:
                # NVIDIA NVENC - fast GPU encoding
                video_encoder = 'h264_nvenc'
                encoder_preset = ['-preset', 'fast']
                await emit_log("INFO", "VideoTransform", "Using NVIDIA NVENC acceleration", conversion_id)
            elif hardware_acceleration["amf"]:
                # AMD AMF - AMD GPU encoding
                video_encoder = 'h264_amf'
                encoder_preset = ['-quality', 'balanced']
                await emit_log("INFO", "VideoTransform", "Using AMD AMF acceleration", conversion_id)
            elif hardware_acceleration["qsv"]:
                # Intel Quick Sync Video
                video_encoder = 'h264_qsv'
                encoder_preset = ['-preset', 'fast']
                await emit_log("INFO", "VideoTransform", "Using Intel Quick Sync acceleration", conversion_id)
            elif hardware_acceleration["vaapi"]:
                # VAAPI (Linux)
                video_encoder = 'h264_vaapi'
                await emit_log("INFO", "VideoTransform", "Using VAAPI acceleration", conversion_id)
            elif hardware_acceleration["videotoolbox"]:
                # Apple VideoToolbox (macOS)
                video_encoder = 'h264_videotoolbox'
                await emit_log("INFO", "VideoTransform", "Using VideoToolbox acceleration", conversion_id)
            else:
                await emit_log("INFO", "VideoTransform", "Using CPU encoding (no hardware acceleration)", conversion_id)

            # Try hardware acceleration first, fall back to CPU if it fails
            hardware_failed = False
            using_hardware = video_encoder != 'libx264'

            # Build FFmpeg command with hardware acceleration
            ffmpeg_cmd = [
                'ffmpeg', '-y',
                '-i', source_path,
                '-vf', vf_filter,
                '-c:v', video_encoder
            ]

            # Add encoder-specific presets
            ffmpeg_cmd.extend(encoder_preset)

            # Copy audio without re-encoding
            ffmpeg_cmd.extend(['-c:a', 'copy'])

            # Progress output
            ffmpeg_cmd.extend(['-progress', 'pipe:1'])

            # Output file
            ffmpeg_cmd.append(temp_output_path)

            # Run FFmpeg transformation with progress output
            process = await asyncio.create_subprocess_exec(
                *ffmpeg_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Register process for cancellation tracking
            active_conversion_processes[conversion_id] = (process, temp_output_path)

            # Parse FFmpeg progress output asynchronously
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                line_str = line.decode().strip()

                # Look for out_time_ms to calculate progress
                if line_str.startswith('out_time_ms='):
                    try:
                        out_time_ms = int(line_str.split('=')[1])
                        out_time_s = out_time_ms / 1_000_000  # Convert microseconds to seconds

                        if total_duration > 0:
                            progress = min((out_time_s / total_duration) * 100, 99.9)

                            # Update progress in database
                            with get_db() as db:
                                conversion = db.query(ToolConversion).filter(
                                    ToolConversion.id == conversion_id
                                ).first()
                                if conversion:
                                    conversion.progress = progress
                                    db.commit()
                    except (ValueError, IndexError):
                        pass

            # Wait for process to complete
            await process.wait()
            stderr_data = await process.stderr.read()

            # If hardware acceleration failed, retry with CPU
            if process.returncode != 0 and using_hardware:
                hardware_failed = True
                await emit_log("WARNING", "VideoTransform",
                             f"Hardware acceleration failed, retrying with CPU encoding",
                             conversion_id)

                # Clean up temp file
                if os.path.exists(temp_output_path):
                    os.remove(temp_output_path)

                # Rebuild command with CPU encoder
                ffmpeg_cmd = [
                    'ffmpeg', '-y',
                    '-i', source_path,
                    '-vf', vf_filter,
                    '-c:v', 'libx264',  # CPU encoder
                    '-c:a', 'copy',
                    '-progress', 'pipe:1',
                    temp_output_path
                ]

                # Run FFmpeg with CPU encoding
                process = await asyncio.create_subprocess_exec(
                    *ffmpeg_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                # Update process tracking
                active_conversion_processes[conversion_id] = (process, temp_output_path)

                # Reset progress to 0
                with get_db() as db:
                    conversion = db.query(ToolConversion).filter(
                        ToolConversion.id == conversion_id
                    ).first()
                    if conversion:
                        conversion.progress = 0.0
                        db.commit()

                # Parse progress again
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break

                    line_str = line.decode().strip()

                    if line_str.startswith('out_time_ms='):
                        try:
                            out_time_ms = int(line_str.split('=')[1])
                            out_time_s = out_time_ms / 1_000_000

                            if total_duration > 0:
                                progress = min((out_time_s / total_duration) * 100, 99.9)

                                with get_db() as db:
                                    conversion = db.query(ToolConversion).filter(
                                        ToolConversion.id == conversion_id
                                    ).first()
                                    if conversion:
                                        conversion.progress = progress
                                        db.commit()
                        except (ValueError, IndexError):
                            pass

                await process.wait()
                stderr_data = await process.stderr.read()

            if process.returncode != 0:
                raise Exception(f"FFmpeg transformation failed: {stderr_data.decode()}")

            # Get new file size
            new_file_size = os.path.getsize(temp_output_path)

            # Replace original file with transformed file
            os.replace(temp_output_path, source_path)

            # Update file size in download database
            with get_db() as db:
                download = db.query(Download).filter(Download.id == download_id).first()
                if download:
                    download.file_size = new_file_size
                    db.commit()

                # Mark conversion as completed
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.COMPLETED
                    conversion.progress = 100.0
                    conversion.output_size = new_file_size
                    conversion.completed_at = datetime.now(timezone.utc)
                    db.commit()

            await emit_log("SUCCESS", "VideoTransform",
                         f"Transformation {transform_type} completed: {new_file_size} bytes",
                         download_id)

        except Exception as e:
            # Clean up temp file if it exists
            if os.path.exists(temp_output_path):
                try:
                    os.remove(temp_output_path)
                except:
                    pass

            # Mark conversion as failed
            with get_db() as db:
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.FAILED
                    conversion.error_message = str(e)
                    db.commit()

            await emit_log("ERROR", "VideoTransform",
                         f"Transformation {transform_type} failed: {str(e)}",
                         download_id)
        finally:
            # Always unregister process from tracking
            if conversion_id in active_conversion_processes:
                del active_conversion_processes[conversion_id]


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Log all unhandled exceptions"""
    await emit_log("ERROR", "System", f"Unhandled exception: {type(exc).__name__}: {str(exc)}")
    logger.exception("Unhandled exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Authentication Dependencies
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    FastAPI dependency to extract and validate JWT token.
    Raises 401 if token is missing or invalid.

    This dependency:
    - Checks if authentication is enabled
    - Validates public endpoint whitelist
    - Validates JWT token
    - Verifies user exists and is not disabled
    """
    # Try to load admin settings
    admin_settings = None
    auth_enabled = True  # SECURITY: Fail secure by default

    try:
        admin_settings = get_admin_settings()
        # Check if auth config exists and is explicitly set to false
        if hasattr(admin_settings, 'auth') and hasattr(admin_settings.auth, 'enabled'):
            auth_enabled = admin_settings.auth.enabled
            if auth_enabled is False:
                # Auth explicitly disabled - allow access with dummy user
                return {"sub": "system", "username": "system", "is_admin": True}
        else:
            # Auth config missing - fail secure by requiring authentication
            pass
    except Exception as e:
        # Error loading settings - fail secure by requiring authentication
        pass

    # Auth is enabled (or config missing) - check if this endpoint is public
    if admin_settings and hasattr(admin_settings, 'auth'):
        try:
            path = request.url.path
            for public_pattern in admin_settings.auth.public_endpoints:
                if public_pattern.endswith("*"):
                    # Wildcard match
                    if path.startswith(public_pattern[:-1]):
                        return {"sub": "public", "username": "public", "is_admin": False}
                elif path == public_pattern:
                    # Exact match
                    return {"sub": "public", "username": "public", "is_admin": False}
        except (AttributeError, Exception):
            # If we can't check public endpoints, continue to token validation
            pass

    # Require authentication
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if we have valid admin_settings for token validation
    if not admin_settings:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication system unavailable - server configuration error"
        )

    # Validate token
    payload = JWTService.decode_token(credentials.credentials, db, admin_settings)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user still exists and is not disabled
    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user or user.is_disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


async def get_current_admin_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    FastAPI dependency to require admin privileges.
    Raises 403 if user is not an admin.
    """
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


# API Endpoints

# ===========================
# Authentication Endpoints
# ===========================

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db_session)
):
    """
    Authenticate user and return JWT token.

    Performs comprehensive authentication including:
    - Account lockout check
    - User existence verification
    - Password verification
    - Suspicious IP activity detection
    - Login history recording
    - Audit logging
    """
    admin_settings = get_admin_settings()

    # Extract client info
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")

    # Authenticate user
    success, user, error_message = AuthService.authenticate_user(
        username=login_data.username,
        password=login_data.password,
        ip_address=ip_address,
        user_agent=user_agent,
        db=db,
        admin_settings=admin_settings
    )

    if not success:
        # Record login attempt in history
        login_history = UserLoginHistory(
            user_id=user.id if user else None,
            ip_address=ip_address,
            success=False,
            failure_reason=error_message,
            user_agent=user_agent
        )
        db.add(login_history)
        db.commit()

        # Log audit event
        AuditLogService.log_event(
            event_type="login_failed",
            ip_address=ip_address,
            db=db,
            username=login_data.username,
            details={"reason": error_message}
        )

        # Return error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_message
        )

    # Generate JWT token
    access_token = JWTService.create_access_token(
        user_id=user.id,
        username=user.username,
        is_admin=user.is_admin,
        db=db,
        admin_settings=admin_settings
    )

    # Record successful login in history
    login_history = UserLoginHistory(
        user_id=user.id,
        ip_address=ip_address,
        success=True,
        failure_reason=None,
        user_agent=user_agent
    )
    db.add(login_history)
    db.commit()

    # Log audit event
    AuditLogService.log_event(
        event_type="login_success",
        ip_address=ip_address,
        db=db,
        user_id=user.id,
        username=user.username
    )

    await emit_log("INFO", "Authentication", f"User {user.username} logged in from {ip_address}")

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=admin_settings.auth.jwt_session_expiry_hours * 3600,  # Convert to seconds
        username=user.username,
        is_admin=user.is_admin
    )


@app.post("/api/auth/logout")
async def logout(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """
    Logout user (client-side token deletion).

    Note: JWT tokens are stateless, so this endpoint primarily serves
    to log the logout event for audit purposes. The client must delete
    the token from storage.
    """
    ip_address = get_client_ip(request)

    # Log audit event
    AuditLogService.log_event(
        event_type="logout",
        ip_address=ip_address,
        db=db,
        user_id=current_user.get("sub"),
        username=current_user.get("username")
    )

    await emit_log("INFO", "Authentication", f"User {current_user.get('username')} logged out from {ip_address}")

    return {"message": "Logged out successfully"}


@app.post("/api/auth/refresh", response_model=LoginResponse)
async def refresh_token(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """
    Refresh JWT token with new expiry.

    Validates current token and issues a new one with extended expiry.
    Useful for keeping users logged in during active sessions.
    """
    admin_settings = get_admin_settings()
    ip_address = get_client_ip(request)

    # Get user from database
    user = db.query(User).filter(User.id == current_user["sub"]).first()
    if not user or user.is_disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )

    # Generate new token
    access_token = JWTService.create_access_token(
        user_id=user.id,
        username=user.username,
        is_admin=user.is_admin,
        db=db,
        admin_settings=admin_settings
    )

    # Log audit event
    AuditLogService.log_event(
        event_type="token_refresh",
        ip_address=ip_address,
        db=db,
        user_id=user.id,
        username=user.username
    )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=admin_settings.auth.jwt_session_expiry_hours * 3600,
        username=user.username,
        is_admin=user.is_admin
    )


@app.get("/api/auth/me", response_model=UserInfoResponse)
async def get_current_user_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """
    Get current user information.

    Returns details about the authenticated user.
    """
    user = db.query(User).filter(User.id == current_user["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserInfoResponse(
        user_id=user.id,
        username=user.username,
        is_admin=user.is_admin,
        last_login=user.last_login
    )


@app.get("/api/auth/status")
async def get_auth_status():
    """
    Get authentication system status (PUBLIC endpoint).

    Returns whether authentication is enabled and session configuration.
    Used by frontend to determine if login is required.

    SECURITY: Fails secure - if config can't be loaded, reports auth as enabled.
    """
    try:
        admin_settings = get_admin_settings()

        # Check if auth config exists
        if hasattr(admin_settings, 'auth') and hasattr(admin_settings.auth, 'enabled'):
            auth_enabled = admin_settings.auth.enabled
            session_expiry = admin_settings.auth.jwt_session_expiry_hours
        else:
            # Config missing - fail secure by reporting auth as enabled
            auth_enabled = True
            session_expiry = 24  # Default value

    except Exception:
        # Error loading config - fail secure by reporting auth as enabled
        auth_enabled = True
        session_expiry = 24  # Default value

    return {
        "auth_enabled": auth_enabled,
        "session_expiry_hours": session_expiry
    }


@app.get("/api/release-notes")
async def get_release_notes():
    """
    Get release notes from docs/release.json (PUBLIC endpoint).

    Returns version information and release history.
    Used by login page to display release notes.
    Current version is always pulled from APP_VERSION constant.
    """
    try:
        import json
        with open("docs/release.json", "r") as f:
            release_data = json.load(f)
        # Override current_version with APP_VERSION (single source of truth)
        release_data["current_version"] = APP_VERSION
        return release_data
    except FileNotFoundError:
        return {
            "current_version": APP_VERSION,
            "releases": []
        }
    except Exception as e:
        return {
            "current_version": APP_VERSION,
            "releases": [],
            "error": "Failed to load release notes"
        }


# ===========================
# User Management Endpoints (Admin Only)
# ===========================

@app.post("/api/users", response_model=UserResponse)
async def create_user(
    request: Request,
    user_data: CreateUserRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """
    Create a new user (ADMIN ONLY).

    Validates username format and password strength, then creates
    a new user account with hashed password.
    """
    admin_settings = get_admin_settings()
    ip_address = get_client_ip(request)

    # Validate username (3-32 alphanumeric chars, underscore allowed)
    if not user_data.username or len(user_data.username) < 3 or len(user_data.username) > 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be 3-32 characters"
        )

    if not user_data.username.replace("_", "").isalnum():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must contain only alphanumeric characters and underscores"
        )

    # Validate password (min 8 chars)
    if not user_data.password or len(user_data.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters"
        )

    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )

    # Hash password
    password_hash = PasswordService.hash_password(user_data.password)

    # Create user
    new_user = User(
        username=user_data.username,
        password_hash=password_hash,
        is_admin=user_data.is_admin,
        is_disabled=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log audit event
    AuditLogService.log_event(
        event_type="user_created",
        ip_address=ip_address,
        db=db,
        user_id=current_admin.get("sub"),
        username=current_admin.get("username"),
        details={
            "created_user_id": new_user.id,
            "created_username": new_user.username,
            "is_admin": new_user.is_admin
        }
    )

    await emit_log("INFO", "User Management", f"Admin {current_admin.get('username')} created user {new_user.username}")

    return UserResponse.model_validate(new_user)


@app.get("/api/users", response_model=List[UserResponse])
async def list_users(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """
    List all users (ADMIN ONLY).

    Returns all user accounts with their metadata.
    """
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [UserResponse.model_validate(user) for user in users]


@app.patch("/api/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    request: Request,
    update_data: UpdateUserRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """
    Update user account (ADMIN ONLY).

    Can update: is_admin, is_disabled, password.
    Prevents admins from disabling their own accounts.
    """
    ip_address = get_client_ip(request)

    # Find user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    changes = {}

    # Update is_admin
    if update_data.is_admin is not None:
        old_value = user.is_admin
        user.is_admin = update_data.is_admin
        changes["is_admin"] = {"from": old_value, "to": update_data.is_admin}

    # Update is_disabled
    if update_data.is_disabled is not None:
        # Prevent self-disable
        if user.id == current_admin.get("sub") and update_data.is_disabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable your own account"
            )

        old_value = user.is_disabled
        user.is_disabled = update_data.is_disabled
        changes["is_disabled"] = {"from": old_value, "to": update_data.is_disabled}

        # If enabling account, clear failed login attempts
        if not update_data.is_disabled:
            AuthService.clear_failed_attempts(user.username, db)

    # Update password
    if update_data.new_password:
        if len(update_data.new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters"
            )

        user.password_hash = PasswordService.hash_password(update_data.new_password)
        changes["password"] = "updated"

    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    # Log audit event
    AuditLogService.log_event(
        event_type="user_updated",
        ip_address=ip_address,
        db=db,
        user_id=current_admin.get("sub"),
        username=current_admin.get("username"),
        details={
            "updated_user_id": user.id,
            "updated_username": user.username,
            "changes": changes
        }
    )

    await emit_log("INFO", "User Management", f"Admin {current_admin.get('username')} updated user {user.username}")

    return UserResponse.model_validate(user)


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    """
    Delete user account (ADMIN ONLY).

    Prevents self-deletion. Deletes user and all associated records.
    """
    ip_address = get_client_ip(request)

    # Prevent self-deletion
    if user_id == current_admin.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    # Find user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    username = user.username

    # Delete associated records
    db.query(UserLoginHistory).filter(UserLoginHistory.user_id == user_id).delete()
    db.query(FailedLoginAttempt).filter(FailedLoginAttempt.username == username).delete()

    # Delete user
    db.delete(user)
    db.commit()

    # Log audit event
    AuditLogService.log_event(
        event_type="user_deleted",
        ip_address=ip_address,
        db=db,
        user_id=current_admin.get("sub"),
        username=current_admin.get("username"),
        details={
            "deleted_user_id": user_id,
            "deleted_username": username
        }
    )

    await emit_log("INFO", "User Management", f"Admin {current_admin.get('username')} deleted user {username}")

    return {"message": f"User {username} deleted successfully"}


@app.get("/")
async def root(request: Request):
    """
    Serve the main HTML page or redirect to login.

    If authentication is enabled, checks for valid token in Authorization header
    or as a query parameter (for browser redirects). If token is invalid or missing,
    redirects to login page.
    """
    from fastapi.responses import HTMLResponse, RedirectResponse

    admin_settings = get_admin_settings()

    # If auth is disabled, serve main page directly
    if not admin_settings.auth.enabled:
        with open("assets/index.html") as f:
            return HTMLResponse(content=f.read())

    # Auth is enabled - check for token
    # Try to get token from Authorization header first
    auth_header = request.headers.get('authorization', '')
    token = None

    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]

    if token:
        # Validate token
        with get_db() as db:
            payload = JWTService.decode_token(token, db, admin_settings)
            if payload:
                # Valid token - serve main page
                with open("assets/index.html") as f:
                    return HTMLResponse(content=f.read())

    # No valid token - redirect to login
    return RedirectResponse(url='/assets/login.html')


@app.get("/favicon.ico")
async def favicon():
    """Serve favicon"""
    from fastapi.responses import FileResponse
    return FileResponse("assets/logo.png", media_type="image/png")


@app.get("/api/test-log")
async def test_log():
    """Test endpoint to generate a log message"""
    await emit_log("INFO", "System", f"Test log generated at {datetime.now(timezone.utc).isoformat()}")
    return {"status": "ok", "message": "Test log sent"}


@app.post("/api/download", response_model=DownloadResponse)
async def start_download(request: DownloadRequest, http_request: Request, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Start a new video download"""
    # Get client IP (from proxy headers middleware)
    client_ip = getattr(http_request.state, 'client_ip', 'unknown')

    # Rate limiting: configured in admin_settings.json
    if not check_rate_limit(client_ip):
        await emit_log("WARNING", "API", f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    # Validate URL
    is_valid, error_msg = validate_url(request.url)
    if not is_valid:
        await emit_log("WARNING", "API", f"Invalid URL rejected: {error_msg}")
        raise HTTPException(status_code=400, detail=f"Invalid URL: {error_msg}")

    # Validate cookie file if provided
    if request.cookies_file:
        if not validate_cookie_filename(request.cookies_file):
            await emit_log("WARNING", "API", f"Invalid cookie filename: {request.cookies_file}")
            raise HTTPException(status_code=400, detail="Invalid cookie filename")

        # Check if cookie file exists
        cookie_path = os.path.join("cookies", request.cookies_file)
        if not os.path.exists(cookie_path):
            raise HTTPException(status_code=404, detail="Cookie file not found")

    safe_url = sanitize_url_for_logging(request.url)
    await emit_log("INFO", "API", f"New download request from {client_ip} for URL: {safe_url}")

    download = DatabaseService.create_download(db, request.url, request.cookies_file)

    await emit_log("INFO", "API", f"Download created with ID: {download.id}", download.id)

    # Add download to queue
    await download_queue.add_to_queue(
        download.id,
        request.url,
        request.cookies_file
    )

    return download


@app.post("/api/upload", response_model=DownloadResponse)
async def upload_video(
    file: UploadFile = File(...),
    http_request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    """
    Upload a video file to use with tools.
    Creates a Download record with status COMPLETED to integrate with existing tools.
    """
    # Get client IP
    client_ip = getattr(http_request.state, 'client_ip', 'unknown') if http_request else 'unknown'

    # Validate filename doesn't contain path traversal or dangerous characters
    if not file.filename or '..' in file.filename or '/' in file.filename or '\\' in file.filename:
        await emit_log("WARNING", "Upload", f"Suspicious filename rejected from {client_ip}")
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Validate file extension (only accept common video formats)
    allowed_extensions = {'.mp4', '.mkv', '.webm', '.avi', '.mov'}
    file_ext = os.path.splitext(file.filename)[1].lower()

    if file_ext not in allowed_extensions:
        await emit_log("WARNING", "Upload", f"Invalid file type rejected: {file_ext} from {client_ip}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: MP4, MKV, WebM, AVI, MOV"
        )

    # Validate file size (max 2GB to prevent abuse)
    MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB in bytes
    if file.size and file.size > MAX_FILE_SIZE:
        await emit_log("WARNING", "Upload", f"File too large rejected from {client_ip}: {file.size} bytes")
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is 2GB."
        )

    # Check disk space
    free_space_mb = shutil.disk_usage("downloads").free / (1024 * 1024)
    min_space = settings.get("min_disk_space_mb", 1000)

    if free_space_mb < min_space:
        await emit_log("WARNING", "Upload", f"Insufficient disk space for upload from {client_ip}")
        raise HTTPException(
            status_code=507,
            detail=f"Insufficient disk space. Need {min_space}MB free, only {free_space_mb:.1f}MB available."
        )

    try:
        # Generate UUID for internal filename (safe from injection)
        file_uuid = str(uuid.uuid4())
        internal_filename = f"{file_uuid}{file_ext}"
        file_path = os.path.join("downloads", internal_filename)

        # Use original filename for display (already validated for path traversal above)
        display_filename = file.filename

        await emit_log("INFO", "Upload", f"Starting upload from {client_ip}: {display_filename}")

        # Save uploaded file
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        # Get file size
        file_size = os.path.getsize(file_path)

        # Extract thumbnail using FFmpeg
        thumbnail_uuid = str(uuid.uuid4())
        internal_thumbnail = f"{thumbnail_uuid}.jpg"
        thumbnail_path = os.path.join("downloads", internal_thumbnail)

        try:
            # Extract thumbnail at 2 seconds into the video
            thumb_process = await asyncio.create_subprocess_exec(
                'ffmpeg', '-i', file_path,
                '-ss', '2',  # Seek to 2 seconds
                '-vframes', '1',  # Extract 1 frame
                '-vf', 'scale=320:-1',  # Scale to 320px width, maintain aspect ratio
                thumbnail_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await asyncio.wait_for(thumb_process.communicate(), timeout=30)

            # Check if thumbnail was created successfully
            if not os.path.exists(thumbnail_path) or thumb_process.returncode != 0:
                internal_thumbnail = None
                await emit_log("WARNING", "Upload", f"Failed to generate thumbnail for {display_filename}", None)
            else:
                # Embed the thumbnail into the video
                await embed_thumbnail_in_video(file_path, thumbnail_path, None)
        except Exception as e:
            # Thumbnail extraction failed, but upload still succeeds
            internal_thumbnail = None
            await emit_log("WARNING", "Upload", f"Thumbnail extraction failed: {str(e)}", None)

        # Create Download record with status COMPLETED
        # This allows the uploaded file to appear in tools and file lists
        download = Download(
            url=f"uploaded://{display_filename}",  # Special URL to indicate upload
            filename=display_filename,
            internal_filename=internal_filename,
            thumbnail=internal_thumbnail if internal_thumbnail else None,  # Display thumbnail name
            internal_thumbnail=internal_thumbnail,  # Internal thumbnail name
            file_size=file_size,
            status=DownloadStatus.COMPLETED,
            progress=100.0,
            completed_at=datetime.now(timezone.utc)
        )
        db.add(download)
        db.commit()
        db.refresh(download)

        await emit_log("SUCCESS", "Upload",
                      f"Upload completed: {display_filename} ({file_size} bytes)",
                      download.id)

        return download

    except Exception as e:
        # Clean up files if they were created
        if 'file_path' in locals() and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass

        if 'thumbnail_path' in locals() and os.path.exists(thumbnail_path):
            try:
                os.remove(thumbnail_path)
            except:
                pass

        await emit_log("ERROR", "Upload", f"Upload failed from {client_ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.get("/api/downloads", response_model=List[DownloadResponse])
async def get_downloads(status: Optional[str] = None, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Get all downloads, optionally filtered by status"""
    if status:
        try:
            status_enum = DownloadStatus(status)
            downloads = DatabaseService.get_downloads_by_status(db, status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")
    else:
        downloads = DatabaseService.get_all_downloads(db)

    return downloads


@app.get("/api/downloads/{download_id}", response_model=DownloadResponse)
async def get_download(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Get a specific download by ID"""
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")
    return download


@app.delete("/api/downloads/{download_id}")
async def delete_download(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Delete a download and its associated file"""
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        await emit_log("WARNING", "API", f"Attempted to delete non-existent download: {download_id}")
        raise HTTPException(status_code=404, detail="Download not found")

    await emit_log("INFO", "API", f"Deleting download: {download_id}", download_id)

    display_name = download.filename or "unknown"

    # Delete video file if it exists (using internal_filename)
    if download.internal_filename:
        filepath = os.path.join("downloads", download.internal_filename)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                await emit_log("INFO", "API", f"Deleted file: {display_name} (internal: {download.internal_filename})", download_id)
            except Exception as e:
                await emit_log("ERROR", "API", f"Failed to delete file {display_name}: {str(e)}", download_id)

    # Delete thumbnail if it exists (using internal_thumbnail)
    if download.internal_thumbnail:
        thumb_path = os.path.join("downloads", download.internal_thumbnail)
        if os.path.exists(thumb_path):
            try:
                os.remove(thumb_path)
                await emit_log("INFO", "API", f"Deleted thumbnail: {download.internal_thumbnail}", download_id)
            except Exception as e:
                await emit_log("WARNING", "API", f"Failed to delete thumbnail: {str(e)}", download_id)

    DatabaseService.delete_download(db, download_id)
    await emit_log("SUCCESS", "API", f"Download deleted successfully: {display_name}", download_id)
    return {"message": "Download deleted successfully"}


@app.post("/api/downloads/cleanup", response_model=CleanupStats)
async def cleanup_downloads(days: int = 7, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Clean up failed downloads older than specified days and remove orphaned files"""

    await emit_log("INFO", "Cleanup", f"Starting cleanup of downloads older than {days} days")

    # Delete old failed downloads
    failed_downloads = DatabaseService.get_failed_downloads_older_than(db, days)
    downloads_removed = 0
    space_freed = 0

    await emit_log("INFO", "Cleanup", f"Found {len(failed_downloads)} failed downloads to clean up")

    for download in failed_downloads:
        display_name = download.filename or "unknown"

        # Delete video file using internal_filename
        if download.internal_filename:
            filepath = os.path.join("downloads", download.internal_filename)
            if os.path.exists(filepath):
                try:
                    size = os.path.getsize(filepath)
                    os.remove(filepath)
                    space_freed += size
                    await emit_log("INFO", "Cleanup", f"Removed file: {display_name} ({size} bytes)", download.id)
                except Exception as e:
                    await emit_log("ERROR", "Cleanup", f"Failed to remove file {display_name}: {str(e)}", download.id)

        # Delete thumbnail using internal_thumbnail
        if download.internal_thumbnail:
            thumb_path = os.path.join("downloads", download.internal_thumbnail)
            if os.path.exists(thumb_path):
                try:
                    thumb_size = os.path.getsize(thumb_path)
                    os.remove(thumb_path)
                    space_freed += thumb_size
                    await emit_log("INFO", "Cleanup", f"Removed thumbnail: {download.internal_thumbnail} ({thumb_size} bytes)", download.id)
                except Exception as e:
                    await emit_log("WARNING", "Cleanup", f"Failed to remove thumbnail: {str(e)}", download.id)

        DatabaseService.delete_download(db, download.id)
        downloads_removed += 1

    # Remove orphaned files
    await emit_log("INFO", "Cleanup", "Checking for orphaned files")
    orphaned_count, orphaned_bytes = DatabaseService.remove_orphaned_files()

    if orphaned_count > 0:
        await emit_log("INFO", "Cleanup", f"Removed {orphaned_count} orphaned files ({orphaned_bytes} bytes)")

    total_freed = space_freed + orphaned_bytes
    await emit_log("SUCCESS", "Cleanup", f"Cleanup complete: {downloads_removed} downloads, {orphaned_count} files removed, {total_freed} bytes freed")

    return CleanupStats(
        downloads_removed=downloads_removed,
        files_removed=orphaned_count,
        space_freed=total_freed
    )


@app.websocket("/ws/{download_id}")
async def websocket_endpoint(websocket: WebSocket, download_id: str):
    """WebSocket endpoint for real-time download progress"""
    await websocket.accept()

    # Add to active connections
    if download_id not in active_connections:
        active_connections[download_id] = []
    active_connections[download_id].append(websocket)

    try:
        # Send current status
        with get_db() as db:
            download = DatabaseService.get_download_by_id(db, download_id)
            if download:
                await websocket.send_json({
                    "type": "status",
                    "status": download.status.value,
                    "progress": download.progress
                })

        # Keep connection alive with timeout
        # Disconnect if client stops responding for 5 minutes
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=WEBSOCKET_IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error for download {download_id}: {e}")
    finally:
        # Ensure proper cleanup
        if download_id in active_connections:
            try:
                active_connections[download_id].remove(websocket)
            except ValueError:
                pass  # Already removed
            
            if not active_connections[download_id]:
                del active_connections[download_id]
        
        # Close connection if still open
        try:
            await websocket.close()
        except Exception:
            pass  # Already closed


@app.post("/api/logs/test")
async def test_log():
    """Test endpoint to emit a log message"""
    await emit_log("INFO", "Test", "🧪 This is a test log message from the API!")
    return {"message": "Test log emitted", "websocket_clients": len(log_websockets)}


@app.get("/api/logs")
async def get_logs(
    level: Optional[str] = None,
    component: Optional[str] = None,
    download_id: Optional[str] = None,
    since_sequence: Optional[int] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get logs with optional filtering and incremental updates"""
    logs = list(log_buffer)

    # If since_sequence is provided, only return logs after that sequence number
    if since_sequence is not None:
        logs = [log for log in logs if log["sequence"] > since_sequence]

    # Apply filters
    if level:
        logs = [log for log in logs if log["level"] == level.upper()]
    if component:
        logs = [log for log in logs if log["component"] == component]
    if download_id:
        logs = [log for log in logs if log.get("download_id") == download_id]

    # Return logs with the current sequence number
    latest_sequence = log_buffer[-1]["sequence"] if log_buffer else 0

    return {
        "logs": logs,
        "buffer_size": len(log_buffer),
        "latest_sequence": latest_sequence
    }


@app.websocket("/ws/logs")
async def logs_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time log streaming"""
    logger.info(f"[DEBUG] WebSocket connection attempt from {websocket.client}")
    
    # Enforce maximum WebSocket connections to prevent memory exhaustion
    if len(log_websockets) >= MAX_LOG_WEBSOCKET_CONNECTIONS:
        await websocket.close(code=1008, reason="Server at max WebSocket capacity")
        logger.warning(f"[DEBUG] WebSocket connection rejected - max capacity ({MAX_LOG_WEBSOCKET_CONNECTIONS}) reached")
        await emit_log("WARNING", "System", f"WebSocket connection rejected - max capacity reached from {websocket.client}")
        return
    
    await websocket.accept()
    logger.info(f"[DEBUG] WebSocket accepted, adding to log_websockets list")
    log_websockets.append(websocket)
    logger.info(f"[DEBUG] Total WebSocket clients: {len(log_websockets)}")

    await emit_log("INFO", "System", "Log viewer connected")

    try:
        # Send existing logs
        logger.info(f"[DEBUG] Sending {len(log_buffer)} buffered logs to new client")
        for log in log_buffer:
            await websocket.send_json(log)

        # Keep connection alive with heartbeat and idle timeout
        # The emit_log function will send new logs to all connected clients
        # We just need to keep this connection alive by sending periodic pings
        idle_timeout_task = None
        last_activity = datetime.now(timezone.utc)
        
        while True:
            try:
                # Send ping every 30 seconds to keep connection alive
                await asyncio.sleep(30)
                
                # Check for idle timeout (client hasn't received messages in WEBSOCKET_IDLE_TIMEOUT seconds)
                now = datetime.now(timezone.utc)
                if (now - last_activity).total_seconds() > WEBSOCKET_IDLE_TIMEOUT:
                    logger.info(f"[DEBUG] WebSocket idle timeout: {websocket.client}")
                    break
                
                await websocket.send_json({"type": "ping", "timestamp": now.isoformat()})
                last_activity = now
            except asyncio.CancelledError:
                logger.info(f"[DEBUG] WebSocket cancelled: {websocket.client}")
                raise
            except Exception as e:
                logger.error(f"[DEBUG] Error in logs WebSocket loop: {e}")
                break

    except WebSocketDisconnect:
        logger.info(f"[DEBUG] WebSocket disconnected")
    except Exception as e:
        logger.error(f"[DEBUG] WebSocket error: {e}")
    finally:
        # Ensure proper cleanup of WebSocket connection
        if websocket in log_websockets:
            log_websockets.remove(websocket)
            logger.info(f"[DEBUG] Removed WebSocket from list. Remaining: {len(log_websockets)}")
        
        # Clean up any references
        try:
            await websocket.close()
        except Exception:
            pass  # Already closed
        
        # Don't emit log here as it might cause issues during shutdown


@app.get("/api/settings/version", response_model=VersionInfo)
async def get_version(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get yt-dlp and app version"""
    try:
        result = subprocess.run(
            ["yt-dlp", "--version"],
            capture_output=True,
            text=True
        )
        ytdlp_version = result.stdout.strip()
    except Exception:
        ytdlp_version = "unknown"

    return VersionInfo(
        ytdlp_version=ytdlp_version,
        app_version=APP_VERSION
    )


@app.get("/api/settings/disk-space", response_model=DiskSpaceInfo)
async def get_disk_space():
    """Get disk space information for downloads directory only"""
    downloads_path = Path("downloads")
    
    # Calculate total space used by files in downloads folder
    used_space = 0
    if downloads_path.exists():
        for item in downloads_path.rglob("*"):
            if item.is_file():
                used_space += item.stat().st_size
    
    # Get total available space on the volume containing downloads
    stat = shutil.disk_usage("downloads")
    free_space = stat.free
    total_space = used_space + free_space
    
    return DiskSpaceInfo(
        total=total_space,
        used=used_space,
        free=free_space,
        percent=(used_space / total_space * 100) if total_space > 0 else 0
    )


@app.get("/api/cookies")
async def get_cookies(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get list of available cookie files"""
    try:
        if not os.path.exists("cookies"):
            return []

        cookie_files = [f for f in os.listdir("cookies") if f.endswith('.txt')]
        await emit_log("INFO", "API", f"Cookie files requested, found {len(cookie_files)} files")
        return cookie_files

    except Exception as e:
        await emit_log("ERROR", "API", f"Failed to list cookie files: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/settings/queue")
async def get_queue_settings(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get queue and download settings"""
    return settings.get_all()


@app.post("/api/settings/queue")
async def update_queue_settings(updates: dict, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Update queue and download settings"""
    # Security: Validate settings
    is_valid, error_msg = validate_settings_update(updates)
    if not is_valid:
        await emit_log("WARNING", "System", f"Invalid settings update rejected: {error_msg}")
        raise HTTPException(status_code=400, detail=error_msg)

    settings.update(updates)
    await emit_log("INFO", "System", f"Queue settings updated: {updates}")
    return {"message": "Settings updated successfully", "settings": settings.get_all()}


@app.post("/api/settings/update-ytdlp")
async def update_ytdlp(current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    """
    Update yt-dlp to the latest version (ADMIN ONLY)

    WARNING: This endpoint is disabled by default for security reasons.
    To enable, set allow_ytdlp_update to true in admin_settings.json.
    """
    # Security: Disable dangerous system package updates by default
    admin_settings = get_admin_settings()
    allow_update = admin_settings.security.allow_ytdlp_update

    if not allow_update:
        await emit_log("WARNING", "System", "yt-dlp update blocked - feature disabled for security")
        raise HTTPException(
            status_code=403,
            detail="yt-dlp updates are disabled for security. Please contact your administrator to enable this feature."
        )

    try:
        await emit_log("INFO", "System", "Starting yt-dlp update")

        # Security: Use python3.12 -m pip instead of direct pip command
        # Security: Hardcode the package name to prevent injection
        result = subprocess.run(
            ["python3.12", "-m", "pip", "install", "--upgrade", "yt-dlp"],
            capture_output=True,
            text=True,
            timeout=60  # Security: Add timeout
        )

        if result.returncode == 0:
            await emit_log("SUCCESS", "System", "yt-dlp updated successfully")
            return {"message": "yt-dlp updated successfully", "output": result.stdout}
        else:
            await emit_log("ERROR", "System", f"yt-dlp update failed: {result.stderr}")
            raise HTTPException(status_code=500, detail=result.stderr)

    except subprocess.TimeoutExpired:
        await emit_log("ERROR", "System", "yt-dlp update timed out")
        raise HTTPException(status_code=500, detail="Update timed out")
    except Exception as e:
        await emit_log("ERROR", "System", f"yt-dlp update error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/settings/clear-ytdlp-cache")
async def clear_ytdlp_cache(current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    """
    Clear yt-dlp cache to resolve signature solving and format extraction issues (ADMIN ONLY).
    
    Useful when:
    - YouTube changes their signature algorithm
    - Format extraction fails with signature solving errors
    - Getting "Some formats may be missing" warnings
    
    This removes cached extractor data and forces yt-dlp to refresh on next use.
    """
    try:
        await emit_log("INFO", "System", "Starting yt-dlp cache cleanup")
        
        cache_dirs = []
        
        # Cache location 1: APPDATA\yt-dlp (Windows)
        appdata_cache = os.path.join(os.environ.get("APPDATA", ""), "yt-dlp")
        if appdata_cache and os.path.exists(appdata_cache):
            cache_dirs.append(appdata_cache)
        
        # Cache location 2: ~/.yt-dlp (Home directory)
        home_cache = os.path.expanduser("~/.yt-dlp")
        if os.path.exists(home_cache):
            cache_dirs.append(home_cache)
        
        # Cache location 3: ~/.config/yt-dlp (Linux/macOS)
        config_cache = os.path.expanduser("~/.config/yt-dlp")
        if os.path.exists(config_cache):
            cache_dirs.append(config_cache)
        
        cleared_count = 0
        for cache_dir in cache_dirs:
            try:
                shutil.rmtree(cache_dir)
                cleared_count += 1
                await emit_log("INFO", "System", f"Cleared yt-dlp cache: {cache_dir}")
            except Exception as e:
                await emit_log("WARNING", "System", f"Failed to clear cache {cache_dir}: {str(e)}")
        
        if cleared_count == 0:
            message = "No yt-dlp cache directories found"
            await emit_log("INFO", "System", message)
        else:
            message = f"Cleared {cleared_count} yt-dlp cache director(ies)"
            await emit_log("SUCCESS", "System", message)
        
        return {"message": message, "cleared": cleared_count}
    
    except Exception as e:
        await emit_log("ERROR", "System", f"yt-dlp cache cleanup error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/settings/cookies")
async def list_cookie_files(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    List all available cookie files in the cookies/ directory.
    Returns filename, size, and last modified time for each file.
    """
    try:
        cookies_dir = "cookies"
        if not os.path.exists(cookies_dir):
            os.makedirs(cookies_dir, mode=0o700, exist_ok=True)
            return {"cookies": []}

        cookie_files = []
        for filename in os.listdir(cookies_dir):
            # Only include .txt files
            if not filename.endswith('.txt'):
                continue

            filepath = os.path.join(cookies_dir, filename)
            if os.path.isfile(filepath):
                stat_info = os.stat(filepath)
                cookie_files.append({
                    "filename": filename,
                    "size": stat_info.st_size,
                    "modified": datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat()
                })

        # Sort by filename
        cookie_files.sort(key=lambda x: x['filename'])

        return {"cookies": cookie_files}

    except Exception as e:
        await emit_log("ERROR", "System", f"Failed to list cookie files: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/settings/cookies/upload")
async def upload_cookie_file(
    file: UploadFile = File(...),
    http_request: Request = None,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Upload a cookie file for authenticated downloads (ADMIN ONLY).
    Validates file size (max 100KB) and file type (.txt only).
    """
    # Get client IP for logging
    client_ip = getattr(http_request.state, 'client_ip', 'unknown') if http_request else 'unknown'

    # Validate filename
    if not file.filename or '..' in file.filename or '/' in file.filename or '\\' in file.filename:
        await emit_log("WARNING", "Cookies", f"Suspicious filename rejected from {client_ip}")
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Validate file extension (only .txt files)
    if not file.filename.endswith('.txt'):
        await emit_log("WARNING", "Cookies", f"Invalid file type rejected: {file.filename} from {client_ip}")
        raise HTTPException(status_code=400, detail="Only .txt files are allowed for cookies")

    # Validate filename using security module
    if not validate_cookie_filename(file.filename):
        await emit_log("WARNING", "Cookies", f"Invalid cookie filename: {file.filename} from {client_ip}")
        raise HTTPException(status_code=400, detail="Invalid cookie filename. Only alphanumeric characters, hyphens, underscores, and dots allowed.")

    # Validate file size (max 5KB)
    MAX_SIZE = 5 * 1024  # 5KB in bytes

    try:
        # Read the file content
        content = await file.read()

        if len(content) > MAX_SIZE:
            await emit_log("WARNING", "Cookies", f"Cookie file too large rejected from {client_ip}: {len(content)} bytes")
            raise HTTPException(
                status_code=413,
                detail=f"Cookie file too large. Maximum size is 5KB, file is {len(content) / 1024:.1f}KB"
            )

        # Ensure cookies directory exists
        cookies_dir = "cookies"
        if not os.path.exists(cookies_dir):
            os.makedirs(cookies_dir, mode=0o700, exist_ok=True)

        # Save the file
        filepath = os.path.join(cookies_dir, file.filename)
        with open(filepath, "wb") as f:
            f.write(content)

        # Set restrictive permissions (owner read/write only)
        os.chmod(filepath, 0o600)

        await emit_log("SUCCESS", "Cookies", f"Cookie file uploaded from {client_ip}: {file.filename} ({len(content)} bytes)")

        return {
            "message": f"Cookie file '{file.filename}' uploaded successfully",
            "filename": file.filename,
            "size": len(content)
        }

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "Cookies", f"Failed to upload cookie file from {client_ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload cookie file: {str(e)}")


@app.delete("/api/settings/cookies/{filename}")
async def delete_cookie_file(filename: str, http_request: Request = None, current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    """
    Delete a cookie file from the cookies/ directory (ADMIN ONLY).
    Validates filename to prevent path traversal attacks.
    """
    # Get client IP for logging
    client_ip = getattr(http_request.state, 'client_ip', 'unknown') if http_request else 'unknown'

    # Validate filename
    if '..' in filename or '/' in filename or '\\' in filename:
        await emit_log("WARNING", "Cookies", f"Path traversal attempt from {client_ip}: {filename}")
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.endswith('.txt'):
        await emit_log("WARNING", "Cookies", f"Invalid file type deletion attempt from {client_ip}: {filename}")
        raise HTTPException(status_code=400, detail="Invalid file type")

    if not validate_cookie_filename(filename):
        await emit_log("WARNING", "Cookies", f"Invalid cookie filename deletion attempt from {client_ip}: {filename}")
        raise HTTPException(status_code=400, detail="Invalid filename")

    try:
        filepath = os.path.join("cookies", filename)

        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="Cookie file not found")

        # Delete the file
        os.remove(filepath)

        await emit_log("SUCCESS", "Cookies", f"Cookie file deleted by {client_ip}: {filename}")

        return {"message": f"Cookie file '{filename}' deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "Cookies", f"Failed to delete cookie file from {client_ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete cookie file: {str(e)}")


@app.get("/api/files/thumbnail/{download_id}")
async def get_thumbnail(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Serve thumbnail images using download ID"""
    # Look up the download record to get internal_thumbnail filename
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    if not download.internal_thumbnail:
        raise HTTPException(status_code=404, detail="Thumbnail not found")

    # Use internal_thumbnail (UUID-based) for file access
    filepath = os.path.join("downloads", download.internal_thumbnail)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Thumbnail file not found")

    # Security: Verify file extension
    ext = os.path.splitext(download.internal_thumbnail)[1].lower()
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.webp'}
    if ext not in allowed_extensions:
        await emit_log("WARNING", "API", f"Disallowed file extension: {ext}")
        raise HTTPException(status_code=403, detail="File type not allowed")

    from fastapi.responses import FileResponse
    media_types = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.webp': 'image/webp'
    }
    media_type = media_types.get(ext, 'image/jpeg')

    return FileResponse(filepath, media_type=media_type)


@app.get("/api/files/video/{download_id}")
async def get_video(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Serve video files for streaming/playing in browser using download ID"""
    # Look up the download record to get internal_filename
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    if not download.internal_filename:
        raise HTTPException(status_code=404, detail="Video file not found")

    # Use internal_filename (UUID-based) for file access
    filepath = os.path.join("downloads", download.internal_filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Video file not found on disk")

    # Security: Verify file extension
    ext = os.path.splitext(download.internal_filename)[1].lower()
    allowed_extensions = {'.mp4', '.webm', '.mkv', '.avi', '.mov', '.flv', '.wmv', '.m4v'}
    if ext not in allowed_extensions:
        await emit_log("WARNING", "API", f"Disallowed file extension: {ext}")
        raise HTTPException(status_code=403, detail="File type not allowed")

    from fastapi.responses import FileResponse
    media_types = {
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.mkv': 'video/x-matroska',
        '.avi': 'video/x-msvideo',
        '.mov': 'video/quicktime'
    }
    media_type = media_types.get(ext, 'video/mp4')

    return FileResponse(filepath, media_type=media_type)


@app.get("/api/files/download/{download_id}")
async def download_file(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Download video file using download ID"""
    # Look up the download record to get internal_filename and display filename
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    if not download.internal_filename:
        raise HTTPException(status_code=404, detail="File not found")

    # Use internal_filename (UUID-based) for file access
    filepath = os.path.join("downloads", download.internal_filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found on disk")

    from fastapi.responses import FileResponse
    # Use display filename (filename field) for the downloaded file name
    return FileResponse(filepath, filename=download.filename, media_type='application/octet-stream')


@app.get("/api/files", response_model=List[FileInfo])
async def list_files(current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """List all completed downloads with their display filenames and sizes"""
    try:
        # Get all completed downloads from database
        completed_downloads = DatabaseService.get_downloads_by_status(db, DownloadStatus.COMPLETED)

        files = []
        for download in completed_downloads:
            if download.filename and download.file_size and download.internal_filename:
                files.append(FileInfo(
                    id=download.id,
                    filename=download.filename,  # Display name
                    size=download.file_size
                ))

        # Sort by filename alphabetically
        files.sort(key=lambda x: x.filename.lower())

        await emit_log("INFO", "API", f"File list requested, found {len(files)} completed downloads")
        return files

    except Exception as e:
        await emit_log("ERROR", "API", f"Failed to list files: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/files/{download_id}")
async def delete_file(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Delete a specific file from downloads directory and remove database entry using download ID"""
    try:
        # Look up the download record
        download = DatabaseService.get_download_by_id(db, download_id)
        if not download:
            raise HTTPException(status_code=404, detail="Download not found")

        display_name = download.filename or "unknown"
        file_size = 0

        # Delete video file if it exists
        if download.internal_filename:
            filepath = os.path.join("downloads", download.internal_filename)
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                os.remove(filepath)
                await emit_log("SUCCESS", "API", f"File deleted: {display_name} ({file_size} bytes)")
            else:
                await emit_log("WARNING", "API", f"File not found on disk: {download.internal_filename}")

        # Delete thumbnail if it exists
        if download.internal_thumbnail:
            thumb_path = os.path.join("downloads", download.internal_thumbnail)
            if os.path.exists(thumb_path):
                try:
                    os.remove(thumb_path)
                    await emit_log("INFO", "API", f"Deleted associated thumbnail: {download.internal_thumbnail}")
                except Exception as e:
                    await emit_log("WARNING", "API", f"Failed to delete thumbnail: {str(e)}")

        # Delete database entry
        DatabaseService.delete_download(db, download_id)
        await emit_log("SUCCESS", "API", f"Deleted database entry for download: {download_id}")

        return {"message": "File deleted successfully", "filename": display_name, "size": file_size}

    except HTTPException:
        raise
    except Exception as e:
        display_name = download.filename if 'download' in locals() else "unknown"
        await emit_log("ERROR", "API", f"Failed to delete file {display_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/files/calculate-zip-size")
async def calculate_zip_size(request: DownloadZipRequest, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Calculate total size of selected files and estimate ZIP size using download IDs"""
    try:
        if not request.download_ids:
            raise HTTPException(status_code=400, detail="No files specified")

        total_size = 0
        valid_files = 0

        for download_id in request.download_ids:
            # Look up download record
            download = DatabaseService.get_download_by_id(db, download_id)
            if not download or not download.internal_filename:
                continue

            filepath = os.path.join("downloads", download.internal_filename)
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)
                valid_files += 1

        # Get average compression ratio from settings
        compression_ratio = settings.get("zip_avg_compression_ratio", 0.70)
        estimated_zip_size = int(total_size * compression_ratio)

        return {
            "total_size": total_size,
            "estimated_zip_size": estimated_zip_size,
            "compression_ratio": compression_ratio,
            "file_count": valid_files
        }

    except Exception as e:
        await emit_log("ERROR", "API", f"Failed to calculate ZIP size: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/files/download-zip")
async def download_files_as_zip(request: DownloadZipRequest, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Create and stream a ZIP file containing selected files using download IDs"""
    try:
        if not request.download_ids:
            raise HTTPException(status_code=400, detail="No files specified")

        await emit_log("INFO", "API", f"Creating streaming ZIP with {len(request.download_ids)} file(s)")

        # Preload download records to avoid database access in generator
        downloads_map = {}
        for download_id in request.download_ids:
            download = DatabaseService.get_download_by_id(db, download_id)
            if download and download.internal_filename and download.filename:
                downloads_map[download_id] = {
                    'internal_filename': download.internal_filename,
                    'display_filename': download.filename
                }

        # Generator function to stream ZIP file
        def generate_zip():
            total_original_size = 0
            total_compressed_size = 0

            # Create ZIP file that writes directly to output
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for download_id, file_info in downloads_map.items():
                    internal_filename = file_info['internal_filename']
                    display_filename = file_info['display_filename']
                    filepath = os.path.join("downloads", internal_filename)

                    if not os.path.exists(filepath):
                        continue

                    # Track original size
                    original_size = os.path.getsize(filepath)
                    total_original_size += original_size

                    # Add file to ZIP using display filename (user-friendly name)
                    zip_file.write(filepath, display_filename)

            # Get the final ZIP size
            zip_buffer.seek(0)
            zip_data = zip_buffer.getvalue()
            total_compressed_size = len(zip_data)

            # Update compression ratio statistics asynchronously
            if total_original_size > 0:
                actual_ratio = total_compressed_size / total_original_size
                update_compression_stats(actual_ratio)

            # Yield the ZIP data in chunks
            chunk_size = 8192
            for i in range(0, len(zip_data), chunk_size):
                yield zip_data[i:i + chunk_size]

        from fastapi.responses import StreamingResponse
        return StreamingResponse(
            generate_zip(),
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename=videos-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.zip"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "API", f"Failed to create ZIP: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ========================================
# Tool Conversion API Endpoints
# ========================================

@app.post("/api/tools/video-to-mp3", response_model=ToolConversionResponse)
async def convert_video_to_mp3(request: VideoToMp3Request, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    Start a video to MP3 conversion.
    Checks for existing conversion to prevent duplicates.
    """
    try:
        # Validate audio quality
        valid_qualities = [96, 128, 192, 256, 320]
        if request.audio_quality not in valid_qualities:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid audio quality. Must be one of: {valid_qualities}"
            )

        # Get source download
        download = DatabaseService.get_download_by_id(db, request.source_download_id)
        if not download:
            raise HTTPException(status_code=404, detail="Source video not found")

        if download.status != DownloadStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Source video download not completed")

        # Check if conversion already exists
        existing = db.query(ToolConversion).filter(
            ToolConversion.source_download_id == request.source_download_id,
            ToolConversion.tool_type == "video_to_mp3",
            ToolConversion.status == ConversionStatus.COMPLETED
        ).first()

        if existing:
            await emit_log("INFO", "ToolConversion",
                         f"Returning existing MP3 conversion for {download.filename}",
                         existing.id)
            return existing

        # Build source and output paths
        source_path = os.path.join("downloads", download.internal_filename)
        if not os.path.exists(source_path):
            raise HTTPException(status_code=404, detail="Source video file not found on disk")

        # Generate UUID for output file
        output_uuid = str(uuid.uuid4())
        output_internal_filename = f"{output_uuid}.mp3"
        output_path = os.path.join("downloads", output_internal_filename)

        # Generate display filename
        base_name = os.path.splitext(download.filename)[0]
        output_display_filename = f"{base_name}.mp3"

        # Create conversion record
        conversion = ToolConversion(
            source_download_id=request.source_download_id,
            tool_type="video_to_mp3",
            status=ConversionStatus.QUEUED,
            progress=0.0,
            output_filename=output_display_filename,
            internal_output_filename=output_internal_filename,
            audio_quality=request.audio_quality
        )

        db.add(conversion)
        db.commit()
        db.refresh(conversion)

        await emit_log("INFO", "ToolConversion",
                     f"Queued MP3 conversion: {download.filename} -> {output_display_filename}",
                     conversion.id)

        # Add to conversion queue
        await conversion_queue.add_to_queue(
            job_type="mp3",
            conversion_id=conversion.id,
            source_path=source_path,
            output_path=output_path,
            bitrate=request.audio_quality
        )

        return conversion

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to queue MP3 conversion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools/conversions", response_model=List[ToolConversionResponse])
async def list_conversions(status: Optional[str] = None, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    List all tool conversions, optionally filtered by status.
    """
    try:
        query = db.query(ToolConversion)

        if status:
            try:
                status_enum = ConversionStatus(status)
                query = query.filter(ToolConversion.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid status value")

        conversions = query.order_by(ToolConversion.created_at.desc()).all()
        return conversions

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to list conversions: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools/conversions/{conversion_id}", response_model=ToolConversionResponse)
async def get_conversion(conversion_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    Get specific conversion status by ID.
    """
    try:
        conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
        if not conversion:
            raise HTTPException(status_code=404, detail="Conversion not found")

        return conversion

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to get conversion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/tools/conversions/{conversion_id}")
async def delete_conversion(conversion_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    Delete a conversion and its output file.
    """
    try:
        conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
        if not conversion:
            raise HTTPException(status_code=404, detail="Conversion not found")

        # Delete output file if it exists
        if conversion.internal_output_filename:
            output_path = os.path.join("downloads", conversion.internal_output_filename)
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                    await emit_log("INFO", "ToolConversion",
                                 f"Deleted audio file: {conversion.output_filename}",
                                 conversion_id)
                except Exception as e:
                    await emit_log("WARNING", "ToolConversion",
                                 f"Failed to delete audio file: {str(e)}",
                                 conversion_id)

        # Delete database record
        db.delete(conversion)
        db.commit()

        await emit_log("INFO", "ToolConversion",
                     f"Deleted conversion record: {conversion.output_filename}",
                     conversion_id)

        return {"message": "Conversion deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to delete conversion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/conversions/{conversion_id}/cancel")
async def cancel_conversion(conversion_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    Cancel an active conversion job.
    Kills the FFmpeg process, cleans up partial files, and marks as failed.
    """
    try:
        conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
        if not conversion:
            raise HTTPException(status_code=404, detail="Conversion not found")

        # Check if conversion is actually active
        if conversion.status not in [ConversionStatus.QUEUED, ConversionStatus.CONVERTING]:
            raise HTTPException(status_code=400, detail="Conversion is not active")

        # Check if process is currently running
        if conversion_id in active_conversion_processes:
            process, temp_file_path = active_conversion_processes[conversion_id]

            # Kill the FFmpeg process
            try:
                process.terminate()
                # Wait briefly for graceful termination
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    # Force kill if it doesn't terminate gracefully
                    process.kill()
                    await process.wait()

                await emit_log("INFO", "ConversionQueue",
                             f"Killed FFmpeg process for conversion {conversion_id[:8]}...",
                             conversion_id)
            except Exception as e:
                await emit_log("WARNING", "ConversionQueue",
                             f"Error killing process: {str(e)}",
                             conversion_id)

            # Clean up temporary/partial files
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    await emit_log("INFO", "ConversionQueue",
                                 f"Removed partial file: {temp_file_path}",
                                 conversion_id)
                except Exception as e:
                    await emit_log("WARNING", "ConversionQueue",
                                 f"Failed to remove partial file: {str(e)}",
                                 conversion_id)

            # Remove from active processes tracking
            del active_conversion_processes[conversion_id]

        # Mark conversion as failed in database
        conversion.status = ConversionStatus.FAILED
        conversion.error_message = "Cancelled by user"
        conversion.completed_at = datetime.now(timezone.utc)
        db.commit()

        await emit_log("INFO", "ConversionQueue",
                     f"Conversion cancelled by user: {conversion.output_filename}",
                     conversion_id)

        return {
            "message": "Conversion cancelled successfully",
            "conversion_id": conversion_id
        }

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ConversionQueue", f"Failed to cancel conversion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools/audio/{conversion_id}")
async def download_audio(conversion_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    Stream/download the MP3 audio file for a completed conversion.
    """
    try:
        conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
        if not conversion:
            raise HTTPException(status_code=404, detail="Conversion not found")

        if conversion.status != ConversionStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Conversion not completed yet")

        if not conversion.internal_output_filename:
            raise HTTPException(status_code=404, detail="Audio file not found")

        filepath = os.path.join("downloads", conversion.internal_output_filename)
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="Audio file not found on disk")

        await emit_log("INFO", "ToolConversion",
                     f"Serving audio file: {conversion.output_filename}",
                     conversion_id)

        from fastapi.responses import FileResponse
        return FileResponse(
            filepath,
            media_type="audio/mpeg",
            filename=conversion.output_filename
        )

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to serve audio file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/conversions/cleanup", response_model=ConversionCleanupStats)
async def cleanup_stale_conversions(hours: int = 1, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """
    Clean up stale conversions that have been stuck in queued or converting state
    for longer than the specified number of hours.
    """
    try:
        await emit_log("INFO", "Cleanup", f"Starting cleanup of stale conversions older than {hours} hour(s)")

        # Calculate cutoff time
        from datetime import datetime, timezone, timedelta
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Find stale conversions (stuck in queued or converting state)
        stale_conversions = db.query(ToolConversion).filter(
            ToolConversion.status.in_([ConversionStatus.QUEUED, ConversionStatus.CONVERTING]),
            ToolConversion.created_at < cutoff_time
        ).all()

        conversions_removed = 0
        files_removed = 0
        space_freed = 0

        await emit_log("INFO", "Cleanup", f"Found {len(stale_conversions)} stale conversions to clean up")

        for conversion in stale_conversions:
            display_name = conversion.output_filename or "unknown"

            # Delete output file if it exists
            if conversion.internal_output_filename:
                output_path = os.path.join("downloads", conversion.internal_output_filename)
                if os.path.exists(output_path):
                    try:
                        size = os.path.getsize(output_path)
                        os.remove(output_path)
                        space_freed += size
                        files_removed += 1
                        await emit_log("INFO", "Cleanup",
                                     f"Removed stale conversion file: {display_name} ({size} bytes)",
                                     conversion.id)
                    except Exception as e:
                        await emit_log("ERROR", "Cleanup",
                                     f"Failed to remove file {display_name}: {str(e)}",
                                     conversion.id)

            # Delete database record
            db.delete(conversion)
            conversions_removed += 1
            await emit_log("INFO", "Cleanup",
                         f"Removed stale conversion record: {display_name} (stuck in {conversion.status})",
                         conversion.id)

        db.commit()

        await emit_log("SUCCESS", "Cleanup",
                     f"Cleanup complete: removed {conversions_removed} conversions, "
                     f"{files_removed} files, freed {space_freed} bytes")

        return ConversionCleanupStats(
            conversions_removed=conversions_removed,
            files_removed=files_removed,
            space_freed=space_freed
        )

    except Exception as e:
        await emit_log("ERROR", "Cleanup", f"Failed to cleanup stale conversions: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/transform")
async def transform_video(request: VideoTransformRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Queue a video transformation (flip or rotate).
    Creates a ToolConversion record and adds to processing queue.
    The transformation modifies the original video file in-place.
    Returns immediately with the conversion record - actual processing happens in background.
    """
    try:
        conversion = await VideoTransformService.transform_video(
            request.download_id,
            request.transform_type
        )
        return conversion

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "VideoTransform", f"Failed to queue video transformation: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


def update_compression_stats(ratio: float):
    """Update compression ratio statistics with new sample"""
    try:
        samples = settings.get("zip_compression_samples", [])

        # Add new sample
        samples.append(ratio)

        # Keep only last 10 samples for rolling average
        if len(samples) > 10:
            samples = samples[-10:]

        # Calculate new average
        avg_ratio = sum(samples) / len(samples)

        # Update settings
        settings.set("zip_compression_samples", samples)
        settings.set("zip_avg_compression_ratio", avg_ratio)

    except Exception:
        pass  # Don't fail the download if stats update fails


# Hardware Information Detection
def get_cpu_info():
    """Get CPU information"""
    try:
        cpu_info = {
            "model": platform.processor() or "Unknown",
            "architecture": platform.machine(),
            "cores": os.cpu_count() or 1
        }

        # Try to get more detailed CPU info on Linux
        if os.path.exists("/proc/cpuinfo"):
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    # Extract model name
                    model_match = re.search(r"model name\s*:\s*(.+)", cpuinfo)
                    if model_match:
                        cpu_info["model"] = model_match.group(1).strip()
            except:
                pass

        return cpu_info
    except Exception as e:
        logger.error(f"Failed to get CPU info: {e}")
        return {"model": "Unknown", "architecture": "Unknown", "cores": 1}


def get_memory_info():
    """Get memory information in MB"""
    try:
        # Try Linux /proc/meminfo first
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r") as f:
                meminfo = f.read()

                # Extract total and available memory
                total_match = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
                available_match = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo)

                if total_match:
                    total_mb = int(total_match.group(1)) / 1024
                    available_mb = int(available_match.group(1)) / 1024 if available_match else 0
                    used_mb = total_mb - available_mb

                    return {
                        "total_mb": round(total_mb, 2),
                        "used_mb": round(used_mb, 2),
                        "available_mb": round(available_mb, 2),
                        "usage_percent": round((used_mb / total_mb) * 100, 1) if total_mb > 0 else 0
                    }

        # Fallback - return basic info
        return {
            "total_mb": 0,
            "used_mb": 0,
            "available_mb": 0,
            "usage_percent": 0
        }
    except Exception as e:
        logger.error(f"Failed to get memory info: {e}")
        return {"total_mb": 0, "used_mb": 0, "available_mb": 0, "usage_percent": 0}


def get_disk_info():
    """Get disk information for downloads directory"""
    try:
        disk_usage = shutil.disk_usage("downloads")
        total_gb = disk_usage.total / (1024 ** 3)
        used_gb = disk_usage.used / (1024 ** 3)
        free_gb = disk_usage.free / (1024 ** 3)

        return {
            "total_gb": round(total_gb, 2),
            "used_gb": round(used_gb, 2),
            "free_gb": round(free_gb, 2),
            "usage_percent": round((used_gb / total_gb) * 100, 1) if total_gb > 0 else 0
        }
    except Exception as e:
        logger.error(f"Failed to get disk info: {e}")
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "usage_percent": 0}


def get_network_info():
    """Get network interface information"""
    try:
        interfaces = []

        # Try Linux /sys/class/net
        if os.path.exists("/sys/class/net"):
            net_dir = "/sys/class/net"
            for iface in os.listdir(net_dir):
                # Skip loopback
                if iface == "lo":
                    continue

                iface_info = {"name": iface}

                # Get MAC address
                mac_file = os.path.join(net_dir, iface, "address")
                if os.path.exists(mac_file):
                    with open(mac_file, "r") as f:
                        iface_info["mac"] = f.read().strip()

                # Get interface state
                state_file = os.path.join(net_dir, iface, "operstate")
                if os.path.exists(state_file):
                    with open(state_file, "r") as f:
                        iface_info["state"] = f.read().strip()

                # Get speed if available
                speed_file = os.path.join(net_dir, iface, "speed")
                if os.path.exists(speed_file):
                    try:
                        with open(speed_file, "r") as f:
                            speed = f.read().strip()
                            if speed != "-1":
                                iface_info["speed_mbps"] = int(speed)
                    except:
                        pass

                interfaces.append(iface_info)

        return interfaces
    except Exception as e:
        logger.error(f"Failed to get network info: {e}")
        return []


async def detect_hardware_acceleration():
    """
    Detect available hardware acceleration for FFmpeg.
    Checks for NVIDIA NVENC, AMD AMF, Intel Quick Sync (QSV), and VAAPI.
    """
    acceleration = {
        "nvenc": False,      # NVIDIA GPU encoding
        "amf": False,        # AMD GPU encoding
        "qsv": False,        # Intel Quick Sync Video
        "vaapi": False,      # Video Acceleration API (Linux)
        "videotoolbox": False,  # Apple VideoToolbox (macOS)
        "detected_encoders": []
    }

    try:
        # Run ffmpeg -encoders to get list of available encoders
        process = await asyncio.create_subprocess_exec(
            'ffmpeg', '-hide_banner', '-encoders',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)
        encoders_output = stdout.decode()

        # Check for hardware acceleration encoder support
        detected = []

        # NVIDIA NVENC (h264_nvenc, hevc_nvenc)
        if 'h264_nvenc' in encoders_output or 'hevc_nvenc' in encoders_output:
            acceleration["nvenc"] = True
            detected.append("NVIDIA NVENC")

        # AMD AMF (h264_amf, hevc_amf)
        if 'h264_amf' in encoders_output or 'hevc_amf' in encoders_output:
            acceleration["amf"] = True
            detected.append("AMD AMF")

        # Intel Quick Sync (h264_qsv, hevc_qsv)
        if 'h264_qsv' in encoders_output or 'hevc_qsv' in encoders_output:
            acceleration["qsv"] = True
            detected.append("Intel Quick Sync")

        # VAAPI (h264_vaapi, hevc_vaapi)
        if 'h264_vaapi' in encoders_output or 'hevc_vaapi' in encoders_output:
            acceleration["vaapi"] = True
            detected.append("VAAPI")

        # VideoToolbox (h264_videotoolbox, hevc_videotoolbox)
        if 'h264_videotoolbox' in encoders_output or 'hevc_videotoolbox' in encoders_output:
            acceleration["videotoolbox"] = True
            detected.append("VideoToolbox")

        acceleration["detected_encoders"] = detected

    except Exception as e:
        logger.error(f"Failed to detect hardware acceleration: {e}")

    return acceleration


async def collect_hardware_info():
    """
    Collect all hardware information for caching.
    This is called at startup and when the user clicks refresh.
    Returns a complete hardware info dict that clients cache in localStorage.
    """
    try:
        cpu_info = get_cpu_info()
        memory_info = get_memory_info()
        disk_info = get_disk_info()
        network_info = get_network_info()

        # Use the global hardware_acceleration if already detected, otherwise detect
        global hardware_acceleration
        if hardware_acceleration.get("detected_encoders"):
            acceleration = hardware_acceleration
        else:
            acceleration = await detect_hardware_acceleration()

        return {
            "cpu": cpu_info,
            "memory": memory_info,
            "disk": disk_info,
            "network": network_info,
            "acceleration": acceleration,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version()
            }
        }
    except Exception as e:
        logger.error(f"Failed to collect hardware info: {e}")
        raise


@app.get("/api/hardware/info")
async def get_hardware_info(current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    """
    Get server hardware information (returns cached data).
    Cache is populated at startup and refreshed via POST /api/hardware/refresh.
    Clients should cache this in localStorage and only fetch once per session.
    (ADMIN ONLY)
    """
    global hardware_info_cache

    # If cache is empty (shouldn't happen after startup), populate it
    if hardware_info_cache is None:
        hardware_info_cache = await collect_hardware_info()

    return hardware_info_cache


@app.post("/api/hardware/refresh")
async def refresh_hardware_info(current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    """
    Refresh hardware information cache (ADMIN ONLY).
    Called when user clicks the "Refresh Hardware Info" button.
    Re-detects all hardware and updates the server cache.
    """
    global hardware_info_cache, hardware_acceleration

    try:
        # Re-detect everything
        hardware_info_cache = await collect_hardware_info()

        # Update the global acceleration cache for FFmpeg
        hardware_acceleration = hardware_info_cache["acceleration"]

        await emit_log("INFO", "System", "Hardware information refreshed")

        return hardware_info_cache
    except Exception as e:
        logger.error(f"Failed to refresh hardware info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
