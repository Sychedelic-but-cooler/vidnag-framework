"""
Video Downloader API - Main Application
A FastAPI-based web application for downloading videos using yt-dlp.
Provides a web interface for managing video downloads with queue management,
file browsing, and comprehensive logging.
"""

# FastAPI and web framework imports
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Data validation and database
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

# Date and time handling (always use timezone-aware datetimes)
from datetime import datetime, timedelta, timezone

# Type hints for better code clarity
from typing import Optional, List
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

# Application modules
from database import init_db, get_db_session, Download, DownloadStatus, ToolConversion, ConversionStatus, get_db
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
    Set appropriate file permissions on critical application directories.
    
    Ensures:
    - downloads/ directory: readable/writable by app, readable by others (755)
    - logs/ directory: readable/writable by app, readable by others (755)
    - data.db: readable/writable by app only (600)
    - cookies/ directory: readable/writable by app (700)
    - admin_settings.json: readable/writable by app (600)
    
    Permissions work correctly on Linux/macOS. Windows NTFS has different 
    permission model but these settings don't harm and ensure cross-platform compatibility.
    """
    try:
        import stat
        
        # Directories that should be 755 (rwxr-xr-x)
        # Owner can read/write/execute, others can read/execute
        rwx_r_r_dirs = ["downloads", "logs", "assets", "backups"]
        
        for dir_path in rwx_r_r_dirs:
            if os.path.exists(dir_path):
                try:
                    os.chmod(dir_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                    logger.debug(f"Set permissions 755 on {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {dir_path}: {e}")
        
        # Directories that should be 700 (rwx------)
        # Owner can read/write/execute, others cannot access
        rwx_only_dirs = ["cookies"]
        
        for dir_path in rwx_only_dirs:
            if os.path.exists(dir_path):
                try:
                    os.chmod(dir_path, stat.S_IRWXU)
                    logger.debug(f"Set permissions 700 on {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {dir_path}: {e}")
        
        # Files that should be 600 (rw-------)
        # Owner can read/write, others cannot access
        rw_only_files = ["data.db", "admin_settings.json"]
        
        for file_path in rw_only_files:
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
    os.makedirs("downloads", exist_ok=True)  # Ensure download directory exists
    os.makedirs("cookies", exist_ok=True)    # Ensure cookies directory exists

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

    # Start the conversion queue processor
    conversion_queue.start_processing()

    # Log startup information for diagnostics
    await emit_log("INFO", "System", "Application started successfully")
    await emit_log("INFO", "System", f"Download queue started (max concurrent: {settings.get('max_concurrent_downloads', 2)})")
    await emit_log("INFO", "System", f"Conversion queue started (max concurrent: {settings.get('max_concurrent_conversions', 2)})")
    await emit_log("INFO", "System", f"Python version: {os.sys.version}")
    await emit_log("INFO", "System", f"Working directory: {os.getcwd()}")
    await emit_log("INFO", "System", "Log files: rotated daily, kept for 3 days in logs/ directory")

    # Yield control back to FastAPI - application runs normally from here
    yield

    # Shutdown sequence - runs when the application stops
    # Currently no cleanup needed, but this is where it would go
    pass

# Create the FastAPI application instance with our lifespan handler
app = FastAPI(title="Video Downloader API", lifespan=lifespan)

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
    '%(asctime)s - %(levelname)s - [%(component)s] %(message)s',
    defaults={'component': 'System'}
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

# WebSocket connection storage (currently not used, kept for future use)
active_connections: dict[str, list[WebSocket]] = {}
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
        await emit_log("ERROR", "Download", f"Download exceeded timeout ({DOWNLOAD_TIMEOUT_SECONDS}s) - terminated", download_id)
        # The download_video method's exception handler will mark as failed
        # Any subprocess is already terminated by asyncio.wait_for


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
    Manages the MP3 conversion queue with concurrent conversion limiting.
    Ensures only a limited number of conversions run simultaneously
    to prevent resource exhaustion.
    """

    def __init__(self):
        # AsyncIO queue for pending conversions
        self.queue: asyncio.Queue = asyncio.Queue()

        # Set of currently running conversion IDs
        self.active_conversions: set = set()

        # Background task that processes the queue
        self.processing_task: Optional[asyncio.Task] = None

    async def add_to_queue(self, conversion_id: str, source_path: str, output_path: str, bitrate: int):
        """
        Add a conversion to the queue.
        Conversions are processed in FIFO order when capacity is available.
        """
        await self.queue.put((conversion_id, source_path, output_path, bitrate))
        await emit_log("INFO", "ConversionQueue",
                     f"Conversion {conversion_id[:8]}... added to queue. Queue size: {self.queue.qsize()}",
                     conversion_id)

    async def process_queue(self):
        """
        Continuously process conversions from the queue.
        Respects max_concurrent_conversions setting and disk space limits.
        This runs as a background task for the entire application lifetime.
        """
        while True:
            try:
                # Wait for a conversion to be added to the queue (blocking)
                conversion_id, source_path, output_path, bitrate = await self.queue.get()

                # Wait until we have capacity for another conversion
                # Default to 2 concurrent conversions
                max_concurrent = settings.get("max_concurrent_conversions", 2)
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
                             f"Starting conversion {conversion_id[:8]}... ({len(self.active_conversions)}/{max_concurrent} active)",
                             conversion_id)

                # Create a new async task for the conversion (runs in background)
                asyncio.create_task(self._conversion_wrapper(conversion_id, source_path, output_path, bitrate))

                # Mark this queue item as processed
                self.queue.task_done()

            except Exception as e:
                # Log queue processing errors and continue
                await emit_log("ERROR", "ConversionQueue", f"Queue processing error: {str(e)}")
                await asyncio.sleep(1)

    async def _conversion_wrapper(self, conversion_id: str, source_path: str, output_path: str, bitrate: int):
        """
        Wrapper around the actual conversion function.
        Ensures the conversion is always removed from active_conversions
        even if the conversion fails or throws an exception.
        """
        try:
            await ToolConversionService.convert_video_to_mp3(conversion_id, source_path, output_path, bitrate)
        except Exception as e:
            logger.error(f"Conversion wrapper error for {conversion_id}: {e}")
        finally:
            # Always remove from active conversions, even if conversion failed
            self.active_conversions.discard(conversion_id)
            await emit_log("INFO", "ConversionQueue",
                         f"Conversion {conversion_id[:8]}... finished. Active conversions: {len(self.active_conversions)}",
                         conversion_id)

    def start_processing(self):
        """
        Start the background queue processor task.
        Called once during application startup.
        """
        if self.processing_task is None or self.processing_task.done():
            self.processing_task = asyncio.create_task(self.process_queue())


# Global conversion queue manager instance
conversion_queue = ConversionQueueManager()


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
    created_at: datetime
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
                    await emit_log(level, "YT-DLP-ERR", line_str, download_id)

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
            # Mark conversion as failed
            with get_db() as db:
                conversion = db.query(ToolConversion).filter(ToolConversion.id == conversion_id).first()
                if conversion:
                    conversion.status = ConversionStatus.FAILED
                    conversion.error_message = str(e)
                    db.commit()

            await emit_log("ERROR", "ToolConversion",
                         f"MP3 conversion failed: {str(e)}", conversion_id)


# Video Transform Service - Handles video flipping and rotation
class VideoTransformService:
    @staticmethod
    async def transform_video(download_id: str, transform_type: str):
        """
        Apply transformation to video using FFmpeg (in-place).
        Creates a ToolConversion record to track progress.

        Args:
            download_id: UUID of the download record
            transform_type: Type of transformation (hflip, vflip, rotate90, rotate180, rotate270)

        Returns:
            dict: Success message, updated file info, and conversion ID
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

            # Run FFmpeg transformation with progress output
            process = await asyncio.create_subprocess_exec(
                'ffmpeg', '-y',
                '-i', source_path,
                '-vf', vf_filter,
                '-c:a', 'copy',  # Copy audio without re-encoding
                '-progress', 'pipe:1',  # Progress to stdout
                temp_output_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

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

            return {
                "success": True,
                "message": "Video transformed successfully",
                "new_file_size": new_file_size,
                "conversion_id": conversion_id
            }

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
            raise HTTPException(status_code=500, detail=f"Transformation failed: {str(e)}")


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


# API Endpoints

@app.get("/")
async def root():
    """Serve the main HTML page"""
    with open("assets/index.html") as f:
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=f.read())


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
async def start_download(request: DownloadRequest, http_request: Request, db: Session = Depends(get_db_session)):
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
async def get_downloads(status: Optional[str] = None, db: Session = Depends(get_db_session)):
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
async def get_download(download_id: str, db: Session = Depends(get_db_session)):
    """Get a specific download by ID"""
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")
    return download


@app.delete("/api/downloads/{download_id}")
async def delete_download(download_id: str, db: Session = Depends(get_db_session)):
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
async def cleanup_downloads(days: int = 7, db: Session = Depends(get_db_session)):
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
    since_sequence: Optional[int] = None
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
async def get_version():
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
        app_version="1.0.0"
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
async def get_cookies():
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
async def get_queue_settings():
    """Get queue and download settings"""
    return settings.get_all()


@app.post("/api/settings/queue")
async def update_queue_settings(updates: dict):
    """Update queue and download settings"""
    # Security: Validate settings
    is_valid, error_msg = validate_settings_update(updates)
    if not is_valid:
        await emit_log("WARNING", "Settings", f"Invalid settings update rejected: {error_msg}")
        raise HTTPException(status_code=400, detail=error_msg)

    settings.update(updates)
    await emit_log("INFO", "Settings", f"Queue settings updated: {updates}")
    return {"message": "Settings updated successfully", "settings": settings.get_all()}


@app.post("/api/settings/update-ytdlp")
async def update_ytdlp():
    """
    Update yt-dlp to the latest version

    WARNING: This endpoint is disabled by default for security reasons.
    To enable, set ALLOW_YTDLP_UPDATE=true environment variable.
    """
    # Security: Disable dangerous system package updates by default
    allow_update = os.environ.get("ALLOW_YTDLP_UPDATE", "false").lower() == "true"

    if not allow_update:
        await emit_log("WARNING", "Settings", "yt-dlp update blocked - feature disabled for security")
        raise HTTPException(
            status_code=403,
            detail="yt-dlp updates are disabled for security. Set ALLOW_YTDLP_UPDATE=true to enable."
        )

    try:
        await emit_log("INFO", "Settings", "Starting yt-dlp update")

        # Security: Use python3.12 -m pip instead of direct pip command
        # Security: Hardcode the package name to prevent injection
        result = subprocess.run(
            ["python3.12", "-m", "pip", "install", "--upgrade", "yt-dlp"],
            capture_output=True,
            text=True,
            timeout=60  # Security: Add timeout
        )

        if result.returncode == 0:
            await emit_log("SUCCESS", "Settings", "yt-dlp updated successfully")
            return {"message": "yt-dlp updated successfully", "output": result.stdout}
        else:
            await emit_log("ERROR", "Settings", f"yt-dlp update failed: {result.stderr}")
            raise HTTPException(status_code=500, detail=result.stderr)

    except subprocess.TimeoutExpired:
        await emit_log("ERROR", "Settings", "yt-dlp update timed out")
        raise HTTPException(status_code=500, detail="Update timed out")
    except Exception as e:
        await emit_log("ERROR", "Settings", f"yt-dlp update error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/settings/clear-ytdlp-cache")
async def clear_ytdlp_cache():
    """
    Clear yt-dlp cache to resolve signature solving and format extraction issues.
    
    Useful when:
    - YouTube changes their signature algorithm
    - Format extraction fails with signature solving errors
    - Getting "Some formats may be missing" warnings
    
    This removes cached extractor data and forces yt-dlp to refresh on next use.
    """
    try:
        await emit_log("INFO", "Settings", "Starting yt-dlp cache cleanup")
        
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
                await emit_log("INFO", "Settings", f"Cleared yt-dlp cache: {cache_dir}")
            except Exception as e:
                await emit_log("WARNING", "Settings", f"Failed to clear cache {cache_dir}: {str(e)}")
        
        if cleared_count == 0:
            message = "No yt-dlp cache directories found"
            await emit_log("INFO", "Settings", message)
        else:
            message = f"Cleared {cleared_count} yt-dlp cache director(ies)"
            await emit_log("SUCCESS", "Settings", message)
        
        return {"message": message, "cleared": cleared_count}
    
    except Exception as e:
        await emit_log("ERROR", "Settings", f"yt-dlp cache cleanup error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/files/thumbnail/{download_id}")
async def get_thumbnail(download_id: str, db: Session = Depends(get_db_session)):
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
async def get_video(download_id: str, db: Session = Depends(get_db_session)):
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
async def download_file(download_id: str, db: Session = Depends(get_db_session)):
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
async def list_files(db: Session = Depends(get_db_session)):
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
async def delete_file(download_id: str, db: Session = Depends(get_db_session)):
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
async def calculate_zip_size(request: DownloadZipRequest, db: Session = Depends(get_db_session)):
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
async def download_files_as_zip(request: DownloadZipRequest, db: Session = Depends(get_db_session)):
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
async def convert_video_to_mp3(request: VideoToMp3Request, db: Session = Depends(get_db_session)):
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
            conversion.id,
            source_path,
            output_path,
            request.audio_quality
        )

        return conversion

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to queue MP3 conversion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools/conversions", response_model=List[ToolConversionResponse])
async def list_conversions(status: Optional[str] = None, db: Session = Depends(get_db_session)):
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
async def get_conversion(conversion_id: str, db: Session = Depends(get_db_session)):
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
async def delete_conversion(conversion_id: str, db: Session = Depends(get_db_session)):
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


@app.get("/api/tools/audio/{conversion_id}")
async def download_audio(conversion_id: str, db: Session = Depends(get_db_session)):
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


@app.post("/api/tools/transform")
async def transform_video(request: VideoTransformRequest):
    """
    Apply a transformation to a video (flip or rotate).
    This modifies the original video file in-place.
    """
    try:
        result = await VideoTransformService.transform_video(
            request.download_id,
            request.transform_type
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "VideoTransform", f"Failed to transform video: {str(e)}")
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
