"""
Vidnag Framework - Main Application
FastAPI-based web application for downloading and manipulating videos using yt-dlp.
Github Repository: https://github.com/Sychedelic-but-cooler/vidnag-framework
"""

# FastAPI and web framework imports
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request, UploadFile, File, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Data validation and database
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import text

# Date and time handling
from datetime import datetime, timedelta, timezone
from html import escape

# Type hints for better code clarity
from typing import Optional, List, Dict, Any
from pathlib import Path

# Data structures and utilities
from collections import deque
from contextlib import asynccontextmanager
import asyncio
import subprocess
import sys
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
import httpx

# Application modules
from database import init_db, get_db_session, Download, DownloadStatus, ToolConversion, ConversionStatus, get_db, User, UserLoginHistory, FailedLoginAttempt, SystemSettings, JWTKey, AuthAuditLog, OIDCAuthState, ShareToken
from sqlalchemy import or_, and_
from settings import settings, SETTINGS_FILE
from admin_settings import get_admin_settings, ADMIN_SETTINGS_FILE
from security import (
    is_safe_path,
    validate_filename,
    validate_url,
    sanitize_url_for_logging,
    validate_cookie_filename,
    validate_settings_update
)
from auth import PasswordService, JWTService, AuthService, AuditLogService
from external_auth import get_external_auth_config, reload_external_auth_config
from oidc_auth import OIDCService
from config import DATABASE_FILE

# Application version (Major.Minor.Bugfix-ReleaseMonth)
APP_VERSION = "2.7.43-12"

def cleanup_old_logs():
    # Remove log files older than 3 days on application startup.
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


def init_settings_folder():
    # Initialize the settings folder with proper permissions (700).
    try:
        import stat

        # This can be changed if you really want
        settings_dir = "settings" 
        
        # Create settings directory if it doesn't exist
        if not os.path.exists(settings_dir):
            os.makedirs(settings_dir, exist_ok=True)
            logger.info(f"Created settings directory: {settings_dir}")
        
        # Set directory permissions to 700 (owner rwx only, no group/others)
        try:
            os.chmod(settings_dir, stat.S_IRWXU)  # 700 permissions
            logger.debug(f"Set permissions 700 on {settings_dir}")
        except Exception as e:
            logger.warning(f"Could not set permissions on {settings_dir}: {e}")
        
        # Set permissions on all settings files to 600 (owner rw only)
        try:
            for file_name in os.listdir(settings_dir):
                file_path = os.path.join(settings_dir, file_name)
                if os.path.isfile(file_path):
                    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
                    logger.debug(f"Set permissions 600 on {file_path}")
        except Exception as e:
            logger.warning(f"Could not set permissions on settings files: {e}")
            
        logger.info("Settings folder initialized with proper permissions")
        
    except Exception as e:
        logger.error(f"Error initializing settings folder: {e}")


def set_directory_permissions():
    # Set file permissions on all created directories
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
        for dir_path in ["cookies", "settings"]:
            if os.path.exists(dir_path):
                try:
                    os.chmod(dir_path, stat.S_IRWXU)
                    logger.debug(f"Set permissions 700 on {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {dir_path}: {e}")

        # Private files: 600 (owner rw only)
        from config import DATABASE_FILE as CONFIG_DATABASE_FILE
        for file_path in [CONFIG_DATABASE_FILE]:
            if os.path.exists(file_path):
                try:
                    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
                    logger.debug(f"Set permissions 600 on {file_path}")
                except Exception as e:
                    logger.warning(f"Could not set permissions on {file_path}: {e}")
        
        # Set permissions on all settings files to 600 (owner rw only)
        try:
            settings_dir = "settings"
            if os.path.exists(settings_dir):
                for file_name in os.listdir(settings_dir):
                    file_path = os.path.join(settings_dir, file_name)
                    if os.path.isfile(file_path):
                        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 600 permissions
                        logger.debug(f"Set permissions 600 on {file_path}")
        except Exception as e:
            logger.warning(f"Could not set permissions on settings files: {e}")

        logger.info("Directory permissions set successfully")

    except Exception as e:
        logger.error(f"Error setting directory permissions: {e}")


def get_client_ip(request: Request) -> str:
    # Get the connecting client IP address from the request.
    # Checks request.state.client_ip first (set by proxy middleware), then falls back to request.client.host

    if hasattr(request.state, 'client_ip'):
        return request.state.client_ip

    # Fallback to direct connection IP
    if request.client:
        return request.client.host

    return "unknown"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    # Application lifespan event handler. Runs initialization code on startup and cleanup code on shutdown.

    global server_start_time
    server_start_time = datetime.now(timezone.utc)  # Track startup time for uptime calculation

    init_db()  # Create database tables if they don't exist

    # Initialize settings folder first - must happen before settings files are accessed
    init_settings_folder()

    # Create all required directories if they don't exist
    os.makedirs("downloads", exist_ok=True)  # Video Download Storage
    os.makedirs("cookies", exist_ok=True)    # Cookie Files
    os.makedirs("logs", exist_ok=True)       # Application logs
    os.makedirs("backups", exist_ok=True)    # Application Backups

    # Set proper file permissions on critical directories and files
    set_directory_permissions()

    # Load and validate admin settings from admin_settings.json
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
    await shutdown_cleanup()


async def shutdown_cleanup():
    # Shutdown Sequence.
    # Cleans up resources and kills all client connections.

    try:
        await emit_log("INFO", "System", "Shutdown initiated - starting cleanup...")

        # 1. Stop accepting new work from queues
        if download_queue.processing_task and not download_queue.processing_task.done():
            download_queue.processing_task.cancel()
            await emit_log("INFO", "System", "Download queue processing stopped")

        if conversion_queue.processing_task and not conversion_queue.processing_task.done():
            conversion_queue.processing_task.cancel()
            await emit_log("INFO", "System", "Conversion queue processing stopped")

        # 2. Terminate active FFmpeg processes gracefully
        for conversion_id, (process, output_path) in list(active_conversion_processes.items()):
            try:
                if process.poll() is None:  # Process still running
                    process.terminate()  # Send SIGTERM
                    try:
                        process.wait(timeout=3)  # Wait up to 3 seconds
                    except subprocess.TimeoutExpired:
                        process.kill()  # Force kill if it doesn't terminate
                    await emit_log("INFO", "System", f"Terminated conversion process: {conversion_id[:8]}...", conversion_id)
            except Exception as e:
                logger.error(f"Error terminating conversion {conversion_id}: {e}")

        # 3. Close Download WebSockets Gracefully
        for download_id, websockets in list(active_connections.items()):
            for ws in websockets:
                try:
                    await ws.close(code=1001, reason="Server restarting")
                except Exception as e:
                    logger.error(f"Error closing websocket for {download_id}: {e}")


        await emit_log("INFO", "System", "Shutdown cleanup completed successfully")

        # Give logs time to flush
        await asyncio.sleep(0.5)

    except Exception as e:
        logger.error(f"Error during shutdown cleanup: {e}")


# Create the FastAPI application instance with our lifespan handler
app = FastAPI(title="Vidnag Framework API", lifespan=lifespan)

# Configure Python's  logging system so these can be fed to browser console

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Set up logging for application logs, these rotate daily
os.makedirs("logs", exist_ok=True)

from logging.handlers import TimedRotatingFileHandler

# Create a rotating file handler for application logs
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
app_file_logger = logging.getLogger("app_logs")
app_file_logger.setLevel(logging.INFO)
app_file_logger.addHandler(file_handler)
app_file_logger.propagate = False  # Don't send logs to parent logger

# Admin log handler - for system management and security events
admin_file_handler = TimedRotatingFileHandler(
    filename="logs/admin.log",
    when="midnight",         # Rotate at midnight
    interval=1,              # Every 1 day
    backupCount=3,           # Keep 3 days of logs
    encoding="utf-8"
)
admin_file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

# Create a separate logger for admin logs
admin_file_logger = logging.getLogger("admin_logs")
admin_file_logger.setLevel(logging.INFO)
admin_file_logger.addHandler(admin_file_handler)
admin_file_logger.propagate = False

# User log handler - for downloads and conversions
user_file_handler = TimedRotatingFileHandler(
    filename="logs/user.log",
    when="midnight",         # Rotate at midnight
    interval=1,              # Every 1 day
    backupCount=3,           # Keep 3 days of logs
    encoding="utf-8"
)
user_file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

# Create a separate logger for user logs
user_file_logger = logging.getLogger("user_logs")
user_file_logger.setLevel(logging.INFO)
user_file_logger.addHandler(user_file_handler)
user_file_logger.propagate = False


# Load Configuration from admin_settings.json
admin_settings_instance = get_admin_settings()

# If CORS is disabled, use empty allowed_origins to block all cross-origin requests
cors_allowed_origins = admin_settings_instance.cors.allowed_origins if admin_settings_instance.cors.enabled else []
# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allowed_origins,
    allow_credentials=admin_settings_instance.cors.allow_credentials,
    allow_methods=admin_settings_instance.cors.allowed_methods,
    allow_headers=admin_settings_instance.cors.allowed_headers,
)

# Configure Rate Limiting Middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Apply rate limiting to all requests based on client IP.
    # Returns 429 Too Many Requests if limit exceeded.
    admin_settings = get_admin_settings()

    # Skip rate limiting if disabled
    if not admin_settings.rate_limit.enabled:
        return await call_next(request)

    # These scale with the number of downloads and would trigger false positives, excluded from rate limiting
    # They're protected by: authentication, caching headers, and lazy loading
    static_file_paths = ['/api/files/thumbnail/', '/api/files/video/']
    if any(request.url.path.startswith(path) for path in static_file_paths):
        return await call_next(request)

    # Get client IP
    client_ip = getattr(request.state, 'client_ip', 'unknown')

    # Check rate limit
    if not check_rate_limit(client_ip):
        await emit_log("WARNING", "Security", f"Rate limit exceeded for IP: {client_ip} on {request.url.path}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please try again later."}
        )

    response = await call_next(request)
    return response

# Configure IP - Proxy Header Extraction Middleware
@app.middleware("http")
async def trust_proxy_headers(request: Request, call_next):
    # Extract client IP from proxy headers based on admin configuration.
    admin_settings = get_admin_settings()

    # If not behind a proxy, use direct connection IP only
    if not admin_settings.proxy.is_behind_proxy:
        client_ip = request.client.host if request.client else "unknown"
        request.state.client_ip = client_ip
        return await call_next(request)

    # Get the direct connection IP
    direct_ip = request.client.host if request.client else None

    # Default to direct IP
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
                        # CIDR range (e.g., 192.168.0.0/24)
                        if direct_ip_obj in ip_network(trusted, strict=False):
                            is_trusted = True
                            break
                    else:
                        # Single IP
                        if direct_ip_obj == parse_ip(trusted):
                            is_trusted = True
                            break
            except (AddressValueError, ValueError):
                pass

            if is_trusted:
                # Connection is from trusted proxy, extract real IP from configured header
                header_value = request.headers.get(admin_settings.proxy.proxy_header)

                if header_value:
                    # Some headers like X-Forwarded-For may contain multiple IPs, take the leftmost IP and assume it is the original client
                    if ',' in header_value:
                        client_ip = header_value.split(',')[0].strip()
                    else:
                        client_ip = header_value.strip()
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
    # Controlled by admin settings to prevent header leakage in production
    if not hasattr(trust_proxy_headers, 'logged_count'):
        trust_proxy_headers.logged_count = 0

    if admin_settings.security.debug_proxy_headers and trust_proxy_headers.logged_count < 5:
        logger.info(f"Proxy Headers Debug - Direct IP: {direct_ip}")
        logger.info(f"  Configured Header ({admin_settings.proxy.proxy_header}): {request.headers.get(admin_settings.proxy.proxy_header)}")
        logger.info(f"  Resolved Client IP: {client_ip}")
        trust_proxy_headers.logged_count += 1

    response = await call_next(request)
    return response


# Mount static files to be served by FastAPI
app.mount("/assets", StaticFiles(directory="assets"), name="assets")

#WebSocket Connection Management
active_connections: dict[str, list[WebSocket]] = {}

# Server Restart Management
server_start_time: Optional[datetime] = None
graceful_shutdown_requested: bool = False

# WebSocket connection limits to prevent memory exhaustion (for download progress only)
WEBSOCKET_IDLE_TIMEOUT = 300  # Disconnect Idle WebSocket Connections

# Admin logs: system management, security, user operations
admin_log_buffer = deque(maxlen=1000)
admin_log_sequence = 0

# User logs: downloads, conversions, file operations
user_log_buffer = deque(maxlen=1000)
user_log_sequence = 0

# Stores last 1000 log entries for quick retrieval by the frontend
log_buffer = deque(maxlen=1000)

# Global sequence counter for logs
log_sequence = 0

# Component classification for log routing
ADMIN_LOG_COMPONENTS = {
    "User Management",   # User CRUD operations
    "Admin",             # Database operations, system config
    "Settings",          # Admin settings changes
    "System",            # Startup, shutdown, hardware detection
    "Security",          # Security events, rate limiting
    "Auth",              # Login/logout events (legacy)
    "Authentication"     # Login/logout events (current)
    "Cleanup",           # File Cleanup Operations
    "Share"              # Share link creation
}

USER_LOG_COMPONENTS = {
    "Download",          # Download operations
    "Upload",            # File uploads
    "Queue",             # Download Queue Operations
    "YT-DLP",            # yt-dlp output
    "YT-DLP-ERR",        # yt-dlp errors
    "API",               # General API calls
    "Playlist",          # Playlist extraction and processing
    "Tools",             # Conversion tools
    "ToolConversion",    # Tool conversions
    "VideoTransform",    # Video transformations
    "Thumbnail",         # Thumbnail generation
    "Cookies",           # Cookie File Operations
    "ConversionQueue"    # Conversion Queue Operations
}

# Rate limiting data structures
from collections import defaultdict
from datetime import datetime

# Store request timestamps per IP address for rate limiting
# Each IP gets a deque of recent request timestamps
# Configuration (max capacity, cleanup) comes from admin_settings
rate_limit_store: dict[str, deque] = {}
last_cleanup_time = 0


def check_rate_limit(client_ip: str) -> bool:
    # Check if a client has exceeded the rate limit using a sliding window.
    global last_cleanup_time
    
    admin_settings = get_admin_settings()
    
    # If rate limiting is disabled, allow all requests
    if not admin_settings.rate_limit.enabled:
        return True
    
    now = datetime.now(timezone.utc).timestamp()
    window_seconds = admin_settings.rate_limit.window_seconds
    max_requests = admin_settings.rate_limit.max_requests_per_window
    
    # Cleanup old IPs periodically to prevent memory leaks
    if now - last_cleanup_time > admin_settings.rate_limit.cleanup_interval_seconds:
        _cleanup_rate_limit_store()
        last_cleanup_time = now
    
    # Limit number of tracked IPs to prevent memory leaks
    if len(rate_limit_store) >= admin_settings.rate_limit.max_tracked_ips:
        _cleanup_rate_limit_store()
    
    # Get or create request deque for this IP
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = deque(maxlen=max_requests)
    
    requests = rate_limit_store[client_ip]

    # Remove old request timestamps outside the current time window
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
    # Remove IPs with no recent activity from the rate limit store.
    global rate_limit_store
    now = datetime.now(timezone.utc).timestamp()
    
    # 1. Remove IPs with no requests in the last 30 minutes
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
    
    # 2. If still too many IPs, do aggressive cleanup (5 minutes)
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


# Download timeout configuration (in seconds), prevent stale downloads from growing indefinitely
DOWNLOAD_TIMEOUT_SECONDS = 3600  # 1 hour

async def download_with_timeout(download_id: str, url: str, cookies_file: Optional[str] = None):
    # Wrapper for Download Timeouts
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
        raise


# Download Queue Manager
class DownloadQueueManager:
    # Manages downloads with queue to make sure only a limited number of downloads run simultaneously.

    def __init__(self):
        # Queue for pending downloads
        self.queue: asyncio.Queue = asyncio.Queue()

        # Set of currently running download IDs
        self.active_downloads: set = set()

        # Background task that processes the queue
        self.processing_task: Optional[asyncio.Task] = None

    async def add_to_queue(self, download_id: str, url: str, cookies_file: Optional[str] = None):
        # Add a download to the queue. Downloads are processed in order when capacity is available.
        await self.queue.put((download_id, url, cookies_file))
        await emit_log("INFO", "Queue", f"Download {download_id[:8]}... added to queue. Queue size: {self.queue.qsize()}", download_id)

    async def process_queue(self):
        # Continuously process downloads from the queue.
        # Respects max_concurrent_downloads setting and Disk Space limits.
        while True:
            try:
                # Wait for a download to be added to the queue (blocking)
                download_id, url, cookies_file = await self.queue.get()

                # Wait until we have capacity for another download, enforcing the max_concurrent_downloads limit
                max_concurrent = settings.get("max_concurrent_downloads", 2)
                while len(self.active_downloads) >= max_concurrent:
                    await asyncio.sleep(1)

                # Check if we have enough free disk space, enforing min_disk_space_mb limit
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

                # Create a new async task for the download, wrapped with timeout to prevent hung downloads
                asyncio.create_task(self._download_wrapper(download_id, url, cookies_file))

                # Mark this queue item as processed
                self.queue.task_done()

            except Exception as e:
                # Log queue processing errors and continue processing
                await emit_log("ERROR", "Queue", f"Queue processing error: {str(e)}")
                await asyncio.sleep(1)

    async def _download_wrapper(self, download_id: str, url: str, cookies_file: Optional[str]):
        # Wrapper around the download function.
        # Ensures the download is always removed from active_downloads even if the download fails or throws an exception.
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
        # Restore queued and downloading items from database on startup.
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
        # Start the background queue processor task, called during application startup.
        if self.processing_task is None or self.processing_task.done():
            self.processing_task = asyncio.create_task(self.process_queue())

# Global queue manager instance used throughout the application
download_queue = DownloadQueueManager()


# Conversion Queue Manager
class ConversionQueueManager:
    # Manages the conversion queue for both MP3 conversions and video transforms.

    def __init__(self):
        # AsyncIO queue for pending conversions
        # Items: (job_type, conversion_id, job_params)
        self.queue: asyncio.Queue = asyncio.Queue()

        # Set of currently running conversion IDs
        self.active_conversions: set = set()

        # Background task that processes the queue
        self.processing_task: Optional[asyncio.Task] = None

    async def add_to_queue(self, job_type: str, conversion_id: str, **job_params):
        # Add a conversion job to the queue.
        await self.queue.put((job_type, conversion_id, job_params))
        await emit_log("INFO", "ConversionQueue",
                     f"{job_type.upper()} job {conversion_id[:8]}... added to queue. Queue size: {self.queue.qsize()}",
                     conversion_id)

    async def process_queue(self):
        # Continuously process conversions from the queue.
        while True:
            try:
                # Wait for a job to be added to the queue (blocking)
                job_type, conversion_id, job_params = await self.queue.get()

                # Wait until we have capacity for another conversion
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
        # Wrapper around the actual job processing function.
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
        # Restore queued and converting items from database on startup.
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
        # Start the background queue processor task, called during application startup.
        if self.processing_task is None or self.processing_task.done():
            self.processing_task = asyncio.create_task(self.process_queue())


# Global conversion queue manager instance
conversion_queue = ConversionQueueManager()

# Global hardware acceleration cache
hardware_acceleration = {
    "nvenc": False,
    "amf": False,
    "qsv": False,
    "vaapi": False,
    "videotoolbox": False,
    "detected_encoders": []
}

# Global dictionary to track active conversion processes for cancellation
active_conversion_processes = {}

# Global cache for all hardware information, clients fetch this once and cache in browser localStorage
hardware_info_cache = None


# Filename sanitization
def sanitize_filename(filename: str) -> str:
    # Sanitize filename to handle special characters, emojis, and problematic characters.
    if not filename:
        return filename

    # Split filename into base name and extension, maintains file type information
    base, ext = os.path.splitext(filename)

    # Normalize unicode characters
    base = unicodedata.normalize('NFKD', base)

    # Replace filesystem-unsafe characters with placeholder character
    unsafe_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\n', '\r', '\t']
    for char in unsafe_chars:
        base = base.replace(char, '_')

    # Remove invisible characters that can cause issues
    base = ''.join(char for char in base if unicodedata.category(char)[0] != 'C')

    # Remove leading/trailing spaces and dots
    base = base.strip('. ')

    # Collapse multiple consecutive underscores or spaces into a single underscore
    base = re.sub(r'[_\s]+', '_', base)

    # Limit filename length to prevent filesystem issues
    max_length = 200
    if len(base.encode('utf-8')) > max_length:
        # Truncate at byte level to handle multi-byte UTF-8 characters correctly
        # errors='ignore' handles partial multi-byte characters at the cut point
        base = base.encode('utf-8')[:max_length].decode('utf-8', errors='ignore')
        base = base.rstrip('_')

    # Ensure we have at least some content for the filename, use a default name if no filename exists
    if not base or base == '_':
        base = 'video'

    return base + ext


async def embed_thumbnail_in_video(video_path: str, thumbnail_path: str, download_id: Optional[str] = None) -> bool:
    # Embed a thumbnail image into a video file as cover art/poster frame.
    # This allows the thumbnail to be displayed in external file explorers and video players.
    try:
        # Create a temporary output file path
        temp_output = f"{video_path}.temp.mp4"

        await emit_log("INFO", "Thumbnail", f"Embedding thumbnail into video: {os.path.basename(video_path)}", download_id)

        # Use ffmpeg to embed the thumbnail as cover art
        
        embed_process = await asyncio.create_subprocess_exec(
            'ffmpeg',
            '-i', video_path,                       # -i video_path: input video
            '-i', thumbnail_path,                   # -i thumbnail_path: input thumbnail
            '-map', '0',                            # -map 0: map all streams from first input (video)
            '-map', '1',                            # -map 1: map the thumbnail as an additional stream
            '-c', 'copy',                           # -c copy: copy all streams without re-encodin
            '-c:v:1', 'mjpeg',                      # -c:v:1 mjpeg: encode the thumbnail stream as MJPEG (required for cover art)
            '-disposition:v:1', 'attached_pic',     # -disposition:v:1 attached_pic: mark the thumbnail as an attached picture/cover art
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
    # Data model for a single log entry.
    sequence: int                       # Ever-increasing sequence number
    timestamp: str                      # ISO 8601 timestamp in UTC
    level: str                          # INFO, WARNING, ERROR, etc.
    component: str                      # Which part of the system generated the log
    message: str                        # The actual log message
    download_id: Optional[str] = None   # Associated download ID (if applicable)    

async def emit_log(level: str, component: str, message: str, download_id: Optional[str] = None):
    # Emit a log entry to all logging destinations with automatic routing.
    global admin_log_sequence, user_log_sequence, log_sequence

    # Determine log type based on component classification
    is_admin_log = component in ADMIN_LOG_COMPONENTS
    is_user_log = component in USER_LOG_COMPONENTS

    # Default to user log if component not explicitly classified
    # This ensures new components don't break logging
    if not is_admin_log and not is_user_log:
        is_user_log = True

    # Create timestamp once for consistency
    timestamp = datetime.now(timezone.utc).isoformat()

    # Map our log levels to Python's built-in logging levels
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "SUCCESS": logging.INFO,  # SUCCESS is treated as INFO in file logs
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR
    }
    file_log_level = log_level_map.get(level, logging.INFO)

    # Format the message for file logging
    log_msg = message
    if download_id:
        log_msg = f"[{download_id[:8]}] {message}"

    # Route to admin log
    if is_admin_log:
        admin_log_sequence += 1
        log_entry = LogEntry(
            sequence=admin_log_sequence,
            timestamp=timestamp,
            level=level,
            component=component,
            message=message,
            download_id=download_id
        )
        admin_log_buffer.append(log_entry.model_dump())
        admin_file_logger.log(file_log_level, log_msg, extra={'component': component})

    # Route to user log
    if is_user_log:
        user_log_sequence += 1
        log_entry = LogEntry(
            sequence=user_log_sequence,
            timestamp=timestamp,
            level=level,
            component=component,
            message=message,
            download_id=download_id
        )
        user_log_buffer.append(log_entry.model_dump())
        user_file_logger.log(file_log_level, log_msg, extra={'component': component})

    # Also write to legacy buffer for backwards compatibility
    log_sequence += 1
    legacy_entry = LogEntry(
        sequence=log_sequence,
        timestamp=timestamp,
        level=level,
        component=component,
        message=message,
        download_id=download_id
    )
    log_buffer.append(legacy_entry.model_dump())
    app_file_logger.log(file_log_level, log_msg, extra={'component': component})

    # Debug logging to console for troubleshooting
    if not hasattr(emit_log, 'call_count'):
        emit_log.call_count = 0
    emit_log.call_count += 1

    # Log to console selectively to avoid spam
    if emit_log.call_count <= 20 or emit_log.call_count % 50 == 0:
        log_type = "ADMIN" if is_admin_log else "USER"
        logger.info(f"[LOG #{emit_log.call_count}] {log_type} | {level} | {component} | {message[:100]}")
        logger.info(f"[LOG] Sequences - Admin: {admin_log_sequence}, User: {user_log_sequence}")




# Pydantic schemas for API request/response validation
# These models validate incoming requests and serialize outgoing responses

class DownloadRequest(BaseModel):
    # Request body for creating a new download
    url: str                                # Video URL to download
    cookies_file: Optional[str] = None      # Optional cookies file for authentication
    is_public: bool = True                  # Visibility flag (defaults to public)
    download_playlist: bool = False         # If True, download all videos in playlist


class DownloadResponse(BaseModel):
    # Response model for download information
    model_config = ConfigDict(from_attributes=True)  # Allows creation from ORM objects

    id: str
    url: str
    status: str
    progress: float                         # 0.0 to 100.0
    filename: Optional[str]                 # Set after download completes
    thumbnail: Optional[str]                # Thumbnail filename
    file_size: Optional[int]                # Size in bytes
    error_message: Optional[str]            # Error message if failed
    user_id: Optional[str] = None           # User who created this download
    username: Optional[str] = None          # Username for display purposes
    is_public: bool = True                  # Visibility flag
    created_at: datetime                    # When job was created/queued
    started_at: Optional[datetime]          # When download actually started
    completed_at: Optional[datetime]        # When download finished


class DownloadsListResponse(BaseModel):
    # Response model for list of downloads with privacy info
    downloads: List[DownloadResponse]
    hidden_active_count: int = 0  # Number of private active downloads from other users


class VersionInfo(BaseModel):
    # System version information
    ytdlp_version: str                      # yt-dlp version string
    app_version: str                        # Application version
    python_version: str                     # Python version string
    python_version_warning: bool = False    # True if Python version < 3.10


class DiskSpaceInfo(BaseModel):
    # Disk space information
    total: int                              # Total disk space in bytes
    used: int                               # Used disk space in bytes
    free: int                               # Free disk space in bytes
    percent: float                          # Percentage used


class CleanupStats(BaseModel):
    # Statistics from cleanup operation
    downloads_removed: int                  # Number of database entries removed
    files_removed: int                      # Number of files deleted
    space_freed: int                        # Space freed in bytes


class ConversionCleanupStats(BaseModel):
    # Statistics from conversion cleanup operation
    conversions_removed: int                # Number of conversion entries removed
    files_removed: int                      # Number of files deleted
    space_freed: int                        # Space freed in bytes


class FileInfo(BaseModel):
    # Information about a downloaded file
    id: str                                  # Download ID for API operations
    filename: str                            # Display filename (user-friendly name)
    size: int                               # File size in bytes
    user_id: Optional[str] = None            # User who uploaded/downloaded this file
    username: Optional[str] = None           # Username for display purposes
    is_public: bool = True                   # Visibility flag


class DownloadZipRequest(BaseModel):
    # Request body for downloading multiple files as ZIP
    download_ids: List[str]                 # List of download IDs to include


# Tool Conversion API Models
class VideoToMp3Request(BaseModel):
    # Request body for video to MP3 conversion
    source_download_id: str                 # UUID of source video
    audio_quality: int = 128                # Audio bitrate in kbps (96, 128, 192)


class ToolConversionResponse(BaseModel):
    # Response model for tool conversion status
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
    # Request body for video transformation
    download_id: str                         # UUID of video to transform
    transform_type: str                      # Type of transformation (hflip, vflip, rotate90, rotate180, rotate270)


# Authentication Pydantic Models
class LoginRequest(BaseModel):
    # Request body for user login
    username: str
    password: str


class LoginResponse(BaseModel):
    # Response body for successful login
    access_token: str
    token_type: str
    expires_in: int  # seconds
    username: str
    is_admin: bool


class UserInfoResponse(BaseModel):
    # Response body for current user info
    user_id: str
    username: str
    display_name: Optional[str] = None
    is_admin: bool
    last_login: Optional[datetime]


class UpdateUserProfileRequest(BaseModel):
    # Request body for updating user profile (non-admin settings)
    display_name: Optional[str] = None


class UserResponse(BaseModel):
    # Response model for user data
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    display_name: Optional[str] = None
    is_admin: bool
    is_disabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    oidc_provider: Optional[str] = None
    oidc_email: Optional[str] = None


class CreateUserRequest(BaseModel):
    # Request body for creating a new user
    username: str
    password: str
    is_admin: bool = False


class UpdateUserRequest(BaseModel):
    # Request body for updating a user
    is_admin: Optional[bool] = None
    is_disabled: Optional[bool] = None
    new_password: Optional[str] = None


# Database Service - Handles all database operations
class DatabaseService:
    # Static service class for database operations.
    # All methods take a database session as the first parameter.
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
    def get_visible_downloads(db: Session, user_id: str) -> List[Download]:
        # Get downloads visible to a regular user.
        # Returns public downloads + user's own private downloads
        return db.query(Download).filter(
            or_(
                Download.is_public == True,
                Download.user_id == user_id
            )
        ).order_by(Download.created_at.desc()).all()

    @staticmethod
    def get_visible_downloads_by_status(
        db: Session,
        user_id: str,
        status: DownloadStatus
    ) -> List[Download]:
        # Get downloads visible to a regular user, filtered by status.
        return db.query(Download).filter(
            and_(
                Download.status == status,
                or_(
                    Download.is_public == True,
                    Download.user_id == user_id
                )
            )
        ).order_by(Download.created_at.desc()).all()

    @staticmethod
    def get_failed_downloads_older_than(db: Session, days: int) -> List[Download]:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        return db.query(Download).filter(
            Download.status == DownloadStatus.FAILED,
            Download.created_at < cutoff_date
        ).all()

    @staticmethod
    def create_download(
        db: Session,
        url: str,
        cookies_file: Optional[str] = None,
        user_id: Optional[str] = None,
        is_public: bool = True
    ) -> Download:
        download = Download(
            url=url,
            cookies_file=cookies_file,
            user_id=user_id,
            is_public=is_public
        )
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
        # Find files in downloads/ that don't have database entries
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
        # Remove orphaned files and return (count, bytes_freed)
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
    # Service for interacting with yt-dlp to download videos.
    # Handles the subprocess execution, progress tracking, and file management.

    @staticmethod
    async def extract_playlist_urls(url: str, cookies_file: Optional[str] = None) -> List[str]:
        # Extract all video URLs from a playlist without downloading, for individual queueing.
        await emit_log("INFO", "Playlist", f"Starting playlist extraction with yt-dlp")

        cmd = [
            sys.executable, "-m", "yt_dlp",
            "--flat-playlist",  # Don't download, just list
            "--yes-playlist",   # Explicitly process as playlist
            "--get-url",        # Get video URLs
            "--skip-download",  # Don't download, extract info
            url
        ]

        if cookies_file and os.path.exists(f"cookies/{cookies_file}"):
            cmd.extend(["--cookies", f"cookies/{cookies_file}"])
            await emit_log("INFO", "Playlist", f"Using cookies file: {cookies_file}")

        try:
            await emit_log("DEBUG", "Playlist", f"Executing: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                await emit_log("ERROR", "Playlist", f"yt-dlp failed with return code {process.returncode}")
                await emit_log("ERROR", "Playlist", f"Error output: {error_msg}")
                return []

            # Parse URLs from output (one per line)
            output_text = stdout.decode().strip()
            await emit_log("DEBUG", "Playlist", f"Raw output length: {len(output_text)} characters")

            if not output_text:
                await emit_log("WARNING", "Playlist", "No output from yt-dlp - playlist may be empty or URL is a single video")
                return []

            urls = [line.strip() for line in output_text.split('\n') if line.strip() and line.strip().startswith('http')]

            # Check for duplicates
            unique_urls = list(dict.fromkeys(urls))  # Preserves order while removing duplicates
            if len(urls) != len(unique_urls):
                await emit_log("WARNING", "Playlist", f"Found {len(urls) - len(unique_urls)} duplicate URLs, removed them")
                urls = unique_urls

            # Log stderr if there was any (even with success)
            stderr_text = stderr.decode().strip()
            if stderr_text:
                await emit_log("DEBUG", "Playlist", f"yt-dlp stderr: {stderr_text}")

            await emit_log("INFO", "Playlist", f"Successfully extracted {len(urls)} unique video URL(s) from playlist")

            # Log first few URLs for debugging
            if urls:
                await emit_log("INFO", "Playlist", f"Preview of extracted URLs:")
                for i, video_url in enumerate(urls[:5]):
                    await emit_log("INFO", "Playlist", f"  [{i+1}] {video_url}")
                if len(urls) > 5:
                    await emit_log("INFO", "Playlist", f"  ... and {len(urls) - 5} more videos")

            # Log if all URLs are the same (indicates a problem)
            if len(urls) > 1 and len(set(urls)) == 1:
                await emit_log("ERROR", "Playlist", f"All {len(urls)} URLs are identical! This indicates an extraction problem.")
                await emit_log("ERROR", "Playlist", f"The repeated URL is: {urls[0]}")
                return []

            return urls

        except Exception as e:
            await emit_log("ERROR", "Playlist", f"Exception while extracting playlist: {str(e)}")
            import traceback
            await emit_log("ERROR", "Playlist", f"Traceback: {traceback.format_exc()}")
            return []

    @staticmethod
    async def download_video(download_id: str, url: str, cookies_file: Optional[str] = None):
        # Download a video using yt-dlp subproceses.
        # Downloads runs asynchronously so multiple downloads can run concurrently.

        await emit_log("INFO", "Download", f"Starting download for URL: {url}", download_id)

        cmd = [
            sys.executable, "-m", "yt_dlp",
            "-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best[height>=360]",
            "-o", f"downloads/%(title)s-%(id)s.%(ext)s",
            "--merge-output-format", "mp4",
            "--write-thumbnail",
            "--convert-thumbnails", "jpg",
            "--no-playlist",
            "--newline",
            "--restrict-filenames",  # Restrict filenames to safe characters, names are still sanitized later
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
                # Success Case
                if filename and os.path.exists(filename):
                    file_size = os.path.getsize(filename)
                    original_basename = os.path.basename(filename)

                    # Apply additional sanitization to the filename for display
                    sanitized_basename = sanitize_filename(original_basename)

                    # Generate UUID-based internal filename for storage, this isolates file operations from user-generated names
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

                    basename = sanitized_basename               # Display name for user
                    internal_filename_only = internal_basename  # UUID name on disk

                    # Look for thumbnail file with various possible extensions and patterns
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

                    # Embed thumbnail into video if one is found
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
                # Failure Case
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
        # Broadcast progress to all connected WebSocket Clients for this download
        if download_id in active_connections:
            disconnected = []
            for websocket in active_connections[download_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    disconnected.append(websocket)

            # Clean up Disconnected Clients
            for ws in disconnected:
                active_connections[download_id].remove(ws)

            if not active_connections[download_id]:
                del active_connections[download_id]


# Tool Conversion Service - Handles video to MP3 conversions
class ToolConversionService:
    @staticmethod
    async def convert_video_to_mp3(conversion_id: str, source_path: str,
                                   output_path: str, bitrate: int):
        # Extract audio from video using FFmpeg with progress tracking.
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
            process = await asyncio.create_subprocess_exec(
                'ffmpeg', '-y',  # Overwrite output file
                '-i', source_path,
                '-vn',  # No video
                '-acodec', 'libmp3lame',    # MP3 encoder
                '-b:a', f'{bitrate}k',      # Audio bitrate
                '-progress', 'pipe:1',      # Progress to stdout
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
    # Queue a video transformation job.
    async def transform_video(download_id: str, transform_type: str):
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
        # Process a video transformation from queue.
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
            video_encoder = 'libx264'   # Default CPU encoder
            encoder_preset = []         # Additional encoder-specific options

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
                # Intel Quick Sync Video - Intel HW encoding
                video_encoder = 'h264_qsv'
                encoder_preset = ['-preset', 'fast']
                await emit_log("INFO", "VideoTransform", "Using Intel Quick Sync acceleration", conversion_id)
            elif hardware_acceleration["vaapi"]:
                # VAAPI Encoding
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
    # Log all unhandled exceptions
    await emit_log("ERROR", "System", f"Unhandled exception: {type(exc).__name__}: {str(exc)}")
    logger.exception("Unhandled exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Authentication Dependencies
security = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    token: Optional[str] = None,  # Query parameter token
    db: Session = Depends(get_db_session)
) -> Dict[str, Any]:
    # Authentication dependency for file endpoints, checks Authorization header first, then ?token= query parameter
    # Try to load admin settings
    admin_settings = None
    try:
        admin_settings = get_admin_settings()
        if hasattr(admin_settings, 'auth') and hasattr(admin_settings.auth, 'enabled'):
            if admin_settings.auth.enabled is False:
                # Auth disabled - return system user
                return {"sub": "system", "username": "system", "is_admin": True}
    except Exception:
        pass

    # Try Authorization header first
    token_string = None
    if credentials:
        token_string = credentials.credentials
    elif token:
        # Fall back to query parameter
        token_string = token

    # If we have a token, try to validate it
    if token_string and admin_settings:
        try:
            payload = JWTService.decode_token(token_string, db, admin_settings)
            if payload:
                # Check if user still exists and is not disabled
                user = db.query(User).filter(User.id == payload["sub"]).first()
                if user and not user.is_disabled:
                    return payload
        except Exception:
            # Token validation failed
            pass

    # No valid credentials - require authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated - token required in Authorization header or ?token= parameter",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db_session)
) -> Dict[str, Any]:
    # FastAPI dependency to extract and validate JWT token. Raises 401 if token is missing or invalid.
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

    # SECURITY: Return is_admin from DATABASE, not from JWT payload
    # This prevents privilege escalation if JWT is forged or user is demoted
    return {
        "sub": user.id,
        "user_id": user.id,
        "username": user.username,
        "is_admin": user.is_admin  # Always from database, never from JWT
    }


async def get_current_admin_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    # FastAPI dependency to require admin privileges. Raises 403 if user is not an admin.
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# Authentication Endpoints
@app.post("/api/auth/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db_session)
):
    # Authenticate user and return JWT token.
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
    # Logout user, client-side token deletion.
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
    # Refresh JWT token with new expiry. Validates current token and issues a new one with extended expiry.
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


# OIDC Authentication Endpoints
@app.get("/api/auth/oidc/config")
async def get_oidc_config():
    # Get public OIDC configuration for frontend.
    external_auth = get_external_auth_config()
    return external_auth.get_public_config()


@app.get("/api/auth/oidc/login")
async def oidc_login_initiate(
    request: Request,
    db: Session = Depends(get_db_session)
):
    # Initiate OIDC login flow.
    admin_settings = get_admin_settings()
    external_auth = get_external_auth_config()

    # Check if OIDC is enabled
    if not external_auth.oidc.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not enabled"
        )

    # Check if main authentication is enabled
    if not admin_settings.auth.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication system is not enabled"
        )

    try:
        # Fetch OIDC provider metadata
        metadata = await OIDCService.get_oidc_metadata(external_auth.oidc.discovery_url)
        authorization_endpoint = metadata.get("authorization_endpoint")

        if not authorization_endpoint:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC provider metadata is invalid"
            )

        # Get client IP for security
        ip_address = get_client_ip(request)

        # Generate PKCE pair if enabled
        code_verifier = None
        code_challenge = None
        if external_auth.oidc.use_pkce:
            code_verifier, code_challenge = OIDCService.generate_pkce_pair()

        # Build redirect URI (callback endpoint)
        redirect_uri = str(request.base_url).rstrip('/') + "/api/auth/oidc/callback"

        # Create auth state for CSRF protection
        state = OIDCService.create_auth_state(
            db=db,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            ip_address=ip_address
        )

        # Build authorization URL
        authorization_url = OIDCService.build_authorization_url(
            authorization_endpoint=authorization_endpoint,
            client_id=external_auth.oidc.client_id,
            redirect_uri=redirect_uri,
            scopes=external_auth.oidc.scopes,
            state=state,
            code_challenge=code_challenge
        )

        # Log audit event
        AuditLogService.log_event(
            event_type="oidc_login_initiated",
            ip_address=ip_address,
            db=db,
            details=f"Provider: {external_auth.oidc.provider_name}"
        )

        await emit_log("INFO", "Authentication", f"OIDC login initiated from {ip_address}")

        return {"authorization_url": authorization_url}

    except httpx.HTTPError as e:
        await emit_log("ERROR", "Authentication", f"Failed to connect to OIDC provider: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot connect to OIDC provider: {str(e)}"
        )
    except Exception as e:
        await emit_log("ERROR", "Authentication", f"OIDC login initiation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OIDC login: {str(e)}"
        )


@app.get("/api/auth/oidc/callback", response_model=LoginResponse)
async def oidc_callback(
    request: Request,
    code: str,
    state: str,
    db: Session = Depends(get_db_session)
):
    # Handle OIDC callback from provider.
    admin_settings = get_admin_settings()
    external_auth = get_external_auth_config()
    ip_address = get_client_ip(request)

    # Check if OIDC is enabled
    if not external_auth.oidc.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not enabled"
        )

    try:
        # Validate and consume state token (CSRF protection)
        auth_state = OIDCService.validate_and_consume_state(db, state, ip_address)
        if not auth_state:
            await emit_log("WARNING", "Authentication", f"Invalid OIDC state from {ip_address}")
            AuditLogService.log_event(
                event_type="oidc_login_failed",
                ip_address=ip_address,
                db=db,
                details="Invalid or expired state token"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired state token"
            )

        # Fetch OIDC provider metadata
        metadata = await OIDCService.get_oidc_metadata(external_auth.oidc.discovery_url)
        token_endpoint = metadata.get("token_endpoint")
        userinfo_endpoint = metadata.get("userinfo_endpoint")

        if not token_endpoint:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC provider metadata is invalid (missing token_endpoint)"
            )

        # Use custom userinfo_url if provided, otherwise use from metadata
        if external_auth.oidc.userinfo_url:
            userinfo_endpoint = external_auth.oidc.userinfo_url
        elif not userinfo_endpoint:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC provider metadata is invalid (missing userinfo_endpoint)"
            )

        # Exchange authorization code for tokens
        token_response = await OIDCService.exchange_code_for_tokens(
            code=code,
            redirect_uri=auth_state.redirect_uri,
            token_endpoint=token_endpoint,
            client_id=external_auth.oidc.client_id,
            client_secret=external_auth.oidc.client_secret,
            code_verifier=auth_state.code_verifier if external_auth.oidc.use_pkce else None
        )

        access_token = token_response.get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC provider did not return access token"
            )

        # Fetch user info from OIDC provider
        userinfo = await OIDCService.get_userinfo(userinfo_endpoint, access_token)

        # Find or create user
        user, error = OIDCService.find_or_create_user(
            db=db,
            userinfo=userinfo,
            config=external_auth.oidc,
            provider_name=external_auth.oidc.provider_name
        )

        if error:
            await emit_log("WARNING", "Authentication", f"OIDC login failed for {userinfo.get('preferred_username', 'unknown')}: {error}")
            AuditLogService.log_event(
                event_type="oidc_login_failed",
                ip_address=ip_address,
                db=db,
                username=userinfo.get(external_auth.oidc.username_claim),
                details=error
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error
            )

        # Check if account is disabled
        if user.is_disabled:
            await emit_log("WARNING", "Authentication", f"Disabled user {user.username} attempted OIDC login from {ip_address}")
            AuditLogService.log_event(
                event_type="oidc_login_failed",
                ip_address=ip_address,
                db=db,
                user_id=user.id,
                username=user.username,
                details="Account is disabled"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is disabled"
            )

        # Update last_login
        user.last_login = datetime.now(timezone.utc)

        # Update is_admin if not manually overridden
        if not user.admin_override:
            new_admin_status = OIDCService.determine_admin_status(userinfo, external_auth.oidc)
            if user.is_admin != new_admin_status:
                old_status = user.is_admin
                user.is_admin = new_admin_status
                await emit_log("INFO", "Authentication", f"Admin status changed for {user.username}: {old_status} -> {new_admin_status}")
                AuditLogService.log_event(
                    event_type="admin_status_changed",
                    ip_address=ip_address,
                    db=db,
                    user_id=user.id,
                    username=user.username,
                    details=f"Changed from {old_status} to {new_admin_status} via OIDC group sync"
                )

        db.commit()

        # Generate JWT token
        jwt_token = JWTService.create_access_token(
            user_id=user.id,
            username=user.username,
            is_admin=user.is_admin,
            db=db,
            admin_settings=admin_settings
        )

        # Log successful OIDC login
        AuditLogService.log_event(
            event_type="oidc_login_success",
            ip_address=ip_address,
            db=db,
            user_id=user.id,
            username=user.username,
            details=f"Provider: {external_auth.oidc.provider_name}"
        )

        await emit_log("INFO", "Authentication", f"User {user.username} logged in via OIDC from {ip_address}")

        # Return HTML that stores token in localStorage and redirects to main app
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Successful</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }}
                .container {{
                    text-align: center;
                }}
                .spinner {{
                    border: 4px solid rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    border-top: 4px solid white;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Login Successful!</h2>
                <div class="spinner"></div>
                <p>Redirecting to application...</p>
            </div>
            <script>
                localStorage.setItem('auth_token', '{jwt_token}');

                // Redirect to main application
                window.location.href = '/';
            </script>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    except HTTPException as e:
        # Return user-friendly error page that redirects to login
        error_message = e.detail
        await emit_log("ERROR", "Authentication", f"OIDC login failed: {error_message}")

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Failed</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                }}
                .container {{
                    text-align: center;
                    max-width: 500px;
                    padding: 2rem;
                }}
                .error-icon {{
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }}
                .message {{
                    background: rgba(0, 0, 0, 0.2);
                    padding: 1rem;
                    border-radius: 8px;
                    margin: 1rem 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">⚠️</div>
                <h2>Login Failed</h2>
                <div class="message">
                    <p>{error_message}</p>
                </div>
                <p>Redirecting to login page...</p>
            </div>
            <script>
                setTimeout(function() {{
                    window.location.href = '/assets/login.html';
                }}, 3000);
            </script>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=e.status_code)

    except httpx.HTTPError as e:
        await emit_log("ERROR", "Authentication", f"Failed to connect to OIDC provider during callback: {str(e)}")

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Failed</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                }}
                .container {{
                    text-align: center;
                    max-width: 500px;
                    padding: 2rem;
                }}
                .error-icon {{
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }}
                .message {{
                    background: rgba(0, 0, 0, 0.2);
                    padding: 1rem;
                    border-radius: 8px;
                    margin: 1rem 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">🔌</div>
                <h2>Connection Error</h2>
                <div class="message">
                    <p>Cannot connect to SSO provider. Please try again later.</p>
                </div>
                <p>Redirecting to login page...</p>
            </div>
            <script>
                setTimeout(function() {{
                    window.location.href = '/assets/login.html';
                }}, 3000);
            </script>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=503)

    except Exception as e:
        await emit_log("ERROR", "Authentication", f"OIDC callback failed: {str(e)}")

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Failed</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                }}
                .container {{
                    text-align: center;
                    max-width: 500px;
                    padding: 2rem;
                }}
                .error-icon {{
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }}
                .message {{
                    background: rgba(0, 0, 0, 0.2);
                    padding: 1rem;
                    border-radius: 8px;
                    margin: 1rem 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">❌</div>
                <h2>Login Failed</h2>
                <div class="message">
                    <p>An unexpected error occurred. Please try again.</p>
                </div>
                <p>Redirecting to login page...</p>
            </div>
            <script>
                setTimeout(function() {{
                    window.location.href = '/assets/login.html';
                }}, 3000);
            </script>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=500)


# Helper functions for download visibility and access control

def enrich_download_with_user(db: Session, download: Download) -> DownloadResponse:
    # Add username to download response
    username = None
    if download.user_id:
        user = db.query(User).filter(User.id == download.user_id).first()
        username = user.username if user else "Unknown"

    return DownloadResponse(
        id=download.id,
        url=download.url,
        status=download.status,
        progress=download.progress,
        filename=download.filename,
        thumbnail=download.thumbnail,
        file_size=download.file_size,
        error_message=download.error_message,
        user_id=download.user_id,
        username=username,
        is_public=download.is_public,
        created_at=download.created_at,
        started_at=download.started_at,
        completed_at=download.completed_at
    )


def verify_download_access(
    download: Download,
    current_user: Dict[str, Any]
) -> bool:
    # Verify user has access to download.
    is_admin = current_user.get("is_admin", False)
    user_id = current_user.get("sub")

    # Public downloads are accessible to everyone
    if download.is_public:
        return True

    # From here on, download is private - only authenticated users with ownership or admin can access
    # Admin users can access all downloads
    if is_admin:
        return True

    # Owner can access their own private downloads
    if download.user_id == user_id:
        return True

    # Deny access to other users' private downloads
    return False


@app.get("/api/auth/me", response_model=UserInfoResponse)
async def get_current_user_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    # Get current user information.
    user = db.query(User).filter(User.id == current_user["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserInfoResponse(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        is_admin=user.is_admin,
        last_login=user.last_login
    )


@app.patch("/api/auth/profile", response_model=UserInfoResponse)
async def update_user_profile(
    profile_data: UpdateUserProfileRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    # Update current user's profile settings (display name, etc.)
    user = db.query(User).filter(User.id == current_user["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update display name if provided
    if profile_data.display_name is not None:
        # Validate display name length and content
        if len(profile_data.display_name.strip()) == 0:
            user.display_name = None  # Empty string becomes None
        elif len(profile_data.display_name.strip()) > 100:
            raise HTTPException(status_code=400, detail="Display name too long (max 100 characters)")
        else:
            user.display_name = profile_data.display_name.strip()
    
    # Update timestamp
    user.updated_at = datetime.now(timezone.utc)
    
    try:
        db.commit()
        
        # Log the profile update
        client_ip = get_client_ip(request)
        await emit_log("INFO", "Authentication", 
                      f"User '{user.username}' updated profile (display name: '{user.display_name or 'None'}') from {client_ip}")
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update profile")
    
    return UserInfoResponse(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        display_name=user.display_name,
        is_admin=user.is_admin,
        last_login=user.last_login
    )


@app.get("/api/auth/status")
async def get_auth_status():
    # Get authentication system status
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
    # Get release notes from docs/release.json (PUBLIC endpoint).

    try:
        import json
        with open("docs/release.json", "r") as f:
            release_data = json.load(f)
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


@app.get("/api/auth/check-setup")
async def check_setup_status(db: Session = Depends(get_db_session)):
    # Check if initial setup is needed
    try:
        settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()

        # If settings don't exist for some reason, create them
        if not settings:
            settings = SystemSettings(id=1, first_time_setup=True)
            db.add(settings)
            db.commit()

        return {
            "setup_needed": settings.first_time_setup,
            "has_users": not settings.first_time_setup
        }
    except Exception as e:
        # On error, assume setup is not needed (fail secure)
        return {
            "setup_needed": False,
            "has_users": True,
            "error": "Unable to determine setup status"
        }


@app.post("/api/auth/setup")
async def create_first_admin(
    request: Request,
    setup_data: dict,
    db: Session = Depends(get_db_session)
):
    # Create the first admin user during initial setup (PUBLIC endpoint, one-time use).
    try:
        # Only allow if first_time_setup flag is True
        settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()
        if not settings:
            # Create settings if they don't exist
            settings = SystemSettings(id=1, first_time_setup=True)
            db.add(settings)
            db.commit()

        if not settings.first_time_setup:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Setup already completed. Admin user already exists."
            )

        # Extract credentials
        username = setup_data.get("username", "").strip()
        password = setup_data.get("password", "")

        # Validate username
        if not username or len(username) < 3 or len(username) > 32:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username must be between 3 and 32 characters"
            )

        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username must contain only alphanumeric characters and underscores"
            )

        # Validate password
        if not password or len(password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long"
            )

        # Hash password
        password_hash = PasswordService.hash_password(password)

        # Create first admin user
        admin_user = User(
            username=username,
            password_hash=password_hash,
            is_admin=True,
            is_disabled=False
        )

        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        # Get IP address for audit log
        ip_address = get_client_ip(request)

        # Log audit event
        AuditLogService.log_event(
            event_type="user_created",
            ip_address=ip_address,
            db=db,
            user_id=admin_user.id,
            username=username,
            details={
                "created_by": "initial_setup",
                "is_admin": True,
                "first_user": True
            }
        )

        #  Set first_time_setup to False
        settings.first_time_setup = False
        settings.updated_at = datetime.now(timezone.utc)
        db.commit()

        await emit_log("INFO", "Auth", f"First admin user created via web setup: {username}")
        await emit_log("INFO", "Auth", "First-time setup completed - setup flag set to False")

        return {
            "success": True,
            "message": "Admin user created successfully",
            "username": username,
            "user_id": admin_user.id
        }

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "Auth", f"Failed to create first admin user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create admin user: {str(e)}"
        )


# User Management Endpoints
@app.post("/api/users", response_model=UserResponse)
async def create_user(
    request: Request,
    user_data: CreateUserRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    # Validates username format and password strength, then creates a new user account with hashed password.
    admin_settings = get_admin_settings()
    ip_address = get_client_ip(request)

    # Validate username
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
    # Returns all user accounts with their metadata.
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
    # Update user account
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
    # Delete user account
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


# Admin Endpoints
@app.get("/api/admin/database/stats")
async def get_database_stats(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    # Get database statistics (ADMIN ONLY).
    stats = {
        "users": db.query(User).count(),
        "downloads": db.query(Download).count(),
        "conversions": db.query(ToolConversion).count(),
        "audit_logs": db.query(AuthAuditLog).count(),
        "failed_login_attempts": db.query(FailedLoginAttempt).count(),
        "user_login_history": db.query(UserLoginHistory).count(),
        "jwt_keys": db.query(JWTKey).count(),
    }

    # Get database file size
    import os
    db_path = DATABASE_FILE
    if os.path.exists(db_path):
        stats["database_size_bytes"] = os.path.getsize(db_path)
        stats["database_size_mb"] = round(os.path.getsize(db_path) / (1024 * 1024), 2)
    else:
        stats["database_size_bytes"] = 0
        stats["database_size_mb"] = 0

    await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} viewed database stats")

    return stats


@app.post("/api/admin/database/backup")
async def backup_database(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Create a timestamped database backup of the SQLite database in the backups/ directory.
    import shutil
    from datetime import datetime

    db_path = DATABASE_FILE
    backup_dir = "backups"

    if not os.path.exists(db_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Database file not found"
        )

    # Create backups directory if it doesn't exist
    os.makedirs(backup_dir, exist_ok=True)

    # Create backup filename with timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{backup_dir}/{DATABASE_FILE}.backup.{timestamp}"

    try:
        shutil.copy2(db_path, backup_filename)
        backup_size = os.path.getsize(backup_filename)

        await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} created database backup: {backup_filename}")

        return {
            "message": "Database backup created successfully",
            "filename": backup_filename,
            "size_bytes": backup_size,
            "size_mb": round(backup_size / (1024 * 1024), 2)
        }
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to create database backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create backup: {str(e)}"
        )


@app.post("/api/admin/database/vacuum")
async def vacuum_database(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Rebuilds the database file, repacking it into minimal disk space.
    try:
        # Use a raw connection to run VACUUM (cannot be in a transaction)
        from database import engine
        with engine.connect() as connection:
            connection.execute(text("VACUUM"))
            connection.commit()

        await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} ran database VACUUM")

        # Get new database size
        import os
        db_path = DATABASE_FILE
        new_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0

        return {
            "message": "Database VACUUM completed successfully",
            "new_size_mb": round(new_size / (1024 * 1024), 2)
        }
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to VACUUM database: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to VACUUM database: {str(e)}"
        )


@app.post("/api/admin/database/optimize")
async def optimize_database(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Optimize the database for better query performance
    try:
        from database import engine
        with engine.connect() as connection:
            connection.execute(text("ANALYZE"))
            connection.commit()

        await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} ran database OPTIMIZE")

        return {"message": "Database optimized successfully"}
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to optimize database: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to optimize database: {str(e)}"
        )


@app.post("/api/admin/database/integrity-check")
async def check_database_integrity(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Verifies that the database structure is valid.
    try:
        from database import engine
        with engine.connect() as connection:
            result = connection.execute(text("PRAGMA integrity_check"))
            integrity_result = result.fetchall()

            # If integrity check passes, it returns [('ok',)]
            is_ok = len(integrity_result) == 1 and integrity_result[0][0] == 'ok'

            await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} ran database integrity check")

            return {
                "status": "ok" if is_ok else "error",
                "message": "Database integrity check passed" if is_ok else "Database integrity check found issues",
                "details": [row[0] for row in integrity_result]
            }
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to check database integrity: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check database integrity: {str(e)}"
        )


@app.get("/api/admin/database/backups")
async def list_backups(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # List available database backup files. Includes both manual backups and pre-restore safety backups.
    import os
    import glob
    from datetime import datetime

    backup_dir = "backups"

    # Create backups directory if it doesn't exist
    os.makedirs(backup_dir, exist_ok=True)

    # Get both manual backups and pre-restore safety backups from backups/ directory
    backup_files = glob.glob(f"{backup_dir}/{DATABASE_FILE}.backup.*") + glob.glob(f"{backup_dir}/{DATABASE_FILE}.pre-restore.*")

    backups = []
    for backup_file in backup_files:
        stat = os.stat(backup_file)
        backup_type = "Safety Backup" if "pre-restore" in backup_file else "Manual Backup"
        backups.append({
            "filename": backup_file,
            "type": backup_type,
            "size_bytes": stat.st_size,
            "size_mb": round(stat.st_size / (1024 * 1024), 2),
            "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })

    # Sort by creation time, newest first
    backups.sort(key=lambda x: x['created_at'], reverse=True)

    return {
        "total": len(backups),
        "backups": backups
    }


@app.post("/api/admin/database/restore")
async def restore_database(
    backup_filename: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Restore database from a backup file.
    import os
    import shutil
    from datetime import datetime

    db_path = DATABASE_FILE
    backup_dir = "backups"

    # Validate backup file exists and has correct prefix
    if not backup_filename.startswith(f"{backup_dir}/{DATABASE_FILE}.backup.") and not backup_filename.startswith(f"{backup_dir}/{DATABASE_FILE}.pre-restore."):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid backup filename"
        )

    if not os.path.exists(backup_filename):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup file not found"
        )

    try:
        # Create backups directory if it doesn't exist
        os.makedirs(backup_dir, exist_ok=True)

        # Create a safety backup of current database before restoring
        safety_backup = f"{backup_dir}/{DATABASE_FILE}.pre-restore.{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        if os.path.exists(db_path):
            shutil.copy2(db_path, safety_backup)

        # Restore from backup
        shutil.copy2(backup_filename, db_path)

        await emit_log("WARNING", "Admin", f"Admin {current_admin.get('username')} restored database from backup: {backup_filename}")

        return {
            "message": "Database restored successfully from backup",
            "backup_filename": backup_filename,
            "safety_backup": safety_backup
        }
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to restore database from backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to restore database: {str(e)}"
        )


@app.delete("/api/admin/database/backups/{backup_filename}")
async def delete_backup(
    backup_filename: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Delete a backup file, expects just the filename part ({DATABASE_FILE}.backup.{DATETIME}")
    import os

    # Validate backup filename format
    if not backup_filename.startswith(f"{DATABASE_FILE}.backup.") and not backup_filename.startswith(f"{DATABASE_FILE}.pre-restore."):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid backup filename"
        )

    # Construct full path
    backup_dir = "backups"
    full_path = os.path.join(backup_dir, backup_filename)

    if not os.path.exists(full_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup file not found"
        )

    try:
        os.remove(full_path)
        await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} deleted backup: {backup_filename}")

        return {
            "message": "Backup deleted successfully",
            "filename": backup_filename
        }
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to delete backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete backup: {str(e)}"
        )


@app.get("/api/admin/database/backups/{backup_filename}/download")
async def download_backup(
    backup_filename: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Download a backup file (ADMIN ONLY).
    import os
    from fastapi.responses import FileResponse

    # Validate backup filename format (without directory prefix)
    if not backup_filename.startswith(f"{DATABASE_FILE}.backup.") and not backup_filename.startswith(f"{DATABASE_FILE}.pre-restore."):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid backup filename"
        )

    # Construct full path
    backup_dir = "backups"
    full_path = os.path.join(backup_dir, backup_filename)

    if not os.path.exists(full_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup file not found"
        )

    try:
        await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} downloaded backup: {backup_filename}")

        return FileResponse(
            path=full_path,
            filename=backup_filename,
            media_type='application/octet-stream'
        )
    except Exception as e:
        await emit_log("ERROR", "Admin", f"Failed to download backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download backup: {str(e)}"
        )


@app.get("/api/admin/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    # Get audit logs with pagination.
    query = db.query(AuthAuditLog).order_by(AuthAuditLog.timestamp.desc())

    # Filter by event type if specified (supports comma-separated list)
    if event_type:
        # Split comma-separated event types and filter
        event_types = [et.strip() for et in event_type.split(',')]
        query = query.filter(AuthAuditLog.event_type.in_(event_types))

    # Get total count for pagination
    total = query.count()

    # Apply pagination
    logs = query.offset(offset).limit(limit).all()

    # Convert to dict and parse JSON details
    import json
    result = []
    for log in logs:
        log_dict = {
            "id": log.id,
            "event_type": log.event_type,
            "user_id": log.user_id,
            "username": log.username,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat(),
            "details": json.loads(log.details) if log.details else None
        }
        result.append(log_dict)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": result
    }


@app.get("/api/admin/failed-logins")
async def get_failed_logins(
    limit: int = 100,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    # Get recent failed login attempts for security monitoring.
    failed_attempts = db.query(FailedLoginAttempt)\
        .order_by(FailedLoginAttempt.attempt_time.desc())\
        .limit(limit)\
        .all()

    result = []
    for attempt in failed_attempts:
        result.append({
            "id": attempt.id,
            "username": attempt.username,
            "ip_address": attempt.ip_address,
            "attempt_time": attempt.attempt_time.isoformat(),
            "lockout_until": attempt.lockout_until.isoformat() if attempt.lockout_until else None,
            "is_locked": attempt.lockout_until and attempt.lockout_until > datetime.now(timezone.utc)
        })

    return {
        "total": len(result),
        "failed_attempts": result
    }


@app.get("/api/admin/sessions")
async def get_active_sessions(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    # Get list of recent successful logins within the last 24 hours.
    from datetime import timedelta

    # Get successful logins in the last 24 hours
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)

    recent_logins = db.query(UserLoginHistory)\
        .filter(UserLoginHistory.success == True)\
        .filter(UserLoginHistory.login_time >= cutoff_time)\
        .order_by(UserLoginHistory.login_time.desc())\
        .all()

    # Get user info for each session
    sessions = []
    for login in recent_logins:
        user = db.query(User).filter(User.id == login.user_id).first()
        if user:
            sessions.append({
                "id": login.id,
                "user_id": login.user_id,
                "username": user.username,
                "is_admin": user.is_admin,
                "ip_address": login.ip_address,
                "login_time": login.login_time.isoformat(),
                "user_agent": login.user_agent
            })

    return {
        "total": len(sessions),
        "sessions": sessions,
        "note": "JWT tokens are stateless. Showing successful logins in the last 24 hours."
    }



@app.get("/api/admin/settings")
async def get_admin_settings_ui(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Get admin settings for web UI editing.
    # Excludes application architecture settings like public_endpoints.
    admin_settings = get_admin_settings()

    return {
        "proxy": {
            "is_behind_proxy": admin_settings.proxy.is_behind_proxy,
            "proxy_header": admin_settings.proxy.proxy_header,
            "trusted_proxies": admin_settings.proxy.trusted_proxies
        },
        "cors": {
            "enabled": admin_settings.cors.enabled,
            "allowed_origins": admin_settings.cors.allowed_origins
        },
        "auth": {
            "enabled": admin_settings.auth.enabled,
            "jwt_session_expiry_hours": admin_settings.auth.jwt_session_expiry_hours,
            "jwt_key_rotation_days": admin_settings.auth.jwt_key_rotation_days,
            "failed_login_attempts_max": admin_settings.auth.failed_login_attempts_max,
            "failed_login_lockout_minutes": admin_settings.auth.failed_login_lockout_minutes,
            "suspicious_ip_threshold": admin_settings.auth.suspicious_ip_threshold,
            "suspicious_ip_window_hours": admin_settings.auth.suspicious_ip_window_hours
        },
        "security": {
            "debug_proxy_headers": admin_settings.security.debug_proxy_headers,
            "debug_logs": admin_settings.security.debug_logs,
            "validate_ip_format": admin_settings.security.validate_ip_format,
            "allow_ytdlp_update": admin_settings.security.allow_ytdlp_update
        },
        "rate_limiting": {
            "enabled": admin_settings.rate_limit.enabled,
            "max_requests_per_window": admin_settings.rate_limit.max_requests_per_window,
            "window_seconds": admin_settings.rate_limit.window_seconds,
            "max_tracked_ips": admin_settings.rate_limit.max_tracked_ips,
            "cleanup_interval_seconds": admin_settings.rate_limit.cleanup_interval_seconds
        }
    }


@app.get("/api/admin/oidc/config")
async def get_oidc_admin_config(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Get full OIDC configuration for admin UI.
    external_auth = get_external_auth_config()
    return external_auth.get_admin_config(redact_secret=True)


@app.post("/api/admin/oidc/config/update")
async def update_oidc_config(
    config_update: Dict[str, Any],
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    request: Request = None
):
    # Update OIDC configuration.
    try:
        print("=== OIDC Config Update Endpoint Called ===")
        print(f"Received config update: {config_update}")

        # Get current config
        external_auth = get_external_auth_config()
        print(f"Current config file: {external_auth.config_file}")

        # If client_secret is masked (********), keep the existing secret
        if "oidc" in config_update and "client_secret" in config_update["oidc"]:
            if config_update["oidc"]["client_secret"] == "********":
                print("Client secret is masked, keeping existing secret")
                current_config = external_auth.get_admin_config(redact_secret=False)
                config_update["oidc"]["client_secret"] = current_config["oidc"]["client_secret"]

        # Save updated configuration
        print(f"Saving config to file: {external_auth.config_file}")
        external_auth.save_config(config_update)
        print("Config saved successfully!")

        # Reload configuration
        print("Reloading configuration...")
        reload_external_auth_config()
        print("Configuration reloaded!")

        # Log audit event
        ip_address = get_client_ip(request) if request else "unknown"
        AuditLogService.log_event(
            event_type="oidc_config_updated",
            ip_address=ip_address,
            db=db,
            user_id=current_admin.get("sub"),
            username=current_admin.get("username"),
            details=f"OIDC enabled: {config_update.get('oidc', {}).get('enabled', False)}"
        )

        await emit_log("INFO", "Configuration", f"OIDC configuration updated by {current_admin.get('username')}")

        return {"message": "OIDC configuration updated successfully"}

    except Exception as e:
        print(f"=== ERROR updating OIDC config: {str(e)} ===")
        print(f"Exception type: {type(e)}")
        import traceback
        traceback.print_exc()
        await emit_log("ERROR", "Configuration", f"Failed to update OIDC config: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update OIDC configuration: {str(e)}"
        )


class LinkOIDCAccountRequest(BaseModel):
    # Request model for linking OIDC account to existing user
    user_id: str
    oidc_provider: str
    oidc_subject: str
    oidc_email: Optional[str] = None


@app.post("/api/admin/oidc/link-account")
async def link_oidc_account(
    link_data: LinkOIDCAccountRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    request: Request = None
):
    # Manually link OIDC account to existing user.
    # Allows admins to resolve username conflicts by manually linking an OIDC account to an existing local user account.
    try:
        # Find user by user_id
        user = db.query(User).filter(User.id == link_data.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Check if user already has OIDC linked
        if user.oidc_subject:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"User already has OIDC account linked ({user.oidc_provider})"
            )

        # Check if oidc_subject is already used by another user
        existing_oidc = db.query(User).filter(User.oidc_subject == link_data.oidc_subject).first()
        if existing_oidc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"OIDC subject already linked to user '{existing_oidc.username}'"
            )

        # Link OIDC account
        user.oidc_provider = link_data.oidc_provider
        user.oidc_subject = link_data.oidc_subject
        user.oidc_email = link_data.oidc_email
        user.oidc_linked_at = datetime.now(timezone.utc)
        user.password_hash = None  # Remove local password (OIDC-only)

        db.commit()

        # Log audit event
        ip_address = get_client_ip(request) if request else "unknown"
        AuditLogService.log_event(
            event_type="oidc_account_linked",
            ip_address=ip_address,
            db=db,
            user_id=current_admin.get("sub"),
            username=current_admin.get("username"),
            details=f"Linked OIDC account ({link_data.oidc_provider}) to user '{user.username}'"
        )

        await emit_log("INFO", "User Management", f"OIDC account linked to {user.username} by {current_admin.get('username')}")

        return {"message": f"OIDC account linked successfully to user '{user.username}'"}

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "User Management", f"Failed to link OIDC account: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to link OIDC account: {str(e)}"
        )


@app.post("/api/admin/oidc/unlink-account")
async def unlink_oidc_account(
    user_id: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session),
    request: Request = None
):
    try:
        # Find user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if not user.oidc_subject:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User does not have OIDC account linked"
            )

        # Unlink OIDC
        oidc_provider = user.oidc_provider
        user.oidc_provider = None
        user.oidc_subject = None
        user.oidc_email = None
        user.oidc_linked_at = None

        db.commit()

        # Log audit event
        ip_address = get_client_ip(request) if request else "unknown"
        AuditLogService.log_event(
            event_type="oidc_account_unlinked",
            ip_address=ip_address,
            db=db,
            user_id=current_admin.get("sub"),
            username=current_admin.get("username"),
            details=f"Unlinked OIDC account ({oidc_provider}) from user '{user.username}'"
        )

        await emit_log("INFO", "User Management", f"OIDC account unlinked from {user.username} by {current_admin.get('username')}")

        return {"message": f"OIDC account unlinked from user '{user.username}'"}

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "User Management", f"Failed to unlink OIDC account: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to unlink OIDC account: {str(e)}"
        )


@app.get("/api/admin/users/oidc-linked")
async def get_oidc_linked_users(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user),
    db: Session = Depends(get_db_session)
):
    try:
        oidc_users = db.query(User).filter(User.oidc_subject.isnot(None)).all()

        return {
            "users": [
                {
                    "id": user.id,
                    "username": user.username,
                    "oidc_provider": user.oidc_provider,
                    "oidc_subject": user.oidc_subject,
                    "oidc_email": user.oidc_email,
                    "oidc_linked_at": user.oidc_linked_at.isoformat() if user.oidc_linked_at else None,
                    "is_admin": user.is_admin,
                    "admin_override": user.admin_override,
                    "is_disabled": user.is_disabled
                }
                for user in oidc_users
            ]
        }

    except Exception as e:
        await emit_log("ERROR", "User Management", f"Failed to get OIDC linked users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get OIDC linked users: {str(e)}"
        )


@app.post("/api/admin/settings/update")
async def update_admin_settings_ui(
    settings_update: Dict[str, Any],
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Update admin settings from web UI
    import json
    from pathlib import Path

    try:
        # Load current settings file
        settings_file = Path(ADMIN_SETTINGS_FILE)
        if not settings_file.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{ADMIN_SETTINGS_FILE} not found"
            )

        with open(settings_file, 'r') as f:
            current_settings = json.load(f)

        # Update only the provided fields
        if "proxy" in settings_update:
            current_settings["proxy"].update(settings_update["proxy"])

        if "cors" in settings_update:
            current_settings["cors"].update(settings_update["cors"])

        if "auth" in settings_update:
            current_settings["auth"].update(settings_update["auth"])

        if "security" in settings_update:
            current_settings["security"].update(settings_update["security"])

        if "rate_limiting" in settings_update:
            current_settings["rate_limiting"].update(settings_update["rate_limiting"])

        # Validate updated settings, basic type validation
        if "proxy" in settings_update:
            if "is_behind_proxy" in settings_update["proxy"]:
                if not isinstance(settings_update["proxy"]["is_behind_proxy"], bool):
                    raise ValueError("is_behind_proxy must be a boolean")

            if "trusted_proxies" in settings_update["proxy"]:
                if not isinstance(settings_update["proxy"]["trusted_proxies"], list):
                    raise ValueError("trusted_proxies must be a list")

        if "cors" in settings_update:
            if "allowed_origins" in settings_update["cors"]:
                if not isinstance(settings_update["cors"]["allowed_origins"], list):
                    raise ValueError("allowed_origins must be a list")

        # Write updated settings to file
        with open(settings_file, 'w') as f:
            json.dump(current_settings, f, indent=2)

        # Reload the singleton to pick up the new settings from disk
        from admin_settings import reload_admin_settings
        reload_admin_settings()

        # Log the change
        await emit_log("INFO", "Admin", f"Admin {current_admin.get('username')} updated application settings")

        return {
            "message": "Settings updated successfully. Restart application to apply changes.",
            "settings": current_settings
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to update admin settings: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update settings: {str(e)}"
        )


@app.get("/")
async def root(request: Request):
    """
    Serve the main HTML page or redirect to login, handles login and first-time setup.
    1. If auth disabled -> serve main page
    2. If valid token -> serve main page
    3. Otherwise -> redirect to login
    """
    from fastapi.responses import HTMLResponse, RedirectResponse

    admin_settings = get_admin_settings()

    # If auth is disabled, serve main page directly
    if not admin_settings.auth.enabled:
        with open("assets/index.html") as f:
            return HTMLResponse(content=f.read())

    with open("assets/index.html") as f:
        return HTMLResponse(content=f.read())


@app.get("/favicon.ico")
async def favicon():
    """Serve favicon"""
    from fastapi.responses import FileResponse
    return FileResponse("assets/logo.png", media_type="image/png")


@app.post("/api/download", response_model=DownloadResponse)
async def start_download(request: DownloadRequest, http_request: Request, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Start a new video download"""
    # Get client IP (from proxy headers middleware)
    client_ip = getattr(http_request.state, 'client_ip', 'unknown')


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

    # Extract user ID from authenticated user
    user_id = current_user.get("sub")

    # Handle playlist downloads
    if request.download_playlist:
        await emit_log("INFO", "Playlist", f"Extracting playlist URLs from: {safe_url}")

        # Extract all video URLs from the playlist
        playlist_urls = await YtdlpService.extract_playlist_urls(request.url, request.cookies_file)

        if playlist_urls and len(playlist_urls) > 0:
            await emit_log("INFO", "Playlist", f"✓ Successfully extracted {len(playlist_urls)} videos from playlist")
            await emit_log("INFO", "Playlist", f"Creating {len(playlist_urls)} separate download entries...")

            # Create and queue a download for each video in the playlist
            # Each video gets its own database entry and queue position
            created_downloads = []
            for idx, video_url in enumerate(playlist_urls):
                try:
                    await emit_log("INFO", "Playlist", f"[{idx + 1}/{len(playlist_urls)}] Creating download for: {video_url[:80]}...")

                    # Create database entry for this video
                    download = DatabaseService.create_download(
                        db,
                        video_url,
                        request.cookies_file,
                        user_id=user_id,
                        is_public=request.is_public
                    )
                    created_downloads.append(download)

                    await emit_log("INFO", "Playlist", f"[{idx + 1}/{len(playlist_urls)}] ✓ Created download with ID: {download.id}", download.id)

                    # Add this video to the download queue as a separate job
                    await download_queue.add_to_queue(
                        download.id,
                        video_url,
                        request.cookies_file
                    )

                    await emit_log("INFO", "Playlist", f"[{idx + 1}/{len(playlist_urls)}] ✓ Added to queue (queue size: {download_queue.queue.qsize()})", download.id)

                except Exception as e:
                    await emit_log("ERROR", "Playlist", f"[{idx + 1}/{len(playlist_urls)}] ✗ Failed to create download: {str(e)}")
                    import traceback
                    await emit_log("ERROR", "Playlist", f"Traceback: {traceback.format_exc()}")
                    continue

            if created_downloads:
                await emit_log("INFO", "Playlist", f"  Total videos extracted: {len(playlist_urls)}")
                await emit_log("INFO", "Playlist", f"  Successfully created: {len(created_downloads)}")
                await emit_log("INFO", "Playlist", f"  Failed: {len(playlist_urls) - len(created_downloads)}")

                # Return the first download created
                return enrich_download_with_user(db, created_downloads[0])
            else:
                await emit_log("ERROR", "Playlist", "Failed to create any downloads from playlist")
                raise HTTPException(status_code=500, detail="Failed to create downloads from playlist")
        else:
            # If extraction failed or playlist is empty, fall back to single video download
            await emit_log("WARNING", "Playlist", "No playlist URLs found, falling back to single video download")

    # Standard single video download
    download = DatabaseService.create_download(
        db,
        request.url,
        request.cookies_file,
        user_id=user_id,
        is_public=request.is_public
    )

    await emit_log("INFO", "API", f"Download created with ID: {download.id}", download.id)

    # Add download to queue
    await download_queue.add_to_queue(
        download.id,
        request.url,
        request.cookies_file
    )

    return enrich_download_with_user(db, download)


@app.post("/api/upload", response_model=DownloadResponse)
async def upload_video(
    file: UploadFile = File(...),
    http_request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    # Upload a video file to use with tools and get client IP
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
        # Generate UUID for internal filename
        file_uuid = str(uuid.uuid4())
        internal_filename = f"{file_uuid}{file_ext}"
        file_path = os.path.join("downloads", internal_filename)

        # Use original filename for display
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

        # Create Download record with completed status, this allows the uploaded file to appear in tools and file lists
        user_id = current_user.get("sub")
        download = Download(
            url=f"uploaded://{display_filename}",  # Special URL to indicate upload
            filename=display_filename,
            internal_filename=internal_filename,
            thumbnail=internal_thumbnail if internal_thumbnail else None,  # Display thumbnail name
            internal_thumbnail=internal_thumbnail,  # Internal thumbnail name
            file_size=file_size,
            status=DownloadStatus.COMPLETED,
            progress=100.0,
            completed_at=datetime.now(timezone.utc),
            user_id=user_id,  # Assign to user who uploaded
            is_public=True  # Uploads default to public
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


@app.get("/api/downloads", response_model=DownloadsListResponse)
async def get_downloads(status: Optional[str] = None, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Get downloads visible to the current user.
    user_id = current_user.get("sub")
    is_admin = current_user.get("is_admin", False)

    if is_admin:
        # Admins see everything - no hidden downloads
        if status:
            try:
                status_enum = DownloadStatus(status)
                downloads = DatabaseService.get_downloads_by_status(db, status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid status")
        else:
            downloads = DatabaseService.get_all_downloads(db)

        hidden_active_count = 0
    else:
        # Regular users see: public + own private
        if status:
            try:
                status_enum = DownloadStatus(status)
                downloads = DatabaseService.get_visible_downloads_by_status(
                    db, user_id, status_enum
                )
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid status")
        else:
            downloads = DatabaseService.get_visible_downloads(db, user_id)

        # Count hidden private active downloads from other users
        all_active = db.query(Download).filter(
            Download.status.in_([DownloadStatus.QUEUED, DownloadStatus.DOWNLOADING])
        ).all()

        visible_active_ids = {d.id for d in downloads if d.status in ['queued', 'downloading', 'processing']}
        all_active_ids = {d.id for d in all_active}
        hidden_active_count = len(all_active_ids - visible_active_ids)

    # Enrich with username for display
    enriched_downloads = [enrich_download_with_user(db, d) for d in downloads]

    return DownloadsListResponse(
        downloads=enriched_downloads,
        hidden_active_count=hidden_active_count
    )


@app.get("/api/downloads/{download_id}", response_model=DownloadResponse)
async def get_download(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Get a specific download by ID
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")
    return download


@app.patch("/api/downloads/{download_id}/toggle-visibility", response_model=DownloadResponse)
async def toggle_download_visibility(
    download_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    # Toggle download visibility between public and private, only the owner or admin can toggle visibility.
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    user_id = current_user.get("sub")
    is_admin = current_user.get("is_admin", False)

    if not is_admin and download.user_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only change visibility of your own downloads"
        )

    # Toggle visibility
    download.is_public = not download.is_public
    db.commit()
    db.refresh(download)

    visibility = "public" if download.is_public else "private"
    await emit_log(
        "INFO", "API",
        f"Download {download_id} visibility changed to {visibility}",
        download_id
    )

    return enrich_download_with_user(db, download)


@app.delete("/api/downloads/{download_id}")
async def delete_download(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Delete a download and its associated file
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        await emit_log("WARNING", "API", f"Attempted to delete non-existent download: {download_id}")
        raise HTTPException(status_code=404, detail="Download not found")

    await emit_log("INFO", "API", f"Deleting download: {download_id}", download_id)

    display_name = download.filename or "unknown"

    # Delete video file if it exists
    if download.internal_filename:
        filepath = os.path.join("downloads", download.internal_filename)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                await emit_log("INFO", "API", f"Deleted file: {display_name} (internal: {download.internal_filename})", download_id)
            except Exception as e:
                await emit_log("ERROR", "API", f"Failed to delete file {display_name}: {str(e)}", download_id)

    # Delete thumbnail if it exists
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
    # Clean up failed downloads older than specified days and remove orphaned files
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
    # WebSocket endpoint for real-time download progress
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

        # Keep connection alive with timeout, disconnect if client stops responding for 5 minutes
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


@app.get("/api/logs")
async def get_logs(
    log_type: Optional[str] = "user",  # "user", "admin", or "both"
    level: Optional[str] = None,
    component: Optional[str] = None,
    download_id: Optional[str] = None,
    since_sequence: Optional[int] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    # Get logs with optional filtering and incremental updates.
    is_admin = current_user.get("is_admin", False)

    # Access control: non-admins can only see user logs
    if not is_admin and log_type in ["admin", "both"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to view admin logs"
        )

    # Default non-admins to user logs
    if not is_admin:
        log_type = "user"

    # Collect logs based on log_type
    logs = []
    latest_admin_sequence = 0
    latest_user_sequence = 0

    if log_type in ["admin", "both"]:
        admin_logs = list(admin_log_buffer)
        if since_sequence is not None:
            admin_logs = [log for log in admin_logs if log["sequence"] > since_sequence]
        logs.extend(admin_logs)
        latest_admin_sequence = admin_log_buffer[-1]["sequence"] if admin_log_buffer else 0

    if log_type in ["user", "both"]:
        user_logs = list(user_log_buffer)
        if since_sequence is not None:
            user_logs = [log for log in user_logs if log["sequence"] > since_sequence]
        logs.extend(user_logs)
        latest_user_sequence = user_log_buffer[-1]["sequence"] if user_log_buffer else 0

    # Apply filters
    if level:
        logs = [log for log in logs if log["level"] == level.upper()]
    if component:
        logs = [log for log in logs if log["component"] == component]
    if download_id:
        logs = [log for log in logs if log.get("download_id") == download_id]

    # Sort by timestamp for consistent ordering when viewing "both"
    logs = sorted(logs, key=lambda x: x["timestamp"])

    return {
        "logs": logs,
        "log_type": log_type,
        "admin_buffer_size": len(admin_log_buffer),
        "user_buffer_size": len(user_log_buffer),
        "latest_admin_sequence": latest_admin_sequence,
        "latest_user_sequence": latest_user_sequence
    }





@app.get("/api/settings/version", response_model=VersionInfo)
async def get_version(current_user: Dict[str, Any] = Depends(get_current_user)):
    # Get yt-dlp, Python, and app version
    try:
        result = subprocess.run(
            [sys.executable, "-m", "yt_dlp", "--version"],
            capture_output=True,
            text=True
        )
        ytdlp_version = result.stdout.strip()
    except Exception:
        ytdlp_version = "unknown"

    # Get Python version from the running interpreter (not system python3)
    # This ensures we check the version actually running the app (e.g., in a venv)
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # Check if Python version is below 3.10
    python_version_warning = (sys.version_info.major < 3 or
                             (sys.version_info.major == 3 and sys.version_info.minor < 10))

    return VersionInfo(
        ytdlp_version=ytdlp_version,
        app_version=APP_VERSION,
        python_version=python_version,
        python_version_warning=python_version_warning
    )


@app.get("/api/settings/disk-space", response_model=DiskSpaceInfo)
async def get_disk_space():
    # Get disk space information for downloads directory only
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
    # Get list of available cookie files
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
    # Get queue and download settings
    return settings.get_all()


@app.post("/api/settings/queue")
async def update_queue_settings(updates: dict, current_user: Dict[str, Any] = Depends(get_current_user)):
    # Update queue and download settings
    is_valid, error_msg = validate_settings_update(updates)
    if not is_valid:
        await emit_log("WARNING", "System", f"Invalid settings update rejected: {error_msg}")
        raise HTTPException(status_code=400, detail=error_msg)

    settings.update(updates)
    await emit_log("INFO", "System", f"Queue settings updated: {updates}")
    return {"message": "Settings updated successfully", "settings": settings.get_all()}


@app.post("/api/settings/update-ytdlp")
async def update_ytdlp(current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    # Update yt-dlp to the latest version
    admin_settings = get_admin_settings()
    allow_update = admin_settings.security.allow_ytdlp_update

    if not allow_update:
        await emit_log("WARNING", "System", "yt-dlp update blocked - feature disabled for security")
        raise HTTPException(
            status_code=403,
            detail="yt-dlp updates are disabled. Enable 'Allow yt-dlp Updates' in Admin Settings > App Config to use this feature."
        )

    try:
        await emit_log("INFO", "System", "Starting yt-dlp update")

        # Security: Use sys.executable -m pip instead of direct pip command
        # Security: Hardcode the package name to prevent injection
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "yt-dlp"],
            capture_output=True,
            text=True,
            timeout=60  # Add timeout to keep job from going stale
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
    # Clear yt-dlp cache to resolve signature solving and format extraction issues.
    # This removes cached extractor data and forces yt-dlp to refresh on next use.
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
    # List all available cookie files in the cookies/ directory.
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
    # Upload a cookie file for authenticated downloads, validates file size  and file type.
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
    # A valid cookie file will be incredibly small, 5KB should be plenty.
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
    # Delete a cookie file from the cookies/ directory.
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
async def get_thumbnail(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user_optional), db: Session = Depends(get_db_session)):
    # Serve thumbnail images using download ID, look up the download record to get internal_thumbnail filename
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    # Verify access to private downloads
    if not verify_download_access(download, current_user):
        raise HTTPException(
            status_code=403,
            detail="Access denied to private download"
        )

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

    # Add caching headers to prevent repeated requests for the same thumbnail
    # ETag based on file modification time for efficient cache validation
    file_stat = os.stat(filepath)
    etag = f'"{download.internal_thumbnail}-{int(file_stat.st_mtime)}"'

    headers = {
        'Cache-Control': 'private, max-age=3600, must-revalidate',  # Cache for 1 hour
        'ETag': etag
    }

    return FileResponse(filepath, media_type=media_type, headers=headers)


@app.get("/api/files/video/{download_id}")
async def get_video(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user_optional), db: Session = Depends(get_db_session)):
    # Serve video files for streaming/playing in browser using download ID, look up the download record to get internal_filename
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    # Verify access to private downloads
    if not verify_download_access(download, current_user):
        raise HTTPException(
            status_code=403,
            detail="Access denied to private download"
        )

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

    # Add caching headers for video files
    file_stat = os.stat(filepath)
    etag = f'"{download.internal_filename}-{int(file_stat.st_mtime)}"'

    headers = {
        'Cache-Control': 'private, max-age=3600, must-revalidate',
        'ETag': etag
    }

    return FileResponse(filepath, media_type=media_type, headers=headers)


@app.get("/api/files/download/{download_id}")
async def download_file(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user_optional), db: Session = Depends(get_db_session)):
    # Download video file using download ID, look up the download record to get internal_filename and display filename
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    # Verify access to private downloads
    if not verify_download_access(download, current_user):
        raise HTTPException(
            status_code=403,
            detail="Access denied to private download"
        )

    if not download.internal_filename:
        raise HTTPException(status_code=404, detail="File not found")

    # Use internal_filename (UUID-based) for file access
    filepath = os.path.join("downloads", download.internal_filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found on disk")

    from fastapi.responses import FileResponse
    # Use display filename (filename field) for the downloaded file name
    return FileResponse(filepath, filename=download.filename, media_type='application/octet-stream')


@app.post("/api/share/{download_id}")
async def create_share_link(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Create a shareable link for a public video, only public videos can be shared.d
    download = DatabaseService.get_download_by_id(db, download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Download not found")

    # Verify user has access to this download
    if not verify_download_access(download, current_user):
        raise HTTPException(status_code=403, detail="Access denied")

    # Only public videos can be shared
    if not download.is_public:
        raise HTTPException(status_code=403, detail="Only public videos can be shared")

    # Check if download is completed
    if download.status != DownloadStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Video must be completed before sharing")

    # Check if a share link already exists for this download
    existing_share = db.query(ShareToken).filter(ShareToken.download_id == download_id).first()
    if existing_share:
        await emit_log("INFO", "Share", f"Returning existing share link for download {download_id[:8]}...", download_id)
        return {"token": existing_share.token, "url": f"/share/{existing_share.token}"}

    # Generate a random alphanumeric token (a-z, 0-9 only)
    import secrets
    import string
    # Generate 16 character token using only lowercase letters and digits
    alphabet = string.ascii_lowercase + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(16))

    # Create share token
    share_token = ShareToken(
        token=token,
        download_id=download_id,
        created_by=current_user.get("sub")
    )
    db.add(share_token)
    db.commit()

    await emit_log("INFO", "Share", f"Created share link for download {download_id[:8]}...", download_id)

    return {"token": token, "url": f"/share/{token}"}


def generate_share_error_page(title: str, message: str, emoji: str = "❌") -> str:
    # Generate a consistent error page for share links that matches the share page styling.
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #0a0a0a;
                background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
                color: #ffffff;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                max-width: 600px;
                width: 100%;
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                text-align: center;
            }}
            .emoji {{
                font-size: 4rem;
                margin-bottom: 20px;
            }}
            h1 {{
                font-size: 1.8rem;
                margin-bottom: 15px;
                background: linear-gradient(135deg, #00FFFF, #FF1493);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }}
            p {{
                color: #cccccc;
                font-size: 1.1rem;
                line-height: 1.6;
                margin-bottom: 30px;
            }}
            .home-link {{
                display: inline-block;
                padding: 12px 24px;
                background: linear-gradient(135deg, #00FFFF, #FF1493);
                color: #ffffff;
                text-decoration: none;
                border-radius: 8px;
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }}
            .home-link:hover {{
                transform: translateY(-2px);
                box-shadow: 0 5px 20px rgba(0, 255, 255, 0.3);
            }}
            .powered-by {{
                margin-top: 30px;
                text-align: center;
                color: #666;
                font-size: 0.9rem;
            }}
            .powered-by a {{
                color: #00FFFF;
                text-decoration: none;
                transition: color 0.3s ease;
            }}
            .powered-by a:hover {{
                color: #FF1493;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="emoji">{emoji}</div>
            <h1>{title}</h1>
            <p>{message}</p>
            <a href="/" class="home-link">Go to Homepage</a>
            <div class="powered-by">
                Powered by <a href="/">Vidnag Framework</a>
            </div>
        </div>
    </body>
    </html>
    """



@app.get("/share/{token}")
async def view_shared_video(token: str, db: Session = Depends(get_db_session)):
    # Public endpoint to view a shared video, anyone with the link can view.
    from fastapi.responses import HTMLResponse

    # Look up the share token
    share = db.query(ShareToken).filter(ShareToken.token == token).first()
    if not share:
        return HTMLResponse(
            content=generate_share_error_page(
                "Share Link Not Found",
                "This share link doesn't exist or may have been removed. Please check the URL and try again.",
                "🔍"
            ),
            status_code=404
        )

    # Get the download
    download = DatabaseService.get_download_by_id(db, share.download_id)
    if not download:
        return HTMLResponse(
            content=generate_share_error_page(
                "Video Not Found",
                "The video associated with this share link could not be found.",
                "📹"
            ),
            status_code=404
        )

    # Verify video is still public
    if not download.is_public:
        return HTMLResponse(
            content=generate_share_error_page(
                "Video No Longer Public",
                "This video has been made private by the owner and is no longer available for sharing.",
                "🔒"
            ),
            status_code=403
        )

    # Verify video is completed
    if download.status != DownloadStatus.COMPLETED:
        return HTMLResponse(
            content=generate_share_error_page(
                "Video Not Available",
                "This video is not yet available for viewing. It may still be downloading or processing.",
                "⏳"
            ),
            status_code=404
        )

    # Update view count
    share.view_count += 1
    share.last_viewed_at = datetime.now(timezone.utc)
    db.commit()

    # Prepare variables for template substitution
    thumbnail_url = f"/share/{token}/thumbnail" if download.thumbnail else None
    poster_attr = f'poster="{escape(thumbnail_url)}"' if thumbnail_url else ""
    video_url = f"/share/{token}/video"
    filename = download.filename or 'Shared Video'
    view_count = str(share.view_count)
    created_at = share.created_at.strftime('%Y-%m-%d %H:%M UTC')

    # Load the static template and safely substitute placeholders
    try:
        with open(os.path.join("assets", "share.html"), 'r', encoding='utf-8') as f:
            tmpl = f.read()
    except Exception as e:
        return HTMLResponse(content=generate_share_error_page("Template Error", "Unable to load share page template."), status_code=500)

    rendered = (
        tmpl
        .replace("__FILENAME__", escape(filename))
        .replace("__POSTER_ATTR__", poster_attr)
        .replace("__VIDEO_URL__", escape(video_url))
        .replace("__VIEW_COUNT__", escape(view_count))
        .replace("__CREATED_AT__", escape(created_at))
    )

    return HTMLResponse(content=rendered)


@app.get("/share/{token}/video")
async def get_shared_video(token: str, db: Session = Depends(get_db_session)):
    # Serve video file for a shared link, look up the share token
    share = db.query(ShareToken).filter(ShareToken.token == token).first()
    if not share:
        raise HTTPException(status_code=404, detail="Share link not found")

    # Get the download
    download = DatabaseService.get_download_by_id(db, share.download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Video not found")

    # Verify video is still public
    if not download.is_public:
        raise HTTPException(status_code=403, detail="This video is no longer public")

    # Verify video is completed
    if download.status != DownloadStatus.COMPLETED:
        raise HTTPException(status_code=404, detail="Video not available")

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

    # Add caching headers for video files
    file_stat = os.stat(filepath)
    etag = f'"{download.internal_filename}-{int(file_stat.st_mtime)}"'

    headers = {
        'Cache-Control': 'public, max-age=3600, must-revalidate',
        'ETag': etag
    }

    return FileResponse(filepath, media_type=media_type, headers=headers)


@app.get("/share/{token}/thumbnail")
async def get_shared_thumbnail(token: str, db: Session = Depends(get_db_session)):
    # Serve thumbnail for a shared link, look up the share token
    share = db.query(ShareToken).filter(ShareToken.token == token).first()
    if not share:
        raise HTTPException(status_code=404, detail="Share link not found")

    # Get the download
    download = DatabaseService.get_download_by_id(db, share.download_id)
    if not download:
        raise HTTPException(status_code=404, detail="Video not found")

    # Verify video is still public
    if not download.is_public:
        raise HTTPException(status_code=403, detail="This video is no longer public")

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
        raise HTTPException(status_code=403, detail="File type not allowed")

    from fastapi.responses import FileResponse
    media_types = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.webp': 'image/webp'
    }
    media_type = media_types.get(ext, 'image/jpeg')

    # Add caching headers to prevent repeated requests for the same thumbnail
    # ETag based on file modification time for efficient cache validation
    file_stat = os.stat(filepath)
    etag = f'"{download.internal_thumbnail}-{int(file_stat.st_mtime)}"'

    headers = {
        'Cache-Control': 'public, max-age=3600, must-revalidate',
        'ETag': etag
    }

    return FileResponse(filepath, media_type=media_type, headers=headers)


@app.get("/api/files", response_model=List[FileInfo])
async def list_files(current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # List completed downloads visible to the current user.
    try:
        user_id = current_user.get("sub")
        is_admin = current_user.get("is_admin", False)

        # Get completed downloads based on user permissions
        if is_admin:
            # Admins see everything
            completed_downloads = DatabaseService.get_downloads_by_status(db, DownloadStatus.COMPLETED)
        else:
            # Regular users see: public + own private
            completed_downloads = DatabaseService.get_visible_downloads_by_status(
                db, user_id, DownloadStatus.COMPLETED
            )

        files = []
        for download in completed_downloads:
            if download.filename and download.file_size and download.internal_filename:
                # Get username for display
                username = None
                if download.user_id:
                    user = db.query(User).filter(User.id == download.user_id).first()
                    username = user.username if user else "Unknown"

                files.append(FileInfo(
                    id=download.id,
                    filename=download.filename,  # Display name
                    size=download.file_size,
                    user_id=download.user_id,
                    username=username,
                    is_public=download.is_public
                ))

        # Sort by filename alphabetically
        files.sort(key=lambda x: x.filename.lower())

        await emit_log("INFO", "API", f"File list requested, found {len(files)} visible files")
        return files

    except Exception as e:
        await emit_log("ERROR", "API", f"Failed to list files: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/files/{download_id}")
async def delete_file(download_id: str, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Delete a specific file from downloads directory and remove database entry using download ID
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
    # Calculate total size of selected files and estimate ZIP size using download IDs
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
async def download_files_as_zip(request: DownloadZipRequest, current_user: Dict[str, Any] = Depends(get_current_user_optional), db: Session = Depends(get_db_session)):
    # Create and stream a ZIP file containing selected files using download IDs
    try:
        if not request.download_ids:
            raise HTTPException(status_code=400, detail="No files specified")

        await emit_log("INFO", "API", f"Creating streaming ZIP with {len(request.download_ids)} file(s)")

        # Preload download records to avoid database access in generator
        downloads_map = {}
        for download_id in request.download_ids:
            download = DatabaseService.get_download_by_id(db, download_id)
            if download and download.internal_filename and download.filename:
                # Verify access to private downloads
                if not verify_download_access(download, current_user):
                    await emit_log("WARNING", "API", f"Access denied to private download {download_id}")
                    continue  # Skip downloads user doesn't have access to

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


@app.post("/api/tools/video-to-mp3", response_model=ToolConversionResponse)
async def convert_video_to_mp3(request: VideoToMp3Request, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Start a video to MP3 conversion, checks for existing conversion to prevent duplicates.
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
    # List all tool conversions, optionally filtered by status.
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
    # Get specific conversion status by ID.
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
    # Delete a conversion and its output file.
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
    # Cancel an active conversion job, kills the FFmpeg process, cleans up partial files, and marks as failed.
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
    # Stream/download the MP3 audio file for a completed conversion.
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
        # Use application/octet-stream to force download instead of playing in browser
        return FileResponse(
            filepath,
            media_type="application/octet-stream",
            filename=conversion.output_filename
        )

    except HTTPException:
        raise
    except Exception as e:
        await emit_log("ERROR", "ToolConversion", f"Failed to serve audio file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/conversions/cleanup", response_model=ConversionCleanupStats)
async def cleanup_stale_conversions(hours: int = 1, current_user: Dict[str, Any] = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Clean up stale conversions that have been stuck in queued or converting state for longer than the specified number of hours.
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
    # Queue a video transformation, creates a conversion record and adds to processing queue.
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
    # Update compression ratio statistics with new sample
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
    # Get CPU information
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
    # Get memory information in MB
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
    # Get disk information for downloads directory
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
    # Get network interface information
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
    # Detect available hardware acceleration for FFmpeg.
    # Checks for NVIDIA NVENC, AMD AMF, Intel Quick Sync (QSV), and VAAPI.
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
    # Collect all hardware information for caching.
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
    # Get server hardware information (returns cached data).
    global hardware_info_cache

    # If cache is empty (shouldn't happen after startup), populate it
    if hardware_info_cache is None:
        hardware_info_cache = await collect_hardware_info()

    return hardware_info_cache


@app.post("/api/hardware/refresh")
async def refresh_hardware_info(current_admin: Dict[str, Any] = Depends(get_current_admin_user)):
    # Refresh hardware information cache, called when user clicks the "Refresh Hardware Info" button.
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


# ==================== SYSTEM POWER MANAGEMENT ====================

@app.get("/api/health")
async def health_check():
    # Simple health check endpoint., used to verify server is running and responsive.
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/admin/system/power-status")
async def get_power_status(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Get current system power status, returns information about active operations and server uptime.
    global server_start_time, graceful_shutdown_requested

    # Calculate uptime
    uptime_seconds = 0
    if server_start_time:
        uptime_seconds = int((datetime.now(timezone.utc) - server_start_time).total_seconds())

    # Count active operations
    active_downloads = len(download_queue.active_downloads)
    active_conversions = len(active_conversion_processes)


    # Count connected users (WebSocket connections for downloads only)
    connected_users = sum(len(websockets) for websockets in active_connections.values())

    return {
        "active_downloads": active_downloads,
        "active_conversions": active_conversions,
        "connected_users": connected_users,
        "uptime_seconds": uptime_seconds,
        "server_start_time": server_start_time.isoformat() if server_start_time else None,
        "graceful_shutdown_in_progress": graceful_shutdown_requested
    }


@app.post("/api/admin/system/restart-graceful")
async def restart_server_graceful(
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    # Initiate a graceful server restart, waits for all active operations to complete before restarting.
    import signal
    global graceful_shutdown_requested

    # Log the restart action
    await emit_log("WARNING", "Admin", f"Admin {current_admin.get('username')} initiated GRACEFUL server restart")

    # Set flag to stop accepting new work
    graceful_shutdown_requested = True

    # Get current operation counts for response
    active_downloads = len(download_queue.active_downloads)
    active_conversions = len(active_conversion_processes)
    total_active = active_downloads + active_conversions

    # If no active operations, restart immediately
    if total_active == 0:
        await emit_log("INFO", "System", "No active operations - restarting immediately")

        async def trigger_immediate_restart():
            await asyncio.sleep(1)
            await emit_log("WARNING", "System", "Graceful restart triggered - shutting down now")
            await asyncio.sleep(0.5)
            os.kill(os.getpid(), signal.SIGTERM)

        asyncio.create_task(trigger_immediate_restart())

        return {
            "message": "No active operations - restarting immediately",
            "active_downloads": 0,
            "active_conversions": 0,
            "wait_time_estimate": "5-10 seconds"
        }

    # Background task to monitor and trigger restart
    async def monitor_and_restart():
        try:
            await emit_log("INFO", "System", f"Waiting for {total_active} operation(s) to complete before restart...")

            # Monitor every 2 seconds
            while True:
                await asyncio.sleep(2)

                current_downloads = len(download_queue.active_downloads)
                current_conversions = len(active_conversion_processes)
                current_total = current_downloads + current_conversions

                if current_total == 0:
                    # All operations complete, trigger restart
                    await emit_log("INFO", "System", "All operations complete - triggering restart")
                    await asyncio.sleep(1)
                    await emit_log("WARNING", "System", "Graceful restart triggered - shutting down now")
                    await asyncio.sleep(0.5)
                    os.kill(os.getpid(), signal.SIGTERM)
                    break
                else:
                    # Log progress
                    if current_total != total_active:
                        await emit_log("INFO", "System", f"Waiting for {current_total} operation(s) to complete...")

        except Exception as e:
            logger.error(f"Error during graceful restart monitoring: {e}")
            await emit_log("ERROR", "System", f"Graceful restart monitoring failed: {e}")

    # Start monitoring in background
    asyncio.create_task(monitor_and_restart())

    return {
        "message": "Graceful restart initiated - waiting for operations to complete",
        "active_downloads": active_downloads,
        "active_conversions": active_conversions,
        "note": "Server will restart automatically when all operations finish"
    }


@app.post("/api/admin/system/restart-force")
async def restart_server_force(
    # Force restart the server application immediately (ADMIN ONLY).
    current_admin: Dict[str, Any] = Depends(get_current_admin_user)
):
    import signal

    # Log the restart action with FORCE indicator
    await emit_log("WARNING", "Admin", f"Admin {current_admin.get('username')} initiated FORCE server restart")

    # Get current operation counts for response
    active_downloads = len(download_queue.active_downloads)
    active_conversions = len(active_conversion_processes)

    # Schedule shutdown in background to allow response to be sent
    async def trigger_shutdown():
        try:
            # Give the response time to be sent
            await asyncio.sleep(1)

            # Log final message
            await emit_log("WARNING", "System", "Force restart initiated - shutting down now")

            # Give logs time to flush
            await asyncio.sleep(0.5)

            # Send SIGTERM to self - this triggers FastAPI shutdown
            os.kill(os.getpid(), signal.SIGTERM)

        except Exception as e:
            logger.error(f"Error during restart trigger: {e}")

    # Schedule the shutdown
    asyncio.create_task(trigger_shutdown())

    return {
        "message": "Force restart initiated",
        "active_downloads": active_downloads,
        "active_conversions": active_conversions,
        "note": "Operations will resume from database after restart"
    }


# Main app launch 
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
