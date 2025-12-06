/**
 * Video Downloader Frontend Application
 *
 * This JavaScript file handles all frontend functionality including:
 * - Tab navigation between Downloads, Files, Settings, and Logs
 * - Submitting download requests to the backend API
 * - Polling for download updates every 2 seconds
 * - Displaying active and completed downloads
 * - File browsing and management (view, download, delete)
 * - Settings configuration (queue settings, theme, preferences)
 * - Real-time log display with filtering
 * - Toast notifications for user feedback
 *
 * Architecture:
 * - Uses vanilla JavaScript (no frameworks)
 * - Communicates with backend via REST API
 * - Polls for updates using HTTP (not WebSockets, for proxy compatibility)
 * - Updates UI dynamically by manipulating DOM elements
 */

// API Base URL - dynamically determined from current page location
// This allows the app to work in different environments (localhost, production)
const API_BASE = window.location.origin;
const WS_BASE = API_BASE.replace('http', 'ws');

// Map to track active WebSocket connections per download
// Currently not used - switched to HTTP polling for better proxy compatibility
const activeWebSockets = new Map();

/**
 * Display a toast notification to the user
 * Toasts appear at the bottom of the screen and auto-dismiss after 5 seconds
 */
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;  // Type: info, success, warning, error
    toast.textContent = message;
    container.appendChild(toast);

    // Fade out and remove after 5 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

/**
 * Convert bytes to human-readable size format
 * Example: 1536 bytes -> "1.5 KB"
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;  // Use 1024 for binary units (KiB, MiB, etc.)
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Format ISO 8601 date string to locale-specific format
 * Uses the browser's locale settings for formatting
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

/**
 * Calculate and format the duration between two dates
 * Returns human-readable format like "5 minutes 30 seconds"
 */
function calculateDuration(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    const durationMs = end - start;
    const seconds = Math.round(durationMs / 1000);

    // Format based on duration length
    if (seconds < 60) {
        return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes} minute${minutes !== 1 ? 's' : ''} ${remainingSeconds} second${remainingSeconds !== 1 ? 's' : ''}`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours} hour${hours !== 1 ? 's' : ''} ${minutes} minute${minutes !== 1 ? 's' : ''}`;
    }
}

/**
 * Tab Management System
 *
 * Handles switching between the four main tabs:
 * - Downloads: Active and completed downloads
 * - Files: Browse downloaded files
 * - Settings: App configuration
 * - Logs: System and download logs
 *
 * When switching tabs, loads relevant data for that tab.
 */
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.dataset.tab;

            // Update active button styling
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            // Show the selected tab content, hide others
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(`${targetTab}-tab`).classList.add('active');

            // Load tab-specific data when switching
            // This ensures data is fresh when user views the tab
            if (targetTab === 'settings') {
                loadVersionInfo();
                loadDiskSpace();
                loadQueueSettings();
            }

            if (targetTab === 'files') {
                loadFiles();
            }

            // Refresh logs display to apply any active filters
            if (targetTab === 'logs') {
                filterLogs();
            }
        });
    });
}

/**
 * Download Submission Handler
 *
 * Handles the download form submission.
 * Supports multiple URLs (one per line) and optional cookies file.
 *
 * Flow:
 * 1. Parse and validate URLs from textarea
 * 2. Submit each URL as a separate download request
 * 3. Connect WebSocket for progress updates (if used)
 * 4. Show success/failure toast notifications
 * 5. Refresh the downloads list
 * 6. Clear the form
 */
async function submitDownload(event) {
    event.preventDefault();

    const urlsText = document.getElementById('video-url').value.trim();
    const cookiesFile = document.getElementById('cookies-file').value || null;

    if (!urlsText) {
        showToast('Please enter a video URL', 'error');
        return;
    }

    // Parse multiple URLs (one per line)
    // Trim whitespace and filter out empty lines
    const urls = urlsText.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

    if (urls.length === 0) {
        showToast('Please enter at least one valid URL', 'error');
        return;
    }

    // Track how many downloads succeeded and failed
    let successCount = 0;
    let failCount = 0;

    try {
        // Submit each URL as a separate download to the backend
        // This allows tracking and managing each download independently
        for (const url of urls) {
            try {
                const response = await fetch(`${API_BASE}/api/download`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        url,
                        cookies_file: cookiesFile
                    })
                });

                if (!response.ok) {
                    throw new Error('Failed to start download');
                }

                const download = await response.json();

                // Connect WebSocket to receive progress updates for this download
                // Note: Currently not used, using HTTP polling instead
                connectWebSocket(download.id);
                successCount++;

            } catch (error) {
                console.error(`Failed to start download for ${url}:`, error);
                failCount++;
            }
        }

        // Show summary toast
        if (successCount > 0 && failCount === 0) {
            showToast(`${successCount} download${successCount > 1 ? 's' : ''} started!`, 'success');
        } else if (successCount > 0 && failCount > 0) {
            showToast(`${successCount} download${successCount > 1 ? 's' : ''} started, ${failCount} failed`, 'info');
        } else {
            showToast('All downloads failed to start', 'error');
        }

        // Clear form if at least one succeeded
        if (successCount > 0) {
            document.getElementById('video-url').value = '';
        }

        // Refresh downloads list
        setTimeout(() => loadDownloads(), 500);

    } catch (error) {
        showToast('Failed to start downloads: ' + error.message, 'error');
    }
}

/**
 * Load and Display Downloads
 *
 * Fetches all downloads from the API and updates the UI.
 * This function is called:
 * - On page load
 * - Every 5 seconds via setInterval (for live updates)
 * - After submitting new downloads
 *
 * Separates downloads into two lists:
 * - Active: queued, downloading, processing (left panel)
 * - Past: completed, failed (right panel)
 *
 * Active downloads are sorted to show currently downloading first,
 * then processing, then queued.
 */
async function loadDownloads() {
    try {
        const response = await fetch(`${API_BASE}/api/downloads`);
        if (!response.ok) throw new Error('Failed to load downloads');

        const downloads = await response.json();

        // Filter active downloads (currently in progress or queued)
        const active = downloads.filter(d =>
            d.status === 'queued' || d.status === 'downloading' || d.status === 'processing'
        );

        // Sort active downloads by priority
        // Show downloads that are actively processing first, then queued items
        const statusOrder = { 'downloading': 1, 'processing': 2, 'queued': 3 };
        active.sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

        // Filter past downloads (completed or failed)
        const past = downloads.filter(d =>
            d.status === 'completed' || d.status === 'failed'
        );

        // Render both lists
        renderDownloads('active-downloads-list', active);
        renderDownloads('past-downloads-list', past);

        // Connect WebSockets for active downloads to receive real-time updates
        // Note: Currently not actively used, polling provides the updates instead
        active.forEach(download => {
            if (!activeWebSockets.has(download.id)) {
                connectWebSocket(download.id);
            }
        });

    } catch (error) {
        console.error('Failed to load downloads:', error);
    }
}

/**
 * Render Download Cards
 *
 * Generates HTML for a list of downloads and updates the specified container.
 * Each download is rendered as a card with:
 * - Thumbnail (for completed downloads)
 * - Status badge
 * - Progress bar (for active downloads)
 * - File information
 * - Action buttons (view, download, delete)
 *
 * The HTML is dynamically generated based on download status and properties.
 */
function renderDownloads(containerId, downloads) {
    const container = document.getElementById(containerId);

    if (downloads.length === 0) {
        container.innerHTML = '<p class="empty-state">No downloads</p>';
        return;
    }

    container.innerHTML = downloads.map(download => `
        <div class="download-item ${download.status === 'completed' && download.thumbnail ? 'with-thumbnail' : ''}" data-id="${download.id}">
            ${download.status === 'completed' && download.thumbnail ? `
                <div class="download-thumbnail">
                    <img src="${API_BASE}/api/files/thumbnail/${download.id}"
                         alt="Video thumbnail"
                         onerror="this.style.display='none'">
                </div>
            ` : ''}

            <div class="download-content">
                <div class="download-header">
                    <div class="download-url">${download.filename ? escapeHtml(download.filename) : escapeHtml(download.url)}</div>
                    <span class="download-status status-${download.status}">${download.status}</span>
                </div>

                ${download.status === 'downloading' || download.status === 'processing' || download.status === 'queued' ? `
                    <div class="download-progress">
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${download.progress}%"></div>
                        </div>
                        <div class="progress-info">
                            <div class="progress-text">${download.progress.toFixed(1)}%</div>
                            <div class="progress-speed" data-speed></div>
                        </div>
                    </div>
                ` : ''}

                ${download.filename ? `
                    <div class="download-info">
                        <span>Downloaded From: <span class="url-domain" onclick="copyToClipboard('${escapeHtml(download.url).replace(/'/g, "\\'")}', 'URL')" title="Click to copy: ${escapeHtml(download.url)}">${escapeHtml(extractDomain(download.url))}</span></span>
                        ${download.file_size ? `<span>File Size: ${formatBytes(download.file_size)}</span>` : ''}
                    </div>
                ` : ''}

                ${download.error_message ? `
                    <div class="error-message">Error: ${escapeHtml(download.error_message)}</div>
                ` : ''}

                <div class="download-info">
                    <span>ID: ${download.id.substring(0, 8)}...</span>
                    ${download.status === 'completed' && download.completed_at ? `
                        <span>Downloaded in: ${calculateDuration(download.created_at, download.completed_at)}</span>
                    ` : ''}
                    ${download.status === 'downloading' || download.status === 'processing' || download.status === 'queued' ? `
                        <span>Started: ${formatDate(download.created_at)}</span>
                    ` : ''}
                    ${download.status === 'failed' && download.completed_at ? `
                        <span>Failed after: ${calculateDuration(download.created_at, download.completed_at)}</span>
                    ` : ''}
                </div>

                <div class="download-actions">
                    ${download.status === 'completed' && download.filename ? `
                        <button class="btn btn-primary btn-small" onclick="playVideo('${download.id}', '${escapeHtml(download.url)}')">
                            <span>▶</span> Play
                        </button>
                        <button class="btn btn-secondary btn-small" onclick="downloadVideo('${download.id}', '${escapeHtml(download.filename)}')">
                            <span>⬇</span> Download
                        </button>
                    ` : ''}
                    ${download.status === 'failed' ? `
                        <button class="btn btn-secondary btn-small" onclick="retryDownload('${escapeHtml(download.url)}')">Retry</button>
                    ` : ''}
                    <button class="btn btn-danger btn-small" onclick="deleteDownload('${download.id}', event)">Delete</button>
                </div>
            </div>
        </div>
    `).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (e) {
        return url;
    }
}

async function copyToClipboard(text, label = 'URL') {
    try {
        await navigator.clipboard.writeText(text);
        showToast(`${label} copied to clipboard`, 'success');
    } catch (err) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast(`${label} copied to clipboard`, 'success');
        } catch (e) {
            showToast('Failed to copy to clipboard', 'error');
        }
        document.body.removeChild(textarea);
    }
}

function connectWebSocket(downloadId) {
    if (activeWebSockets.has(downloadId)) {
        return; // Already connected
    }

    const ws = new WebSocket(`${WS_BASE}/ws/${downloadId}`);

    ws.onopen = () => {
        console.log(`WebSocket connected for download ${downloadId}`);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateDownloadUI(downloadId, data);
    };

    ws.onerror = (error) => {
        console.error(`WebSocket error for download ${downloadId}:`, error);
    };

    ws.onclose = () => {
        console.log(`WebSocket closed for download ${downloadId}`);
        activeWebSockets.delete(downloadId);
    };

    activeWebSockets.set(downloadId, ws);
}

function updateDownloadUI(downloadId, data) {
    const downloadItem = document.querySelector(`[data-id="${downloadId}"]`);
    if (!downloadItem) return;

    // Update status badge
    const statusBadge = downloadItem.querySelector('.download-status');
    if (statusBadge && data.status) {
        statusBadge.textContent = data.status;
        statusBadge.className = `download-status status-${data.status}`;
    }

    // Update progress
    if (data.progress !== undefined) {
        const progressFill = downloadItem.querySelector('.progress-fill');
        const progressText = downloadItem.querySelector('.progress-text');
        if (progressFill) progressFill.style.width = `${data.progress}%`;
        if (progressText) progressText.textContent = `${data.progress.toFixed(1)}%`;
    }

    // Update download speed
    if (data.speed !== undefined) {
        const progressSpeed = downloadItem.querySelector('.progress-speed');
        if (progressSpeed) {
            if (data.speed) {
                progressSpeed.textContent = `↓ ${data.speed}`;
                progressSpeed.style.display = 'block';
            } else {
                progressSpeed.textContent = '';
                progressSpeed.style.display = 'none';
            }
        }
    }

    // If completed or failed, refresh the list
    if (data.type === 'completed' || data.type === 'failed') {
        setTimeout(() => loadDownloads(), 1000);

        // Close WebSocket
        const ws = activeWebSockets.get(downloadId);
        if (ws) {
            ws.close();
            activeWebSockets.delete(downloadId);
        }

        if (data.type === 'completed') {
            showToast('Download completed!', 'success');
        } else {
            showToast('Download failed: ' + (data.error || 'Unknown error'), 'error');
        }
    }
}

async function deleteDownload(downloadId, event) {
    const button = event?.target.closest('button');

    // Check if button is already in confirm state
    if (button?.dataset.confirmDelete === 'true') {
        // Second click - actually delete
        button.disabled = true;

        try {
            const response = await fetch(`${API_BASE}/api/downloads/${downloadId}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to delete download');

            showToast('Download deleted', 'success');
            loadDownloads();

            // Close WebSocket if active
            const ws = activeWebSockets.get(downloadId);
            if (ws) {
                ws.close();
                activeWebSockets.delete(downloadId);
            }

        } catch (error) {
            showToast('Failed to delete download: ' + error.message, 'error');
            button.disabled = false;
            resetDeleteButton(button);
        }
    } else {
        // First click - show confirmation state
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = 'Confirm Delete?';
            button.classList.add('btn-confirm-delete');

            // Reset after 3 seconds if not clicked again
            setTimeout(() => resetDeleteButton(button), 3000);
        }
    }
}

function resetDeleteButton(button) {
    if (button && button.dataset.confirmDelete === 'true') {
        button.dataset.confirmDelete = 'false';
        button.innerHTML = button.dataset.originalText || 'Delete';
        button.classList.remove('btn-confirm-delete');
        delete button.dataset.originalText;
    }
}

function retryDownload(url) {
    document.getElementById('video-url').value = url;
    document.querySelector('[data-tab="downloads"]').click();
    showToast('URL filled in form. Click Download to retry.', 'info');
}

function downloadVideo(downloadId, displayName) {
    window.open(`${API_BASE}/api/files/download/${downloadId}`, '_blank');
    showToast('Download started', 'success');
}

function playVideo(downloadId, title) {
    // Create modal for video player
    const modal = document.createElement('div');
    modal.className = 'video-modal';
    modal.innerHTML = `
        <div class="video-modal-content">
            <div class="video-modal-header">
                <h3>${escapeHtml(title)}</h3>
                <button class="video-modal-close" onclick="this.closest('.video-modal').remove()">×</button>
            </div>
            <video controls autoplay style="width: 100%; max-height: 70vh;">
                <source src="${API_BASE}/api/files/video/${downloadId}">
                Your browser does not support the video tag.
            </video>
        </div>
    `;

    // Close modal when clicking outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });

    document.body.appendChild(modal);
}

// Settings Management
async function loadVersionInfo() {
    try {
        const response = await fetch(`${API_BASE}/api/settings/version`);
        if (!response.ok) throw new Error('Failed to load version info');

        const data = await response.json();
        document.getElementById('app-version').textContent = data.app_version;
        document.getElementById('ytdlp-version').textContent = data.ytdlp_version;

    } catch (error) {
        showToast('Failed to load version info', 'error');
    }
}

async function loadDiskSpace() {
    try {
        const response = await fetch(`${API_BASE}/api/settings/disk-space`);
        if (!response.ok) throw new Error('Failed to load disk space');

        const data = await response.json();
        document.getElementById('disk-total').textContent = formatBytes(data.total);
        document.getElementById('disk-used').textContent = formatBytes(data.used);
        document.getElementById('disk-free').textContent = formatBytes(data.free);
        document.getElementById('disk-percent').textContent = `${data.percent.toFixed(1)}% used`;
        document.getElementById('disk-usage-bar').style.width = `${data.percent}%`;

    } catch (error) {
        showToast('Failed to load disk space info', 'error');
    }
}

async function loadQueueSettings() {
    try {
        const response = await fetch(`${API_BASE}/api/settings/queue`);
        if (!response.ok) throw new Error('Failed to load queue settings');

        const data = await response.json();
        document.getElementById('max-concurrent').value = data.max_concurrent_downloads || 2;
        document.getElementById('max-speed').value = data.max_download_speed || 0;
        document.getElementById('min-disk-space').value = data.min_disk_space_mb || 1000;

    } catch (error) {
        showToast('Failed to load queue settings', 'error');
    }
}

async function saveQueueSettings() {
    const button = document.getElementById('save-queue-settings-btn');
    button.disabled = true;
    button.textContent = 'Saving...';

    try {
        const settings = {
            max_concurrent_downloads: parseInt(document.getElementById('max-concurrent').value),
            max_download_speed: parseInt(document.getElementById('max-speed').value),
            min_disk_space_mb: parseInt(document.getElementById('min-disk-space').value)
        };

        const response = await fetch(`${API_BASE}/api/settings/queue`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(settings)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Save failed');
        }

        showToast('Queue settings saved successfully!', 'success');

        // Show status message
        const statusDiv = document.getElementById('queue-settings-status');
        statusDiv.textContent = 'Settings saved! Changes will apply to new downloads.';
        statusDiv.className = 'settings-status success';
        statusDiv.style.display = 'block';

        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 5000);

    } catch (error) {
        showToast('Failed to save queue settings: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Save Queue Settings';
    }
}

async function updateYtdlp() {
    const button = document.getElementById('update-ytdlp-btn');
    button.disabled = true;
    button.textContent = 'Updating...';

    try {
        const response = await fetch(`${API_BASE}/api/settings/update-ytdlp`, {
            method: 'POST'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Update failed');
        }

        const result = await response.json();
        showToast('yt-dlp updated successfully!', 'success');

        // Reload version info
        setTimeout(() => loadVersionInfo(), 1000);

    } catch (error) {
        showToast('Failed to update yt-dlp: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Update yt-dlp';
    }
}

async function clearYtdlpCache() {
    const button = document.getElementById('clear-cache-btn');
    
    if (!confirm('Clear yt-dlp cache? This will force re-extraction of video formats on next download.')) {
        return;
    }
    
    button.disabled = true;
    button.textContent = 'Clearing...';

    try {
        const response = await fetch(`${API_BASE}/api/settings/clear-ytdlp-cache`, {
            method: 'POST'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Clear failed');
        }

        const result = await response.json();
        showToast(result.message, 'success');

    } catch (error) {
        showToast('Failed to clear cache: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Clear yt-dlp Cache';
    }
}

async function cleanupDownloads() {
    const button = document.getElementById('cleanup-btn');
    const days = parseInt(document.getElementById('cleanup-days').value);

    if (!confirm(`Remove all failed downloads older than ${days} days and orphaned files?`)) {
        return;
    }

    button.disabled = true;
    button.textContent = 'Cleaning up...';

    try {
        const response = await fetch(`${API_BASE}/api/downloads/cleanup?days=${days}`, {
            method: 'POST'
        });

        if (!response.ok) throw new Error('Cleanup failed');

        const stats = await response.json();

        // Show results
        document.getElementById('cleanup-downloads').textContent = stats.downloads_removed;
        document.getElementById('cleanup-files').textContent = stats.files_removed;
        document.getElementById('cleanup-space').textContent = formatBytes(stats.space_freed);
        document.getElementById('cleanup-stats').style.display = 'block';

        showToast('Cleanup completed successfully!', 'success');

        // Reload disk space and downloads
        loadDiskSpace();
        loadDownloads();

    } catch (error) {
        showToast('Cleanup failed: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Clean Up Failed Downloads';
    }
}

// Load cookie files
async function loadCookieFiles() {
    try {
        const response = await fetch(`${API_BASE}/api/cookies`);
        if (response.ok) {
            const files = await response.json();
            const select = document.getElementById('cookies-file');
            files.forEach(file => {
                const option = document.createElement('option');
                option.value = file;
                option.textContent = file;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.log('No cookies endpoint available');
    }
}

// Logs Management
let logsPollingInterval = null;
let logsPaused = false;
let allLogs = [];
let latestLogSequence = 0;

function formatLogTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString() + '.' + date.getMilliseconds().toString().padStart(3, '0');
}

function renderLogEntry(log) {
    const entry = document.createElement('div');
    entry.className = `log-entry level-${log.level}`;

    const timestamp = document.createElement('span');
    timestamp.className = 'log-timestamp';
    timestamp.textContent = formatLogTimestamp(log.timestamp);

    const level = document.createElement('span');
    level.className = `log-level ${log.level}`;
    level.textContent = log.level;

    const component = document.createElement('span');
    component.className = 'log-component';
    component.textContent = `[${log.component}]`;

    const message = document.createElement('span');
    message.className = 'log-message';
    message.textContent = log.message;

    entry.appendChild(timestamp);
    entry.appendChild(level);
    entry.appendChild(component);
    entry.appendChild(message);

    if (log.download_id) {
        const downloadId = document.createElement('span');
        downloadId.className = 'log-download-id';
        downloadId.textContent = `(${log.download_id.substring(0, 8)}...)`;
        entry.appendChild(downloadId);
    }

    return entry;
}

function filterLogs() {
    const levelFilter = document.getElementById('log-level-filter').value;
    const componentFilter = document.getElementById('log-component-filter').value;
    const downloadIdFilter = document.getElementById('log-download-filter').value.trim();

    console.log(`🔍 Filtering logs: Total=${allLogs.length}, Level='${levelFilter}', Component='${componentFilter}', DownloadID='${downloadIdFilter}'`);

    let filtered = allLogs;

    if (levelFilter) {
        filtered = filtered.filter(log => log.level === levelFilter);
    }

    if (componentFilter) {
        filtered = filtered.filter(log => log.component === componentFilter);
    }

    if (downloadIdFilter) {
        filtered = filtered.filter(log => log.download_id && log.download_id.includes(downloadIdFilter));
    }

    console.log(`✅ After filtering: ${filtered.length} logs to display`);
    displayLogs(filtered);
}

function displayLogs(logs) {
    const display = document.getElementById('logs-display');
    display.innerHTML = '';

    if (logs.length === 0) {
        const isPolling = logsPollingInterval !== null;

        if (isPolling) {
            display.innerHTML = '<p class="empty-state">✅ Connected to log system. Logs will appear here as events occur...</p>';
        } else {
            display.innerHTML = '<p class="empty-state">❌ Log polling not running. Check browser console for errors.</p>';
        }
        return;
    }

    logs.forEach(log => {
        display.appendChild(renderLogEntry(log));
    });

    // Auto-scroll to bottom if not paused
    if (!logsPaused) {
        display.scrollTop = display.scrollHeight;
    }
}


async function pollLogs() {
    try {
        // Build query parameters
        const params = new URLSearchParams();
        if (latestLogSequence > 0) {
            params.append('since_sequence', latestLogSequence);
        }

        const response = await fetch(`${API_BASE}/api/logs?${params}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        // Debug logging (only first 10 polls or if new logs received)
        if (!pollLogs.callCount) pollLogs.callCount = 0;
        pollLogs.callCount++;

        if (pollLogs.callCount <= 10 || data.logs.length > 0) {
            console.log(`📨 Poll #${pollLogs.callCount}: Received ${data.logs.length} new logs (seq: ${latestLogSequence} → ${data.latest_sequence})`);
        }

        // Update latest sequence
        if (data.latest_sequence > 0) {
            latestLogSequence = data.latest_sequence;
        }

        // Add new logs
        data.logs.forEach(log => {
            allLogs.push(log);

            // Keep only last 1000 logs in browser
            if (allLogs.length > 1000) {
                allLogs.shift();
            }
        });

        // Update display if logs tab is active and not paused and we have new logs
        if (data.logs.length > 0) {
            const logsTab = document.getElementById('logs-tab');
            if (logsTab && logsTab.classList.contains('active') && !logsPaused) {
                filterLogs();
            }
        }

    } catch (error) {
        console.error('❌ Failed to poll logs:', error);
    }
}

function startLogsPolling() {
    if (logsPollingInterval) {
        console.log('⚠️  Logs polling already running');
        return;
    }

    console.log('✅ Starting logs polling (every 5 seconds)');

    // Poll immediately
    pollLogs();

    // Then poll every 5 seconds
    logsPollingInterval = setInterval(pollLogs, 5000);
}

function stopLogsPolling() {
    if (logsPollingInterval) {
        console.log('🛑 Stopping logs polling');
        clearInterval(logsPollingInterval);
        logsPollingInterval = null;
    }
}

function clearLogsDisplay() {
    allLogs = [];
    document.getElementById('logs-display').innerHTML = '<p class="empty-state">Display cleared. Waiting for new logs...</p>';
}

function toggleLogsPause() {
    logsPaused = !logsPaused;
    const button = document.getElementById('pause-logs-btn');
    button.textContent = logsPaused ? 'Resume' : 'Pause';
    button.classList.toggle('btn-primary', logsPaused);
    button.classList.toggle('btn-secondary', !logsPaused);
}

async function testLog() {
    console.log('🧪 Testing log emission...');
    try {
        const response = await fetch(`${API_BASE}/api/logs/test`, {
            method: 'POST'
        });
        const data = await response.json();
        console.log('✅ Test log API response:', data);
        console.log(`📡 WebSocket clients on server: ${data.websocket_clients}`);
        console.log(`📝 Logs in browser memory: ${allLogs.length}`);
        showToast(`Test log sent! WebSocket clients: ${data.websocket_clients}`, 'info');
    } catch (error) {
        console.error('❌ Test log failed:', error);
        showToast('Failed to send test log: ' + error.message, 'error');
    }
}

// Preferences Management
function initPreferences() {
    // Load theme preference
    const savedTheme = localStorage.getItem('theme') || 'dark';
    applyTheme(savedTheme);
    document.getElementById('theme-toggle').checked = savedTheme === 'dark';

    // Load color theme preference
    const savedColorTheme = localStorage.getItem('colorTheme') || 'synthwave';
    applyColorTheme(savedColorTheme);
    document.getElementById('color-theme-select').value = savedColorTheme;

    // Load auto-cookie preference
    const autoCookie = localStorage.getItem('autoCookie') === 'true';
    document.getElementById('auto-cookie-toggle').checked = autoCookie;
}

function applyTheme(theme) {
    if (theme === 'light') {
        document.body.setAttribute('data-theme', 'light');
    } else {
        document.body.removeAttribute('data-theme');
    }
    localStorage.setItem('theme', theme);
}

function applyColorTheme(colorTheme) {
    document.body.setAttribute('data-color-theme', colorTheme);
    localStorage.setItem('colorTheme', colorTheme);
}

function toggleTheme() {
    const isDark = document.getElementById('theme-toggle').checked;
    const theme = isDark ? 'dark' : 'light';
    applyTheme(theme);
    showToast(`Switched to ${theme} mode`, 'info');
}

function changeColorTheme() {
    const colorTheme = document.getElementById('color-theme-select').value;
    applyColorTheme(colorTheme);

    const themeNames = {
        'synthwave': 'Synthwave',
        'sunset': 'Sunset',
        'blossom': 'Blossom',
        'graphite': 'Graphite',
        'forest': 'Forest',
        'solarized': 'Solarized',
        'arctic': 'Arctic',
        'aqua': 'Aqua'
    };

    showToast(`Switched to ${themeNames[colorTheme]} theme`, 'success');
}

function toggleAutoCookie() {
    const enabled = document.getElementById('auto-cookie-toggle').checked;
    localStorage.setItem('autoCookie', enabled);
    showToast(`Auto-cookie selection ${enabled ? 'enabled' : 'disabled'}`, 'info');
}

function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        // Extract main domain (e.g., instagram.com from www.instagram.com)
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts[parts.length - 2]; // e.g., "instagram" from "www.instagram.com"
        }
        return hostname;
    } catch (e) {
        return null;
    }
}

function handleUrlInput(event) {
    const urlsText = event.target.value.trim();
    const cookieSelect = document.getElementById('cookies-file');

    if (!urlsText) return;

    // Split URLs by newline and filter out empty lines
    const urls = urlsText.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

    // If multiple URLs, default to "None"
    if (urls.length > 1) {
        cookieSelect.value = '';
        return;
    }

    // Single URL: try auto-cookie selection if enabled
    const autoCookieEnabled = localStorage.getItem('autoCookie') === 'true';
    if (!autoCookieEnabled) return;

    const url = urls[0];
    const domain = extractDomain(url);
    if (!domain) return;

    // Try to find matching cookie file
    const options = Array.from(cookieSelect.options);

    // Look for exact match (e.g., instagram.txt for instagram.com)
    const matchingOption = options.find(option => {
        const optionValue = option.value.toLowerCase();
        return optionValue === `${domain}.txt` || optionValue.startsWith(`${domain}.`);
    });

    if (matchingOption) {
        cookieSelect.value = matchingOption.value;
        showToast(`Auto-selected ${matchingOption.value}`, 'info');
    }
}

// File Browser Management
let selectedFiles = new Set();

async function loadFiles() {
    try {
        const response = await fetch(`${API_BASE}/api/files`);
        if (!response.ok) throw new Error('Failed to load files');

        const files = await response.json();
        renderFiles(files);

    } catch (error) {
        console.error('Failed to load files:', error);
        document.getElementById('files-list').innerHTML = '<p class="empty-state">Failed to load files</p>';
    }
}

function renderFiles(files) {
    const container = document.getElementById('files-list');

    if (files.length === 0) {
        container.innerHTML = '<p class="empty-state">No files found</p>';
        return;
    }

    container.innerHTML = files.map(file => {
        return `
        <div class="file-item" data-download-id="${file.id}">
            <input type="checkbox" class="file-checkbox">
            <div class="file-info">
                <span class="file-name">${escapeHtml(file.filename)}</span>
                <span class="file-size">${formatBytes(file.size)}</span>
            </div>
            <div class="file-actions">
                <button class="btn btn-secondary btn-small file-download-btn" title="Download file">
                    <span>⬇</span> Download
                </button>
                <button class="btn btn-danger btn-small file-delete-btn" title="Delete file">
                    <span>🗑</span> Delete
                </button>
            </div>
        </div>
        `;
    }).join('');

    // Add event listeners after rendering
    attachFileEventListeners();
    updateFileActionButtons();
}

function attachFileEventListeners() {
    // Add event listeners to all checkboxes
    document.querySelectorAll('.file-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const fileItem = this.closest('.file-item');
            const downloadId = fileItem.dataset.downloadId;
            toggleFileSelection(downloadId, this.checked);
        });
    });

    // Add event listeners to all download buttons
    document.querySelectorAll('.file-download-btn').forEach(button => {
        button.addEventListener('click', function() {
            const fileItem = this.closest('.file-item');
            const downloadId = fileItem.dataset.downloadId;
            const filename = fileItem.querySelector('.file-name').textContent;
            downloadVideo(downloadId, filename);
        });
    });

    // Add event listeners to all delete buttons
    document.querySelectorAll('.file-delete-btn').forEach(button => {
        button.addEventListener('click', function(event) {
            const fileItem = this.closest('.file-item');
            const downloadId = fileItem.dataset.downloadId;
            deleteFile(downloadId, event);
        });
    });
}

function toggleFileSelection(downloadId, checked) {
    const fileItem = document.querySelector(`.file-item[data-download-id="${downloadId}"]`);

    if (checked) {
        selectedFiles.add(downloadId);
        fileItem.classList.add('selected');
    } else {
        selectedFiles.delete(downloadId);
        fileItem.classList.remove('selected');
    }

    updateFileActionButtons();
    updateSelectAllButton();
}

function updateFileActionButtons() {
    const downloadBtn = document.getElementById('download-selected-btn');
    const deleteBtn = document.getElementById('delete-selected-btn');
    const hasSelection = selectedFiles.size > 0;

    downloadBtn.disabled = !hasSelection;
    deleteBtn.disabled = !hasSelection;

    if (hasSelection) {
        downloadBtn.textContent = `⬇ Download ${selectedFiles.size} file${selectedFiles.size > 1 ? 's' : ''} as ZIP`;
        deleteBtn.textContent = `🗑 Delete ${selectedFiles.size} file${selectedFiles.size > 1 ? 's' : ''}`;
    } else {
        downloadBtn.innerHTML = '<span>⬇</span> Download as ZIP';
        deleteBtn.innerHTML = '<span>🗑</span> Delete Selected';
    }
}

function updateSelectAllButton() {
    const selectAllBtn = document.getElementById('select-all-files-btn');
    const allCheckboxes = document.querySelectorAll('.file-checkbox');
    const allChecked = allCheckboxes.length > 0 &&
                       Array.from(allCheckboxes).every(cb => cb.checked);

    selectAllBtn.textContent = allChecked ? 'Deselect All' : 'Select All';
}

function toggleSelectAll() {
    const allCheckboxes = document.querySelectorAll('.file-checkbox');
    const selectAllBtn = document.getElementById('select-all-files-btn');
    const shouldSelect = selectAllBtn.textContent === 'Select All';

    allCheckboxes.forEach(checkbox => {
        checkbox.checked = shouldSelect;
        const fileItem = checkbox.closest('.file-item');
        const downloadId = fileItem.dataset.downloadId;
        toggleFileSelection(downloadId, shouldSelect);
    });
}

async function deleteFile(downloadId, event) {
    const button = event?.target.closest('button');
    const fileItem = document.querySelector(`.file-item[data-download-id="${downloadId}"]`);
    const filename = fileItem ? fileItem.querySelector('.file-name').textContent : 'this file';

    // Check if button is already in confirm state
    if (button?.dataset.confirmDelete === 'true') {
        // Second click - actually delete
        button.disabled = true;

        try {
            const response = await fetch(`${API_BASE}/api/files/${downloadId}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to delete file');

            showToast('File deleted successfully', 'success');
            selectedFiles.delete(downloadId);
            loadFiles();

            // Also reload downloads list to update the Downloads tab
            loadDownloads();

        } catch (error) {
            showToast('Failed to delete file: ' + error.message, 'error');
            button.disabled = false;
            resetDeleteButton(button);
        }
    } else {
        // First click - show confirmation state
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.innerHTML;
            button.innerHTML = '<span>✓</span> Confirm?';
            button.classList.add('btn-confirm-delete');

            // Reset after 3 seconds if not clicked again
            setTimeout(() => resetDeleteButton(button), 3000);
        }
    }
}

async function deleteSelectedFiles(event) {
    if (selectedFiles.size === 0) return;

    const button = event?.target.closest('button');
    const count = selectedFiles.size;

    // Check if button is already in confirm state
    if (button?.dataset.confirmDelete === 'true') {
        // Second click - actually delete
        button.disabled = true;
        const originalText = button.dataset.originalText;

        let successCount = 0;
        let failCount = 0;

        for (const downloadId of selectedFiles) {
            try {
                const response = await fetch(`${API_BASE}/api/files/${downloadId}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    successCount++;
                } else {
                    failCount++;
                }
            } catch (error) {
                console.error(`Failed to delete ${downloadId}:`, error);
                failCount++;
            }
        }

        if (successCount > 0 && failCount === 0) {
            showToast(`${successCount} file${successCount > 1 ? 's' : ''} deleted successfully`, 'success');
        } else if (successCount > 0 && failCount > 0) {
            showToast(`${successCount} file${successCount > 1 ? 's' : ''} deleted, ${failCount} failed`, 'info');
        } else {
            showToast('Failed to delete files', 'error');
        }

        selectedFiles.clear();
        loadFiles();
        loadDownloads();

        // Reset button state
        if (button) {
            button.disabled = false;
            resetDeleteButton(button);
        }
    } else {
        // First click - show confirmation state
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.textContent;
            button.textContent = `Confirm Delete ${count} file${count > 1 ? 's' : ''}?`;
            button.classList.add('btn-confirm-delete');

            // Reset after 3 seconds if not clicked again
            setTimeout(() => resetDeleteButton(button), 3000);
        }
    }
}

async function downloadSelectedAsZip() {
    if (selectedFiles.size === 0) return;

    const download_ids = Array.from(selectedFiles);
    const downloadBtn = document.getElementById('download-selected-btn');
    const originalBtnContent = downloadBtn.innerHTML;

    try {
        // Disable button and show calculating state
        downloadBtn.disabled = true;
        downloadBtn.innerHTML = '<span>🔢</span> Calculating...';

        // First, calculate the estimated size
        const sizeResponse = await fetch(`${API_BASE}/api/files/calculate-zip-size`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ download_ids })
        });

        if (sizeResponse.ok) {
            const sizeData = await sizeResponse.json();
            const estimatedSize = formatBytes(sizeData.estimated_zip_size);
            const totalSize = formatBytes(sizeData.total_size);
            const compressionPct = Math.round((1 - sizeData.compression_ratio) * 100);

            // Show size estimation with compression info
            showToast(
                `Preparing ZIP with ${sizeData.file_count} file${sizeData.file_count > 1 ? 's' : ''}... ` +
                `Total: ${totalSize} → Estimated ZIP: ${estimatedSize} (~${compressionPct}% compression)`,
                'info'
            );
        }

        // Update button to creating state
        downloadBtn.innerHTML = '<span>⏳</span> Creating ZIP...';

        const response = await fetch(`${API_BASE}/api/files/download-zip`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ download_ids })
        });

        if (!response.ok) throw new Error('Failed to create zip');

        // Update button to show download in progress
        downloadBtn.innerHTML = '<span>⬇</span> Downloading...';

        // Get the blob and create a download link
        const blob = await response.blob();
        const actualSize = formatBytes(blob.size);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `videos-${Date.now()}.zip`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showToast(`Downloaded ${selectedFiles.size} file${selectedFiles.size > 1 ? 's' : ''} as ZIP (${actualSize})`, 'success');

    } catch (error) {
        showToast('Failed to download as ZIP: ' + error.message, 'error');
    } finally {
        // Restore button state
        downloadBtn.disabled = false;
        downloadBtn.innerHTML = originalBtnContent;
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize preferences first
    initPreferences();

    // Initialize tabs
    initTabs();

    // Download form submission
    document.getElementById('new-download-form').addEventListener('submit', submitDownload);

    // URL input for auto-cookie selection
    document.getElementById('video-url').addEventListener('input', handleUrlInput);

    // Settings buttons
    document.getElementById('save-queue-settings-btn').addEventListener('click', saveQueueSettings);
    document.getElementById('update-ytdlp-btn').addEventListener('click', updateYtdlp);
    document.getElementById('clear-cache-btn').addEventListener('click', clearYtdlpCache);
    document.getElementById('cleanup-btn').addEventListener('click', cleanupDownloads);

    // Preference toggles
    document.getElementById('theme-toggle').addEventListener('change', toggleTheme);
    document.getElementById('color-theme-select').addEventListener('change', changeColorTheme);
    document.getElementById('auto-cookie-toggle').addEventListener('change', toggleAutoCookie);

    // Logs controls
    document.getElementById('log-level-filter').addEventListener('change', filterLogs);
    document.getElementById('log-component-filter').addEventListener('change', filterLogs);
    document.getElementById('log-download-filter').addEventListener('input', filterLogs);
    document.getElementById('test-log-btn').addEventListener('click', testLog);
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogsDisplay);
    document.getElementById('pause-logs-btn').addEventListener('click', toggleLogsPause);

    // File browser controls
    document.getElementById('select-all-files-btn').addEventListener('click', toggleSelectAll);
    document.getElementById('download-selected-btn').addEventListener('click', downloadSelectedAsZip);
    document.getElementById('delete-selected-btn').addEventListener('click', deleteSelectedFiles);

    // Initial data load
    loadDownloads();
    loadCookieFiles();

    // Start logs polling on page load
    console.log('='.repeat(60));
    console.log('🚀 INITIALIZING LOGS SYSTEM (HTTP Polling)');
    console.log('='.repeat(60));
    console.log('🌐 API Base:', API_BASE);
    console.log('📍 Logs endpoint:', `${API_BASE}/api/logs`);
    console.log('⏱️  Poll interval: 5 seconds');
    console.log('='.repeat(60));
    startLogsPolling();

    // Auto-refresh downloads every 5 seconds
    setInterval(loadDownloads, 5000);
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    activeWebSockets.forEach(ws => ws.close());
    stopLogsPolling();
});
