/**
 * Video Downloader Frontend Application
 *
 * Handles download management, file browsing, settings, logs, and tools.
 * Uses vanilla JavaScript with REST API polling for updates.
 */

const API_BASE = window.location.origin;
const WS_BASE = API_BASE.replace('http', 'ws');

// WebSocket tracking (available but HTTP polling is default for compatibility)
const activeWebSockets = new Map();

// Interval ID for updating running time counters on active conversions
let runningTimeInterval = null;

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
 * Show error message for a form field
 */
function showFormError(fieldId, message) {
    const field = document.getElementById(fieldId);
    const errorElement = document.getElementById(`${fieldId}-error`);

    if (!field || !errorElement) return;

    // Add visual error styling
    field.classList.add('input-error');
    errorElement.textContent = message;
    errorElement.classList.add('show');

    // Add ARIA attributes if accessibility is enabled
    const accessibilityEnabled = localStorage.getItem('accessibility') === 'true';
    if (accessibilityEnabled) {
        field.setAttribute('aria-invalid', 'true');
        field.setAttribute('aria-describedby', `${fieldId}-error`);
    }

    // Focus the field with error
    field.focus();
}

/**
 * Clear error message for a form field
 */
function clearFormError(fieldId) {
    const field = document.getElementById(fieldId);
    const errorElement = document.getElementById(`${fieldId}-error`);

    if (!field || !errorElement) return;

    // Remove visual error styling
    field.classList.remove('input-error');
    errorElement.textContent = '';
    errorElement.classList.remove('show');

    // Remove ARIA attributes
    field.removeAttribute('aria-invalid');
    field.removeAttribute('aria-describedby');
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
/**
 * Format a date/time string for display in the user's local timezone
 * Automatically converts UTC timestamps to browser's local timezone
 * No permissions needed - uses browser's built-in Intl API
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    // toLocaleString automatically converts from UTC to browser's local timezone
    // Format: "12/13/2025, 3:45:30 PM" (varies by browser locale)
    return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });
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
    const accessibilityEnabled = localStorage.getItem('accessibility') === 'true';

    // Add ARIA attributes if accessibility is enabled
    if (accessibilityEnabled) {
        const tabsContainer = document.querySelector('.tabs');
        tabsContainer.setAttribute('role', 'tablist');
        tabsContainer.setAttribute('aria-label', 'Main navigation');

        tabButtons.forEach((button, index) => {
            const targetTab = button.dataset.tab;
            button.setAttribute('role', 'tab');
            button.setAttribute('id', `tab-${targetTab}`);
            button.setAttribute('aria-controls', `${targetTab}-tab`);
            button.setAttribute('aria-selected', button.classList.contains('active') ? 'true' : 'false');
            button.setAttribute('tabindex', button.classList.contains('active') ? '0' : '-1');
        });

        tabContents.forEach(content => {
            const tabId = content.id.replace('-tab', '');
            content.setAttribute('role', 'tabpanel');
            content.setAttribute('aria-labelledby', `tab-${tabId}`);
            content.setAttribute('tabindex', '0');
        });

        // Add keyboard navigation
        tabButtons.forEach(button => {
            button.addEventListener('keydown', (e) => {
                handleTabKeyNavigation(e, tabButtons);
            });
        });
    }

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.dataset.tab;

            // Update active button styling
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            // Update ARIA attributes if accessibility is enabled
            if (accessibilityEnabled) {
                tabButtons.forEach(btn => {
                    btn.setAttribute('aria-selected', 'false');
                    btn.setAttribute('tabindex', '-1');
                });
                button.setAttribute('aria-selected', 'true');
                button.setAttribute('tabindex', '0');
            }

            // Show the selected tab content, hide others
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(`${targetTab}-tab`).classList.add('active');

            // Load tab-specific data when switching
            // This ensures data is fresh when user views the tab
            if (targetTab === 'settings') {
                loadVersionInfo();
                loadQueueSettings();
                loadHardwareInfo();
                loadCookieFilesSettings();
            }

            if (targetTab === 'files') {
                loadFiles();
            }

            if (targetTab === 'tools') {
                loadToolsTab();
            }

            // Refresh logs display to apply any active filters
            if (targetTab === 'logs') {
                filterLogs();
            }
        });
    });
}

/**
 * Handle keyboard navigation for tabs (arrow keys)
 */
function handleTabKeyNavigation(e, tabButtons) {
    const currentIndex = Array.from(tabButtons).indexOf(e.target);
    let targetIndex;

    switch (e.key) {
        case 'ArrowLeft':
        case 'ArrowUp':
            e.preventDefault();
            targetIndex = currentIndex === 0 ? tabButtons.length - 1 : currentIndex - 1;
            tabButtons[targetIndex].focus();
            tabButtons[targetIndex].click();
            break;
        case 'ArrowRight':
        case 'ArrowDown':
            e.preventDefault();
            targetIndex = currentIndex === tabButtons.length - 1 ? 0 : currentIndex + 1;
            tabButtons[targetIndex].focus();
            tabButtons[targetIndex].click();
            break;
        case 'Home':
            e.preventDefault();
            tabButtons[0].focus();
            tabButtons[0].click();
            break;
        case 'End':
            e.preventDefault();
            tabButtons[tabButtons.length - 1].focus();
            tabButtons[tabButtons.length - 1].click();
            break;
    }
}

/**
 * Show dialog for duplicate URLs
 */
function showDuplicateDialog(duplicates, newUrls) {
    return new Promise((resolve) => {
        const accessibilityEnabled = localStorage.getItem('accessibility') === 'true';
        const previousFocus = document.activeElement;

        const modal = document.createElement('div');
        modal.className = 'duplicate-modal';

        const duplicatesList = duplicates.map(dup => {
            const statusBadge = dup.status === 'completed' ? '✅' :
                               dup.status === 'failed' ? '❌' : '⏳';
            const displayName = dup.filename || new URL(dup.url).hostname;
            // Format date in user's local timezone with date and time
            const downloadDate = new Date(dup.created_at).toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit'
            });
            return `
                <div class="duplicate-item">
                    <span class="duplicate-status">${statusBadge}</span>
                    <div class="duplicate-info">
                        <strong>${escapeHtml(displayName)}</strong>
                        <span class="duplicate-meta">Status: ${dup.status} • Downloaded: ${downloadDate}</span>
                    </div>
                </div>
            `;
        }).join('');

        modal.innerHTML = `
            <div class="duplicate-modal-content">
                <div class="duplicate-modal-header">
                    <h3>Duplicate URLs Detected</h3>
                </div>
                <div class="duplicate-modal-body">
                    <p><strong>${duplicates.length}</strong> URL${duplicates.length > 1 ? 's' : ''} already exist${duplicates.length === 1 ? 's' : ''} in your downloads:</p>
                    <div class="duplicates-list">
                        ${duplicatesList}
                    </div>
                    ${newUrls.length > 0 ? `<p style="margin-top: 1rem; color: var(--text-muted);"><strong>${newUrls.length}</strong> new URL${newUrls.length > 1 ? 's' : ''} will be downloaded.</p>` : ''}
                    <p style="margin-top: 1rem;">What would you like to do?</p>
                </div>
                <div class="duplicate-modal-actions">
                    <button class="btn btn-secondary duplicate-skip-btn">Skip Duplicates</button>
                    <button class="btn btn-primary duplicate-download-btn">Download All Anyway</button>
                    <button class="btn btn-danger duplicate-cancel-btn">Cancel</button>
                </div>
            </div>
        `;

        // Add ARIA if accessibility enabled
        if (accessibilityEnabled) {
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            modal.setAttribute('aria-labelledby', 'duplicate-dialog-title');
        }

        const closeDialog = (result) => {
            modal.remove();
            if (accessibilityEnabled && previousFocus) {
                previousFocus.focus();
            }
            resolve(result);
        };

        // Button handlers
        modal.querySelector('.duplicate-skip-btn').addEventListener('click', () => {
            // Only download new URLs
            closeDialog({ proceed: true, skipDuplicates: true });
        });

        modal.querySelector('.duplicate-download-btn').addEventListener('click', () => {
            // Download all URLs including duplicates
            closeDialog({ proceed: true, skipDuplicates: false });
        });

        modal.querySelector('.duplicate-cancel-btn').addEventListener('click', () => {
            closeDialog({ proceed: false });
        });

        // Close on outside click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeDialog({ proceed: false });
            }
        });

        // Escape key handler
        const handleEscape = (e) => {
            if (e.key === 'Escape') {
                closeDialog({ proceed: false });
                document.removeEventListener('keydown', handleEscape);
            }
        };
        document.addEventListener('keydown', handleEscape);

        document.body.appendChild(modal);

        // Focus first button
        setTimeout(() => modal.querySelector('.duplicate-skip-btn').focus(), 100);
    });
}

/**
 * Check for duplicate URLs in existing downloads
 */
async function checkDuplicateUrls(urls) {
    try {
        const response = await fetch(`${API_BASE}/api/downloads`);
        if (!response.ok) return { duplicates: [], newUrls: urls };

        const downloads = await response.json();
        const existingUrls = new Map();

        // Build map of existing URLs with their download info
        downloads.forEach(download => {
            existingUrls.set(download.url, {
                id: download.id,
                status: download.status,
                filename: download.filename,
                created_at: download.created_at
            });
        });

        const duplicates = [];
        const newUrls = [];

        urls.forEach(url => {
            if (existingUrls.has(url)) {
                const existing = existingUrls.get(url);
                duplicates.push({
                    url: url,
                    ...existing
                });
            } else {
                newUrls.push(url);
            }
        });

        return { duplicates, newUrls };
    } catch (error) {
        console.error('Failed to check for duplicates:', error);
        // On error, proceed with all URLs
        return { duplicates: [], newUrls: urls };
    }
}

/**
 * Download Submission Handler
 *
 * Handles the download form submission.
 * Supports multiple URLs (one per line) and optional cookies file.
 *
 * Flow:
 * 1. Parse and validate URLs from textarea
 * 2. Check for duplicate URLs
 * 3. Submit each URL as a separate download request
 * 4. Connect WebSocket for progress updates (if used)
 * 5. Show success/failure toast notifications
 * 6. Refresh the downloads list
 * 7. Clear the form
 */
async function submitDownload(event) {
    event.preventDefault();

    // Clear any previous errors
    clearFormError('video-url');

    const urlsText = document.getElementById('video-url').value.trim();
    const cookiesFile = document.getElementById('cookies-file').value || null;

    if (!urlsText) {
        showFormError('video-url', 'Please enter a video URL');
        return;
    }

    // Parse multiple URLs (one per line)
    // Trim whitespace and filter out empty lines
    const urls = urlsText.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);

    if (urls.length === 0) {
        showFormError('video-url', 'Please enter at least one valid URL');
        return;
    }

    // Clear error if validation passed
    clearFormError('video-url');

    // Check for duplicates
    const { duplicates, newUrls } = await checkDuplicateUrls(urls);

    // Determine which URLs to download
    let urlsToDownload = urls;

    // If there are duplicates, ask user what to do
    if (duplicates.length > 0) {
        const result = await showDuplicateDialog(duplicates, newUrls);
        if (!result.proceed) {
            return; // User cancelled
        }

        // If skipping duplicates, only download new URLs
        if (result.skipDuplicates) {
            urlsToDownload = newUrls;
            if (newUrls.length === 0) {
                showToast('No new URLs to download', 'info');
                return;
            }
        }
    }

    // Track how many downloads succeeded and failed
    let successCount = 0;
    let failCount = 0;

    try {
        // Submit each URL as a separate download to the backend
        // This allows tracking and managing each download independently
        for (const url of urlsToDownload) {
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
                    // Enhanced error messages based on HTTP status code
                    let errorMessage = 'Failed to start download';
                    if (response.status === 400) {
                        errorMessage = 'Invalid URL format. Please check the URL and try again.';
                    } else if (response.status === 403) {
                        errorMessage = 'Access denied. This video may require a cookie file.';
                    } else if (response.status === 429) {
                        errorMessage = 'Rate limited. Please wait a few minutes before trying again.';
                    } else if (response.status === 507) {
                        errorMessage = 'Not enough disk space. Free up space or adjust threshold in Settings.';
                    } else {
                        // Try to get error details from response
                        try {
                            const errorData = await response.json();
                            errorMessage = errorData.detail || 'Download failed. Check the Logs tab for details.';
                        } catch {
                            errorMessage = 'Download failed. Check the Logs tab for details.';
                        }
                    }
                    throw new Error(errorMessage);
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
 * Video Upload Handler
 *
 * Handles uploading video files directly to the server.
 * Uploaded videos appear in the file list and can be used with tools.
 */
async function submitVideoUpload(event) {
    event.preventDefault();

    const fileInput = document.getElementById('video-file-input');
    const uploadBtn = document.getElementById('upload-video-btn');

    if (!fileInput.files || fileInput.files.length === 0) {
        showToast('Please select a video file', 'error');
        return;
    }

    const file = fileInput.files[0];
    await uploadFile(file, fileInput, uploadBtn);
}

/**
 * Perform the actual file upload
 */
async function uploadFile(file, fileInput, uploadBtn) {
    // Validate file extension
    const allowedExtensions = ['.mp4', '.mkv', '.webm', '.avi', '.mov'];
    const fileExt = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

    if (!allowedExtensions.includes(fileExt)) {
        showToast('Invalid file type. Allowed: MP4, MKV, WebM, AVI, MOV', 'error');
        return;
    }

    // Validate file size (matches backend limit)
    const maxSizeMB = 2048; // 2GB limit
    const maxSizeBytes = maxSizeMB * 1024 * 1024;

    if (file.size > maxSizeBytes) {
        showToast(`File too large. Maximum size is ${maxSizeMB / 1024} GB`, 'error');
        return;
    }

    // Create FormData for file upload
    const formData = new FormData();
    formData.append('file', file);

    try {
        // Disable upload button during upload
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = '<span>⏳</span> Uploading...';

        const response = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            // Enhanced error messages based on HTTP status code
            let errorMessage = 'Upload failed';
            if (response.status === 400) {
                errorMessage = 'Invalid file format. Please check the file type and try again.';
            } else if (response.status === 413) {
                errorMessage = 'File too large for upload. Maximum size is 2 GB.';
            } else if (response.status === 507) {
                errorMessage = 'Not enough disk space. Free up space or adjust threshold in Settings.';
            } else {
                try {
                    const error = await response.json();
                    errorMessage = error.detail || 'Upload failed. Check the Logs tab for details.';
                } catch {
                    errorMessage = 'Upload failed. Check the Logs tab for details.';
                }
            }
            throw new Error(errorMessage);
        }

        const result = await response.json();

        showToast(`Video uploaded successfully: ${result.filename}`, 'success');

        // Clear the file input and selected file name display
        fileInput.value = '';
        const selectedFileName = document.getElementById('selected-file-name');
        if (selectedFileName) {
            selectedFileName.style.display = 'none';
            selectedFileName.textContent = '';
        }

        // Reload the video selects to show the new upload
        await loadSourceVideosForTools();

        // Also reload files list if on Files tab
        await loadFiles();

    } catch (error) {
        console.error('Upload failed:', error);
        showToast(`Upload failed: ${error.message}`, 'error');
    } finally {
        // Re-enable upload button
        uploadBtn.disabled = false;
        uploadBtn.innerHTML = '<span>⬆️</span> Upload Video';
    }
}

/**
 * Initialize drag and drop for video upload
 */
function initDragAndDrop() {
    const dropZone = document.getElementById('upload-drop-zone');
    const fileInput = document.getElementById('video-file-input');
    const selectedFileName = document.getElementById('selected-file-name');

    if (!dropZone || !fileInput) {
        return;
    }

    // Prevent default drag behaviors on the drop zone only
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Highlight drop zone when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

    function highlight() {
        dropZone.classList.add('drag-over');
    }

    function unhighlight() {
        dropZone.classList.remove('drag-over');
    }

    // Handle dropped files
    dropZone.addEventListener('drop', handleDrop, false);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
            // Only take the first file
            const file = files[0];

            // Update the file input
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(file);
            fileInput.files = dataTransfer.files;

            // Show selected file name
            if (selectedFileName) {
                selectedFileName.textContent = `Selected: ${file.name}`;
                selectedFileName.style.display = 'block';
            }

            showToast('File ready to upload', 'info');
        }
    }

    // Show selected file name when using file input
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            const file = fileInput.files[0];
            if (selectedFileName) {
                selectedFileName.textContent = `Selected: ${file.name}`;
                selectedFileName.style.display = 'block';
            }
        }
    });
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
        // Determine which section this is for and show appropriate message
        if (containerId === 'active-downloads-list') {
            container.innerHTML = `
                <div class="empty-state-enhanced">
                    <span class="empty-icon">📥</span>
                    <h3>No active downloads</h3>
                    <p>Paste a video URL in the form above to get started</p>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="empty-state-enhanced">
                    <span class="empty-icon">📝</span>
                    <h3>No downloads yet</h3>
                    <p>Your completed downloads will appear here</p>
                </div>
            `;
        }
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
                    ${download.status === 'completed' && download.completed_at && download.started_at ? `
                        <span>Downloaded in: ${calculateDuration(download.started_at, download.completed_at)}</span>
                    ` : ''}
                    ${download.status === 'downloading' || download.status === 'processing' ? `
                        <span>Started: ${formatDate(download.started_at || download.created_at)}</span>
                    ` : ''}
                    ${download.status === 'queued' ? `
                        <span>Queued: ${formatDate(download.created_at)}</span>
                    ` : ''}
                    ${download.status === 'failed' && download.completed_at ? `
                        <span>Failed after: ${download.started_at ? calculateDuration(download.started_at, download.completed_at) : 'N/A'}</span>
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
        // First click - show confirmation state with countdown
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.innerHTML;
            button.dataset.countdown = '3';
            button.innerHTML = 'Confirm Delete? (3s)';
            button.classList.add('btn-confirm-delete');

            // Countdown timer
            const countdownInterval = setInterval(() => {
                const current = parseInt(button.dataset.countdown);
                if (current > 1) {
                    button.dataset.countdown = (current - 1).toString();
                    button.innerHTML = `Confirm Delete? (${current - 1}s)`;
                } else {
                    clearInterval(countdownInterval);
                }
            }, 1000);

            // Store interval ID to clear it if button is clicked
            button.dataset.intervalId = countdownInterval;

            // Reset after 3 seconds if not clicked again
            setTimeout(() => {
                clearInterval(countdownInterval);
                resetDeleteButton(button);
            }, 3000);
        }
    }
}

function resetDeleteButton(button) {
    if (button && button.dataset.confirmDelete === 'true') {
        // Clear any active countdown interval
        if (button.dataset.intervalId) {
            clearInterval(parseInt(button.dataset.intervalId));
            delete button.dataset.intervalId;
        }

        button.dataset.confirmDelete = 'false';
        button.innerHTML = button.dataset.originalText || 'Delete';
        button.classList.remove('btn-confirm-delete');
        delete button.dataset.originalText;
        delete button.dataset.countdown;
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
    const accessibilityEnabled = localStorage.getItem('accessibility') === 'true';

    // Store currently focused element to restore later
    const previousFocus = document.activeElement;

    // Create modal for video player
    const modal = document.createElement('div');
    modal.className = 'video-modal';

    const modalId = `video-modal-${downloadId}`;
    const titleId = `video-modal-title-${downloadId}`;

    modal.innerHTML = `
        <div class="video-modal-content" id="${modalId}">
            <div class="video-modal-header">
                <h3 id="${titleId}">${escapeHtml(title)}</h3>
                <button class="video-modal-close" aria-label="Close video player">×</button>
            </div>
            <video controls autoplay style="width: 100%; max-height: 70vh;">
                <source src="${API_BASE}/api/files/video/${downloadId}">
                Your browser does not support the video tag.
            </video>
        </div>
    `;

    // Add ARIA attributes if accessibility is enabled
    if (accessibilityEnabled) {
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', titleId);
    }

    // Function to close modal and restore focus
    const closeModal = () => {
        modal.remove();
        // Restore focus to previously focused element
        if (accessibilityEnabled && previousFocus) {
            previousFocus.focus();
        }
    };

    // Close button handler
    const closeButton = modal.querySelector('.video-modal-close');
    closeButton.addEventListener('click', closeModal);

    // Close modal when clicking outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });

    // Add Escape key handler (always enabled)
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            closeModal();
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);

    // Accessibility enhancements (focus management, ARIA)
    if (accessibilityEnabled) {
        // Focus trapping
        const focusableElements = modal.querySelectorAll(
            'button, video, [tabindex]:not([tabindex="-1"])'
        );
        const firstFocusable = focusableElements[0];
        const lastFocusable = focusableElements[focusableElements.length - 1];

        modal.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    // Shift + Tab
                    if (document.activeElement === firstFocusable) {
                        e.preventDefault();
                        lastFocusable.focus();
                    }
                } else {
                    // Tab
                    if (document.activeElement === lastFocusable) {
                        e.preventDefault();
                        firstFocusable.focus();
                    }
                }
            }
        });

        // Focus the close button initially
        setTimeout(() => closeButton.focus(), 100);
    }

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


async function loadQueueSettings() {
    try {
        const response = await fetch(`${API_BASE}/api/settings/queue`);
        if (!response.ok) throw new Error('Failed to load queue settings');

        const data = await response.json();
        document.getElementById('max-concurrent').value = data.max_concurrent_downloads || 2;
        document.getElementById('max-concurrent-conversions').value = data.max_concurrent_conversions || 1;
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
            max_concurrent_conversions: parseInt(document.getElementById('max-concurrent-conversions').value),
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

/**
 * Render hardware information HTML from data object
 */
function renderHardwareInfo(data) {
    const container = document.getElementById('hardware-info-content');

    // Build hardware info display
    let html = '<div class="hardware-info-grid">';

    // Platform Information (includes CPU and Network)
    // Calculate total network bandwidth
    let totalBandwidth = 0;
    if (data.network && data.network.length > 0) {
        data.network.forEach(iface => {
            if (iface.speed_mbps && iface.speed_mbps > 0) {
                totalBandwidth += iface.speed_mbps;
            }
        });
    }

    html += `
        <div class="hardware-section">
            <h3>🖥️ Platform</h3>
            <div class="hardware-details">
                <p><strong>System:</strong> ${escapeHtml(data.platform.system)}</p>
                <p><strong>Release:</strong> ${escapeHtml(data.platform.release)}</p>
                <p><strong>CPU:</strong> ${data.cpu.cores} cores, ${escapeHtml(data.cpu.architecture)}</p>
                ${totalBandwidth > 0 ? `<p><strong>Network Bandwidth:</strong> ${totalBandwidth.toLocaleString()} Mbps</p>` : ''}
            </div>
        </div>
    `;

    // Memory Information with Pie Chart
    const memoryTotalGb = data.memory.total_mb / 1024;
    const memoryUsedGb = data.memory.used_mb / 1024;
    const memoryAvailableGb = data.memory.available_mb / 1024;

    html += `
        <div class="hardware-section memory-section">
            <h3>💾 Memory</h3>
            <div class="storage-content">
                <div class="storage-details">
                    <p><strong>Total:</strong> ${memoryTotalGb.toFixed(2)} GB</p>
                    <p><strong>Used:</strong> <span class="memory-legend-used">■</span> ${memoryUsedGb.toFixed(2)} GB (${data.memory.usage_percent}%)</p>
                    <p><strong>Available:</strong> <span class="memory-legend-available">■</span> ${memoryAvailableGb.toFixed(2)} GB</p>
                </div>
                <div class="storage-chart">
                    <canvas id="memory-pie-chart" width="120" height="120"></canvas>
                </div>
            </div>
        </div>
    `;

    // Storage Information with Pie Chart
    html += `
        <div class="hardware-section storage-section">
            <h3>💿 Storage</h3>
            <div class="storage-content">
                <div class="storage-details">
                    <p><strong>Total:</strong> ${data.disk.total_gb.toLocaleString()} GB</p>
                    <p><strong>Used:</strong> <span class="storage-legend-used">■</span> ${data.disk.used_gb.toLocaleString()} GB (${data.disk.usage_percent}%)</p>
                    <p><strong>Free:</strong> <span class="storage-legend-free">■</span> ${data.disk.free_gb.toLocaleString()} GB</p>
                </div>
                <div class="storage-chart">
                    <canvas id="storage-pie-chart" width="120" height="120"></canvas>
                </div>
            </div>
        </div>
    `;

    // Hardware Acceleration
    html += `
        <div class="hardware-section">
            <h3>⚡ Hardware Acceleration</h3>
            <div class="hardware-details">
    `;

    if (data.acceleration.detected_encoders.length > 0) {
        const encodersList = data.acceleration.detected_encoders.join(', ');
        html += `<p><strong>Available:</strong> ${escapeHtml(encodersList)}</p>`;
    } else {
        html += `<p><strong>Available:</strong> None (CPU-only encoding)</p>`;
    }

    html += `
            </div>
        </div>
    `;

    html += '</div>'; // Close hardware-info-grid

    container.innerHTML = html;

    // Draw the pie charts (reuse variables declared above)
    drawMemoryPieChart(memoryUsedGb, memoryAvailableGb);
    drawStoragePieChart(data.disk.used_gb, data.disk.free_gb);
}

/**
 * Draw a donut chart for memory usage
 */
function drawMemoryPieChart(usedGb, availableGb) {
    const canvas = document.getElementById('memory-pie-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const outerRadius = 50;
    const innerRadius = 30;  // Donut hole size

    // Calculate percentages
    const total = usedGb + availableGb;
    if (total === 0) return; // Avoid division by zero

    const usedPercent = usedGb / total;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Colors: Red for used, Grey for available
    const usedColor = '#ff4444';  // Red (danger)
    const availableColor = '#A8B2C0';  // Grey from graphite theme

    // Draw used portion (red)
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, 0, usedPercent * 2 * Math.PI);
    ctx.arc(centerX, centerY, innerRadius, usedPercent * 2 * Math.PI, 0, true);
    ctx.closePath();
    ctx.fillStyle = usedColor;
    ctx.fill();

    // Draw available portion (grey)
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, usedPercent * 2 * Math.PI, 2 * Math.PI);
    ctx.arc(centerX, centerY, innerRadius, 2 * Math.PI, usedPercent * 2 * Math.PI, true);
    ctx.closePath();
    ctx.fillStyle = availableColor;
    ctx.fill();

    // Add outer border
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, 0, 2 * Math.PI);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Add inner border (donut hole)
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 2;
    ctx.stroke();
}

/**
 * Draw a donut chart for storage usage
 */
function drawStoragePieChart(usedGb, freeGb) {
    const canvas = document.getElementById('storage-pie-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const outerRadius = 50;
    const innerRadius = 30;  // Donut hole size

    // Calculate percentages
    const total = usedGb + freeGb;
    if (total === 0) return; // Avoid division by zero

    const usedPercent = usedGb / total;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Colors: Red for used, Grey for free
    const usedColor = '#ff4444';  // Red (danger)
    const freeColor = '#A8B2C0';  // Grey from graphite theme

    // Draw used portion (red)
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, 0, usedPercent * 2 * Math.PI);
    ctx.arc(centerX, centerY, innerRadius, usedPercent * 2 * Math.PI, 0, true);
    ctx.closePath();
    ctx.fillStyle = usedColor;
    ctx.fill();

    // Draw free portion (grey)
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, usedPercent * 2 * Math.PI, 2 * Math.PI);
    ctx.arc(centerX, centerY, innerRadius, 2 * Math.PI, usedPercent * 2 * Math.PI, true);
    ctx.closePath();
    ctx.fillStyle = freeColor;
    ctx.fill();

    // Add outer border
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, 0, 2 * Math.PI);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Add inner border (donut hole)
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 2;
    ctx.stroke();
}

/**
 * Load hardware information (uses browser cache if available)
 */
async function loadHardwareInfo() {
    const container = document.getElementById('hardware-info-content');
    const CACHE_KEY = 'hardware_info_cache';

    // Try to load from browser localStorage first
    try {
        const cachedData = localStorage.getItem(CACHE_KEY);
        if (cachedData) {
            const data = JSON.parse(cachedData);
            renderHardwareInfo(data);
            console.log('Hardware info loaded from browser cache');
            return;
        }
    } catch (error) {
        console.warn('Failed to load hardware info from cache:', error);
    }

    // No cache found - fetch from server
    container.innerHTML = '<p class="empty-state">Loading hardware information...</p>';

    try {
        const response = await fetch(`${API_BASE}/api/hardware/info`);
        if (!response.ok) throw new Error('Failed to load hardware info');

        const data = await response.json();

        // Cache in localStorage for future page loads
        try {
            localStorage.setItem(CACHE_KEY, JSON.stringify(data));
        } catch (error) {
            console.warn('Failed to cache hardware info:', error);
        }

        renderHardwareInfo(data);

    } catch (error) {
        console.error('Failed to load hardware info:', error);
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to load hardware information. Please try again.</p>';
    }
}

/**
 * Refresh hardware information (re-detects hardware and updates all caches)
 */
async function refreshHardwareInfo() {
    const container = document.getElementById('hardware-info-content');
    const button = document.getElementById('refresh-hardware-btn');
    const CACHE_KEY = 'hardware_info_cache';

    // Disable button during refresh
    button.disabled = true;
    button.textContent = '🔄 Refreshing...';
    container.innerHTML = '<p class="empty-state">Re-detecting hardware...</p>';

    try {
        // Call the refresh endpoint to re-detect hardware
        const response = await fetch(`${API_BASE}/api/hardware/refresh`, {
            method: 'POST'
        });

        if (!response.ok) throw new Error('Failed to refresh hardware info');

        const data = await response.json();

        // Update browser cache
        try {
            localStorage.setItem(CACHE_KEY, JSON.stringify(data));
        } catch (error) {
            console.warn('Failed to update hardware info cache:', error);
        }

        // Render the fresh data
        renderHardwareInfo(data);

        showToast('Hardware information refreshed', 'success');

    } catch (error) {
        console.error('Failed to refresh hardware info:', error);
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to refresh hardware information. Please try again.</p>';
        showToast('Failed to refresh hardware info', 'error');
    } finally {
        // Re-enable button
        button.disabled = false;
        button.textContent = '🔄 Refresh Hardware Info';
    }
}

/**
 * Open the help modal
 */
function openHelpModal() {
    const modal = document.getElementById('help-modal');
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden'; // Prevent scrolling
}

/**
 * Close the help modal
 */
function closeHelpModal() {
    const modal = document.getElementById('help-modal');

    modal.style.display = 'none';
    document.body.style.overflow = '';

    // Reset to main view when closing
    showHelpMainView();
}

// Help Documentation System
let helpDocumentation = null;

async function loadHelpDocumentation() {
    try {
        const response = await fetch('/assets/documentation.json');
        if (!response.ok) throw new Error('Failed to load documentation');
        helpDocumentation = await response.json();
        renderHelpMainView();
    } catch (error) {
        console.error('Failed to load help documentation:', error);
        // Fallback: show a simple error message
        document.getElementById('help-main-view').innerHTML = `
            <p style="color: var(--danger); padding: 2rem; text-align: center;">
                Failed to load help documentation. Please refresh the page.
            </p>
        `;
    }
}

function renderHelpMainView() {
    if (!helpDocumentation) return;

    const mainView = document.getElementById('help-main-view');

    // Render keyboard shortcuts
    const shortcutsHTML = `
        <section class="help-section">
            <h3>⌨️ Keyboard Shortcuts</h3>
            <p class="help-description">Use these keyboard shortcuts to navigate faster.</p>
            <div class="shortcuts-grid">
                ${helpDocumentation.shortcuts.map(shortcut => `
                    <div class="shortcut-item" data-doc-id="${shortcut.id}" data-doc-type="shortcut">
                        <kbd>${shortcut.title}</kbd>
                        <span>${shortcut.summary}</span>
                    </div>
                `).join('')}
            </div>
        </section>
    `;

    // Render tips & tricks
    const tipsHTML = `
        <section class="help-section">
            <h3>💡 Tips & Tricks</h3>
            <p class="help-description">Click on any tip to learn more.</p>
            <div class="tips-list">
                ${helpDocumentation.tips.map(tip => `
                    <div class="tip-item" data-doc-id="${tip.id}" data-doc-type="tip">
                        <div class="tip-content">
                            <strong>${tip.title}:</strong> ${tip.summary}
                        </div>
                    </div>
                `).join('')}
            </div>
        </section>
    `;

    mainView.innerHTML = shortcutsHTML + tipsHTML;

    // Add click listeners only to tip items (not shortcuts)
    mainView.querySelectorAll('[data-doc-type="tip"]').forEach(item => {
        item.addEventListener('click', () => {
            const docId = item.dataset.docId;
            const docType = item.dataset.docType;
            showHelpDetailView(docId, docType);
        });
    });
}

function showHelpDetailView(docId, docType) {
    if (!helpDocumentation) return;

    const items = docType === 'shortcut' ? helpDocumentation.shortcuts : helpDocumentation.tips;
    const item = items.find(i => i.id === docId);

    if (!item || !item.detail) return;

    const detailView = document.getElementById('help-detail-view');
    const detailContent = document.getElementById('help-detail-content');
    const mainView = document.getElementById('help-main-view');

    // Render detail content with back button at the top
    const sectionsHTML = item.detail.sections.map(section => `
        <div class="detail-section">
            <h3>${section.heading}</h3>
            <p>${section.content}</p>
        </div>
    `).join('');

    detailContent.innerHTML = `
        <button class="help-back-button" onclick="showHelpMainView()">
            ← Back
        </button>
        <h2>${item.detail.title}</h2>
        <p class="detail-description">${item.detail.description}</p>
        ${sectionsHTML}
    `;

    // Show detail view, hide main view
    mainView.style.display = 'none';
    detailView.style.display = 'block';

    // Scroll to top of detail view
    detailView.scrollTop = 0;
}

function showHelpMainView() {
    const detailView = document.getElementById('help-detail-view');
    const mainView = document.getElementById('help-main-view');

    detailView.style.display = 'none';
    mainView.style.display = 'block';

    // Scroll to top of main view
    mainView.scrollTop = 0;
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

        // Reload downloads
        loadDownloads();

    } catch (error) {
        showToast('Cleanup failed: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Clean Up Failed Downloads';
    }
}

async function cleanupStaleConversions() {
    const button = document.getElementById('cleanup-conversions-btn');
    const hours = parseInt(document.getElementById('cleanup-hours').value);

    if (!confirm(`Remove all conversions stuck in queued/converting state for more than ${hours} hour${hours > 1 ? 's' : ''}?`)) {
        return;
    }

    button.disabled = true;
    button.textContent = 'Cleaning up...';

    try {
        const response = await fetch(`${API_BASE}/api/tools/conversions/cleanup?hours=${hours}`, {
            method: 'POST'
        });

        if (!response.ok) throw new Error('Cleanup failed');

        const stats = await response.json();

        // Show results
        document.getElementById('cleanup-conversions-count').textContent = stats.conversions_removed;
        document.getElementById('cleanup-conversion-files').textContent = stats.files_removed;
        document.getElementById('cleanup-conversion-space').textContent = formatBytes(stats.space_freed);
        document.getElementById('conversion-cleanup-stats').style.display = 'block';

        showToast('Stale conversions cleaned up successfully!', 'success');

        // Reload conversions list if on Tools tab
        await loadConversions();

    } catch (error) {
        showToast('Cleanup failed: ' + error.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Clean Up Stale Conversions';
    }
}

// Cookie Management
async function loadCookieFilesSettings() {
    const container = document.getElementById('cookie-files-list');

    try {
        const response = await fetch(`${API_BASE}/api/settings/cookies`);

        if (!response.ok) throw new Error('Failed to load cookie files');

        const data = await response.json();
        const cookies = data.cookies || [];

        if (cookies.length === 0) {
            container.innerHTML = '<p class="empty-state">No cookie files uploaded yet.</p>';
            return;
        }

        // Create table of cookie files
        const table = document.createElement('table');
        table.className = 'cookie-files-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>Last Modified</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                ${cookies.map(cookie => `
                    <tr>
                        <td><strong>${cookie.filename}</strong></td>
                        <td>${formatBytes(cookie.size)}</td>
                        <td>${new Date(cookie.modified).toLocaleString()}</td>
                        <td>
                            <button class="btn btn-danger btn-sm" onclick="deleteCookieFileSettings('${cookie.filename}')">
                                Delete
                            </button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        `;

        container.innerHTML = '';
        container.appendChild(table);

    } catch (error) {
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to load cookie files</p>';
        console.error('Failed to load cookie files:', error);
    }
}

function showCookieUploadModal(file) {
    // Create modal overlay
    const modal = document.createElement('div');
    modal.className = 'cookie-modal-overlay';
    modal.innerHTML = `
        <div class="cookie-modal-content glass-card">
            <div class="cookie-modal-header">
                <h3>Name Your Cookie File</h3>
            </div>
            <div class="cookie-modal-body">
                <p style="color: var(--text-muted); margin-bottom: 1rem;">
                    Enter just the site name (e.g., "instagram", "youtube", "x").
                    The file will be saved as <strong>name.txt</strong>
                </p>
                <div class="form-group">
                    <label for="cookie-domain-input">Site Name:</label>
                    <input
                        type="text"
                        id="cookie-domain-input"
                        placeholder="instagram"
                        style="width: 100%; padding: 0.75rem; background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 8px; color: var(--text-color); font-family: inherit;"
                    >
                    <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem;">
                        Only letters, numbers, dots, and hyphens are allowed.
                    </p>
                    <div id="cookie-domain-preview" style="margin-top: 1rem; padding: 0.75rem; background: rgba(var(--primary-color-rgb), 0.1); border: 1px solid rgba(var(--primary-color-rgb), 0.3); border-radius: 8px; display: none;">
                        <p style="margin: 0 0 0.5rem 0; font-weight: 600; color: var(--text-light);">This will be used for:</p>
                        <p id="cookie-domain-examples" style="margin: 0; color: var(--text-muted); font-size: 0.9rem;"></p>
                    </div>
                </div>
            </div>
            <div class="cookie-modal-footer">
                <button class="btn btn-secondary" id="cookie-cancel-btn">Cancel</button>
                <button class="btn btn-primary" id="cookie-upload-btn-modal">Upload</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Focus input
    const input = document.getElementById('cookie-domain-input');
    const preview = document.getElementById('cookie-domain-preview');
    const examples = document.getElementById('cookie-domain-examples');

    input.focus();

    // Update preview in real-time
    input.addEventListener('input', () => {
        const value = input.value.trim().toLowerCase();

        if (value && /^[a-zA-Z0-9.-]+$/.test(value)) {
            // Generate example domains
            const exampleDomains = [
                `${value}.com`,
                `www.${value}.com`,
                `m.${value}.com`
            ];

            examples.textContent = exampleDomains.join(', ');
            preview.style.display = 'block';
        } else {
            preview.style.display = 'none';
        }
    });

    // Handle cancel
    document.getElementById('cookie-cancel-btn').addEventListener('click', () => {
        document.body.removeChild(modal);
    });

    // Handle upload
    document.getElementById('cookie-upload-btn-modal').addEventListener('click', async () => {
        const domain = input.value.trim();

        // Validate site name format
        const domainRegex = /^[a-zA-Z0-9.-]+$/;
        if (!domain) {
            showToast('Please enter a site name', 'error');
            return;
        }

        if (!domainRegex.test(domain)) {
            showToast('Invalid site name. Only letters, numbers, dots, and hyphens allowed.', 'error');
            return;
        }

        // Create filename as domain.txt
        const filename = domain.endsWith('.txt') ? domain : `${domain}.txt`;

        // Upload the file
        await uploadCookieFileSettings(file, filename);

        // Close modal
        document.body.removeChild(modal);
    });

    // Handle Escape key
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            document.body.removeChild(modal);
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);

    // Handle Enter key in input
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('cookie-upload-btn-modal').click();
        }
    });
}

async function uploadCookieFileSettings(file, filename) {
    try {
        const formData = new FormData();

        // Create a new File object with the custom filename
        const renamedFile = new File([file], filename, { type: file.type });
        formData.append('file', renamedFile);

        const response = await fetch(`${API_BASE}/api/settings/cookies/upload`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Upload failed');
        }

        showToast(`Cookie file '${filename}' uploaded successfully!`, 'success');

        // Reload cookie files list
        await loadCookieFilesSettings();

        // Also reload the dropdown for downloads (if it exists)
        if (typeof loadCookieFiles === 'function') {
            await loadCookieFiles();
        }

    } catch (error) {
        showToast(`Failed to upload cookie file: ${error.message}`, 'error');
        console.error('Cookie upload error:', error);
    }
}

async function deleteCookieFileSettings(filename) {
    if (!confirm(`Delete cookie file '${filename}'?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/settings/cookies/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Delete failed');
        }

        showToast(`Cookie file '${filename}' deleted successfully!`, 'success');

        // Reload cookie files list
        await loadCookieFilesSettings();

        // Also reload the dropdown for downloads (if it exists)
        if (typeof loadCookieFiles === 'function') {
            await loadCookieFiles();
        }

    } catch (error) {
        showToast(`Failed to delete cookie file: ${error.message}`, 'error');
        console.error('Cookie delete error:', error);
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

/**
 * Format a log timestamp for display in the user's local timezone
 * Automatically converts UTC timestamps to browser's local timezone
 * Includes milliseconds for precise log timing
 */
function formatLogTimestamp(timestamp) {
    const date = new Date(timestamp);
    // toLocaleTimeString automatically converts from UTC to browser's local timezone
    const timeString = date.toLocaleTimeString(undefined, {
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });
    // Add milliseconds for precise timing
    const milliseconds = date.getMilliseconds().toString().padStart(3, '0');
    return `${timeString}.${milliseconds}`;
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

    // Load accessibility preference
    const accessibility = localStorage.getItem('accessibility') === 'true';
    document.getElementById('accessibility-toggle').checked = accessibility;
    applyAccessibility(accessibility);
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
        'aqua': 'Aqua',
        'fireplace': 'Fireplace'
    };

    showToast(`Switched to ${themeNames[colorTheme]} theme`, 'success');
}

function toggleAutoCookie() {
    const enabled = document.getElementById('auto-cookie-toggle').checked;
    localStorage.setItem('autoCookie', enabled);
    showToast(`Auto-cookie selection ${enabled ? 'enabled' : 'disabled'}`, 'info');
}

function applyAccessibility(enabled) {
    if (enabled) {
        document.body.classList.add('accessibility-enabled');
    } else {
        document.body.classList.remove('accessibility-enabled');
    }
    localStorage.setItem('accessibility', enabled);
}

function toggleAccessibility() {
    const enabled = document.getElementById('accessibility-toggle').checked;
    applyAccessibility(enabled);
    showToast(`Accessibility features ${enabled ? 'enabled' : 'disabled'}`, 'info');
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

// Debounce timer for URL input to prevent excessive updates
let urlInputDebounceTimer = null;

function handleUrlInput(event) {
    // Clear any existing timer
    if (urlInputDebounceTimer) {
        clearTimeout(urlInputDebounceTimer);
    }

    const urlsText = event.target.value.trim();
    const cookieSelect = document.getElementById('cookies-file');
    const hint = document.getElementById('cookie-hint');

    // Clear hint immediately if no URL
    if (!urlsText) {
        hint.style.display = 'none';
        hint.className = 'cookie-hint';
        hint.textContent = '';
        return;
    }

    // Debounce the auto-cookie logic (wait 500ms after user stops typing)
    urlInputDebounceTimer = setTimeout(() => {
        // Split URLs by newline and filter out empty lines
        const urls = urlsText.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);

        // If multiple URLs, default to "None" and show feedback
        if (urls.length > 1) {
            cookieSelect.value = '';
            hint.style.display = 'block';
            hint.className = 'cookie-hint info';
            hint.textContent = `ℹ️ Multiple URLs detected. Cookie selection disabled (downloads will use no cookies).`;
            return;
        }

        // Single URL: try auto-cookie selection if enabled
        const autoCookieEnabled = localStorage.getItem('autoCookie') === 'true';
        if (!autoCookieEnabled) {
            hint.style.display = 'none';
            return;
        }

        const url = urls[0];
        const domain = extractDomain(url);
        if (!domain) {
            hint.style.display = 'none';
            return;
        }

        // Try to find matching cookie file
        const options = Array.from(cookieSelect.options);

        // Look for exact match (e.g., instagram.txt for instagram.com)
        const matchingOption = options.find(option => {
            const optionValue = option.value.toLowerCase();
            return optionValue === `${domain}.txt` || optionValue.startsWith(`${domain}.`);
        });

        if (matchingOption) {
            // Success - cookie found and selected
            cookieSelect.value = matchingOption.value;
            hint.style.display = 'block';
            hint.className = 'cookie-hint success';
            hint.textContent = `✓ Auto-selected ${matchingOption.value} for ${domain}`;
        } else {
            // No match - provide helpful feedback
            hint.style.display = 'block';
            hint.className = 'cookie-hint warning';
            hint.textContent = `⚠️ No cookie file found for ${domain}. If this video is private, you may need to add a ${domain}.txt cookie file.`;
        }
    }, 500); // 500ms delay after user stops typing
}

// File Browser Management
let selectedFiles = new Set();
let allFiles = []; // Store all files for sorting

async function loadFiles() {
    try {
        const response = await fetch(`${API_BASE}/api/files`);
        if (!response.ok) throw new Error('Failed to load files');

        allFiles = await response.json();
        sortAndRenderFiles();

    } catch (error) {
        console.error('Failed to load files:', error);
        document.getElementById('files-list').innerHTML = '<p class="empty-state">Failed to load files</p>';
    }
}

function sortFiles(files, sortBy) {
    const sortedFiles = [...files]; // Create a copy to avoid mutating original

    switch (sortBy) {
        case 'name-asc':
            sortedFiles.sort((a, b) => a.filename.localeCompare(b.filename));
            break;
        case 'name-desc':
            sortedFiles.sort((a, b) => b.filename.localeCompare(a.filename));
            break;
        case 'size-asc':
            sortedFiles.sort((a, b) => a.size - b.size);
            break;
        case 'size-desc':
            sortedFiles.sort((a, b) => b.size - a.size);
            break;
        case 'date-asc':
            sortedFiles.sort((a, b) => new Date(a.created_at || 0) - new Date(b.created_at || 0));
            break;
        case 'date-desc':
            sortedFiles.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
            break;
        default:
            // Default to name ascending
            sortedFiles.sort((a, b) => a.filename.localeCompare(b.filename));
    }

    return sortedFiles;
}

function sortAndRenderFiles() {
    const container = document.getElementById('files-list');
    const sortSelect = document.getElementById('file-sort-select');
    const sortBy = sortSelect ? sortSelect.value : 'name-asc';

    // Show loading indicator while sorting
    container.innerHTML = '<p class="empty-state">Sorting files...</p>';

    // Use setTimeout to allow UI to update before sorting large lists
    setTimeout(() => {
        const sortedFiles = sortFiles(allFiles, sortBy);
        renderFiles(sortedFiles);
    }, 50);
}

function renderFiles(files) {
    const container = document.getElementById('files-list');

    if (files.length === 0) {
        container.innerHTML = `
            <div class="empty-state-enhanced">
                <span class="empty-icon">📁</span>
                <h3>No files yet</h3>
                <p>Downloaded videos will appear here. Go to the Downloads tab to start downloading!</p>
            </div>
        `;
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
                <button class="btn btn-primary btn-small file-tools-btn" title="Open in Tools">
                    Tools
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

    // Add event listeners to all tools buttons
    document.querySelectorAll('.file-tools-btn').forEach(button => {
        button.addEventListener('click', function() {
            const fileItem = this.closest('.file-item');
            const downloadId = fileItem.dataset.downloadId;
            openInTools(downloadId);
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

            if (!response.ok) {
                // Enhanced error messages based on HTTP status code
                let errorMessage = 'Failed to delete file';
                if (response.status === 404) {
                    errorMessage = 'File not found. It may have already been deleted.';
                } else if (response.status === 403) {
                    errorMessage = 'Permission denied. Cannot delete this file.';
                } else {
                    try {
                        const error = await response.json();
                        errorMessage = error.detail || 'Failed to delete file. Check the Logs tab for details.';
                    } catch {
                        errorMessage = 'Failed to delete file. Check the Logs tab for details.';
                    }
                }
                throw new Error(errorMessage);
            }

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
        // First click - show confirmation state with countdown
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.innerHTML;
            button.dataset.countdown = '3';
            button.innerHTML = '<span>✓</span> Confirm? (3s)';
            button.classList.add('btn-confirm-delete');

            // Countdown timer
            const countdownInterval = setInterval(() => {
                const current = parseInt(button.dataset.countdown);
                if (current > 1) {
                    button.dataset.countdown = (current - 1).toString();
                    button.innerHTML = `<span>✓</span> Confirm? (${current - 1}s)`;
                } else {
                    clearInterval(countdownInterval);
                }
            }, 1000);

            // Store interval ID to clear it if button is clicked
            button.dataset.intervalId = countdownInterval;

            // Reset after 3 seconds if not clicked again
            setTimeout(() => {
                clearInterval(countdownInterval);
                resetDeleteButton(button);
            }, 3000);
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
        // First click - show confirmation state with countdown
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.textContent;
            button.dataset.countdown = '3';
            button.textContent = `Confirm Delete ${count} file${count > 1 ? 's' : ''}? (3s)`;
            button.classList.add('btn-confirm-delete');

            // Countdown timer
            const countdownInterval = setInterval(() => {
                const current = parseInt(button.dataset.countdown);
                if (current > 1) {
                    button.dataset.countdown = (current - 1).toString();
                    button.textContent = `Confirm Delete ${count} file${count > 1 ? 's' : ''}? (${current - 1}s)`;
                } else {
                    clearInterval(countdownInterval);
                }
            }, 1000);

            // Store interval ID to clear it if button is clicked
            button.dataset.intervalId = countdownInterval;

            // Reset after 3 seconds if not clicked again
            setTimeout(() => {
                clearInterval(countdownInterval);
                resetDeleteButton(button);
            }, 3000);
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

// ========================================
// TOOLS TAB FUNCTIONS
// ========================================

/**
 * Load tools tab - initialize all tool components
 */
async function loadToolsTab() {
    console.log('Loading tools tab...');

    await loadSourceVideosForTools();
    await loadConversions();
    checkForPreselectedVideo();
}

/**
 * Load available videos for tool dropdowns
 */
async function loadSourceVideosForTools() {
    try {
        const response = await fetch(`${API_BASE}/api/files`);
        const files = await response.json();

        // Populate MP3 source dropdown
        const mp3Select = document.getElementById('mp3-source-video-select');
        if (mp3Select) {
            mp3Select.innerHTML = '<option value="">-- Select a video --</option>';
            files.forEach(file => {
                mp3Select.innerHTML += `<option value="${file.id}">${file.filename}</option>`;
            });

            // Enable button when video selected
            mp3Select.addEventListener('change', () => {
                const btn = document.getElementById('start-mp3-conversion-btn');
                if (btn) {
                    btn.disabled = !mp3Select.value;
                }

                const sourceInfo = document.getElementById('mp3-source-info');
                const selectedName = document.getElementById('mp3-selected-video-name');
                if (mp3Select.value && sourceInfo && selectedName) {
                    sourceInfo.style.display = 'block';
                    selectedName.textContent = mp3Select.options[mp3Select.selectedIndex].text;
                } else if (sourceInfo) {
                    sourceInfo.style.display = 'none';
                }
            });
        }

        // Populate transform source dropdown
        const transformSelect = document.getElementById('transform-source-video-select');
        if (transformSelect) {
            transformSelect.innerHTML = '<option value="">-- Select a video --</option>';
            files.forEach(file => {
                transformSelect.innerHTML += `<option value="${file.id}">${file.filename}</option>`;
            });

            // Enable button when video selected
            transformSelect.addEventListener('change', () => {
                const btn = document.getElementById('apply-transform-btn');
                if (btn) {
                    btn.disabled = !transformSelect.value;
                }

                const sourceInfo = document.getElementById('transform-source-info');
                const selectedName = document.getElementById('transform-selected-video-name');
                if (transformSelect.value && sourceInfo && selectedName) {
                    sourceInfo.style.display = 'block';
                    selectedName.textContent = transformSelect.options[transformSelect.selectedIndex].text;
                } else if (sourceInfo) {
                    sourceInfo.style.display = 'none';
                }
            });
        }

    } catch (error) {
        console.error('Failed to load source videos:', error);
    }
}

/**
 * Start MP3 conversion
 */
async function submitVideoToMp3Conversion() {
    const sourceId = document.getElementById('mp3-source-video-select')?.value;
    const quality = document.getElementById('audio-quality-select')?.value;
    const btn = document.getElementById('start-mp3-conversion-btn');

    if (!sourceId) {
        showToast('Please select a video', 'error');
        return;
    }

    // Show loading state
    const originalContent = btn?.innerHTML;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = 'Starting conversion...';
    }

    try {
        console.log('Starting MP3 conversion:', { sourceId, quality });

        const response = await fetch(`${API_BASE}/api/tools/video-to-mp3`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_download_id: sourceId,
                audio_quality: parseInt(quality)
            })
        });

        console.log('Conversion response status:', response.status);

        if (response.ok) {
            const conversion = await response.json();
            console.log('Conversion created:', conversion);

            if (conversion.status === 'completed') {
                showToast('This video was already converted to MP3', 'info');
            } else {
                showToast('MP3 conversion queued successfully!', 'success');
            }

            // Immediately load conversions to show the queued item
            await loadConversions();
        } else {
            // Enhanced error messages based on HTTP status code
            let errorMessage = 'Conversion failed';
            if (response.status === 400) {
                errorMessage = 'Invalid conversion request. Please check the source video.';
            } else if (response.status === 404) {
                errorMessage = 'Source video not found. It may have been deleted.';
            } else if (response.status === 507) {
                errorMessage = 'Not enough disk space. Free up space or adjust threshold in Settings.';
            } else {
                try {
                    const error = await response.json();
                    errorMessage = error.detail || 'Conversion failed. Check the Logs tab for details.';
                } catch {
                    errorMessage = 'Conversion failed. Check the Logs tab for details.';
                }
            }
            console.error('Conversion failed:', errorMessage);
            showToast(errorMessage, 'error');
        }
    } catch (error) {
        showToast('Failed to start conversion', 'error');
        console.error('Conversion error:', error);
    } finally {
        // Restore button state
        if (btn && originalContent) {
            btn.disabled = false;
            btn.innerHTML = originalContent;
        }
    }
}

/**
 * Load conversions (both active and completed)
 */
async function loadConversions() {
    try {
        console.log('Loading conversions from API...');
        const response = await fetch(`${API_BASE}/api/tools/conversions`);

        if (!response.ok) {
            console.error('Failed to fetch conversions:', response.status);
            return;
        }

        const conversions = await response.json();
        console.log('Loaded conversions:', conversions);

        const active = conversions.filter(c =>
            c.status === 'queued' || c.status === 'converting'
        );
        const completed = conversions.filter(c => c.status === 'completed');

        console.log('Active conversions:', active);
        console.log('Completed conversions:', completed);

        renderActiveConversions(active);
        renderCompletedConversions(completed);
    } catch (error) {
        console.error('Failed to load conversions:', error);
    }
}

/**
 * Format elapsed time in a human-readable format
 * Calculates time difference between now and start time
 * Works with UTC timestamps - no timezone conversion needed for elapsed time calculation
 */
function formatElapsedTime(startTime) {
    const now = new Date();

    // Ensure we parse the timestamp as UTC
    // If the string doesn't end with 'Z', append it to force UTC parsing
    let timeString = startTime;
    if (!timeString.endsWith('Z') && !timeString.includes('+') && !timeString.includes('T')) {
        // Replace space with 'T' and add 'Z' for proper ISO 8601 UTC format
        timeString = timeString.replace(' ', 'T') + 'Z';
    } else if (!timeString.endsWith('Z') && timeString.includes('T') && !timeString.includes('+')) {
        // Has 'T' but no timezone indicator, add 'Z'
        timeString = timeString + 'Z';
    }

    const start = new Date(timeString);
    const elapsedMs = now - start;
    const elapsedSec = Math.floor(elapsedMs / 1000);

    // Handle negative values (shouldn't happen, but just in case)
    if (elapsedSec < 0) {
        return '0s';
    }

    if (elapsedSec < 60) {
        return `${elapsedSec}s`;
    } else if (elapsedSec < 3600) {
        const minutes = Math.floor(elapsedSec / 60);
        const seconds = elapsedSec % 60;
        return `${minutes}m ${seconds}s`;
    } else {
        const hours = Math.floor(elapsedSec / 3600);
        const minutes = Math.floor((elapsedSec % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}

/**
 * Update running time counters for active conversions
 */
function updateRunningTimeCounters() {
    document.querySelectorAll('.running-time').forEach(element => {
        const startTime = element.dataset.startTime;
        if (startTime) {
            element.textContent = formatElapsedTime(startTime);
        }
    });
}

/**
 * Render active conversions with progress
 */
function renderActiveConversions(conversions) {
    const container = document.getElementById('active-conversions-list');
    console.log('Rendering active conversions, container found:', !!container, 'count:', conversions.length);

    if (!container) {
        console.error('active-conversions-list container not found!');
        return;
    }

    if (conversions.length === 0) {
        container.innerHTML = `
            <div class="empty-state-enhanced">
                <span class="empty-icon">⚙️</span>
                <h3>No active operations</h3>
                <p>MP3 conversions and video transformations in progress will appear here</p>
            </div>
        `;
        // Clear running time interval when no active conversions
        if (runningTimeInterval) {
            clearInterval(runningTimeInterval);
            runningTimeInterval = null;
        }
        return;
    }

    const html = conversions.map(conv => {
        // Determine operation type and display label
        let operationType = '';
        let statusLabel = conv.status;

        if (conv.tool_type.startsWith('video_transform_')) {
            const transformType = conv.tool_type.replace('video_transform_', '');
            const transformNames = {
                'hflip': 'Horizontal Flip',
                'vflip': 'Vertical Flip',
                'rotate90': 'Rotate 90°',
                'rotate180': 'Rotate 180°',
                'rotate270': 'Rotate 270°'
            };
            operationType = `🎬 ${transformNames[transformType] || transformType}`;
        } else if (conv.tool_type === 'video_to_mp3') {
            operationType = '🎵 MP3 Conversion';
        } else {
            operationType = conv.tool_type;
        }

        const runningTime = formatElapsedTime(conv.created_at);

        return `
            <div class="conversion-item" data-conversion-id="${conv.id}">
                <div class="conversion-info">
                    <div style="display: flex; flex-direction: column; gap: 0.25rem;">
                        <strong>${conv.output_filename || 'Processing...'}</strong>
                        <span style="font-size: 0.85rem; color: var(--text-muted);">${operationType}</span>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">Running for: <span class="running-time" data-start-time="${conv.created_at}">${runningTime}</span></span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <span class="conversion-status">${statusLabel}</span>
                        <button class="btn btn-danger btn-small cancel-conversion-btn" title="Cancel this conversion">
                            ✕ Cancel
                        </button>
                    </div>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${conv.progress}%"></div>
                </div>
                <span class="progress-text">${conv.progress.toFixed(1)}%</span>
            </div>
        `;
    }).join('');

    console.log('Setting active conversions HTML, length:', html.length);
    container.innerHTML = html;

    // Clear any existing interval first
    if (runningTimeInterval) {
        clearInterval(runningTimeInterval);
        runningTimeInterval = null;
    }

    // Start updating running time counters every second
    runningTimeInterval = setInterval(updateRunningTimeCounters, 1000);

    // Add event listeners to cancel buttons
    document.querySelectorAll('.cancel-conversion-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const conversionItem = this.closest('.conversion-item');
            const conversionId = conversionItem.dataset.conversionId;
            await cancelConversion(conversionId);
        });
    });
}

/**
 * Cancel an active conversion
 */
async function cancelConversion(conversionId) {
    if (!confirm('Are you sure you want to cancel this conversion? This will stop the process and clean up any partial files.')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/tools/conversions/${conversionId}/cancel`, {
            method: 'POST'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to cancel conversion');
        }

        showToast('Conversion cancelled successfully', 'success');

        // Refresh conversions list
        await loadConversions();
    } catch (error) {
        console.error('Failed to cancel conversion:', error);
        showToast(`Failed to cancel conversion: ${error.message}`, 'error');
    }
}

/**
 * Render completed conversions
 */
function renderCompletedConversions(conversions) {
    const container = document.getElementById('completed-conversions-list');
    console.log('Rendering completed conversions, container found:', !!container, 'count:', conversions.length);

    if (!container) {
        console.error('completed-conversions-list container not found!');
        return;
    }

    if (conversions.length === 0) {
        container.innerHTML = `
            <div class="empty-state-enhanced">
                <span class="empty-icon">✅</span>
                <h3>No completed conversions yet</h3>
                <p>Finished MP3 conversions and transformations will appear here</p>
            </div>
        `;
        return;
    }

    const html = conversions.map(conv => {
        // Determine operation type and display label
        let operationType = '';
        let operationIcon = '';

        if (conv.tool_type.startsWith('video_transform_')) {
            const transformType = conv.tool_type.replace('video_transform_', '');
            const transformNames = {
                'hflip': 'Horizontal Flip',
                'vflip': 'Vertical Flip',
                'rotate90': 'Rotate 90°',
                'rotate180': 'Rotate 180°',
                'rotate270': 'Rotate 270°'
            };
            operationType = transformNames[transformType] || transformType;
            operationIcon = '🎬';
        } else if (conv.tool_type === 'video_to_mp3') {
            operationType = 'MP3 Conversion';
            operationIcon = '🎵';
        } else {
            operationType = conv.tool_type;
            operationIcon = '🔧';
        }

        return `
            <div class="conversion-item">
                <div class="conversion-info">
                    <div style="display: flex; flex-direction: column; gap: 0.25rem;">
                        <strong>${conv.output_filename || 'Completed'}</strong>
                        <span style="font-size: 0.85rem; color: var(--text-muted);">${operationIcon} ${operationType}</span>
                        <span style="font-size: 0.85rem; color: var(--text-muted);">Size: ${formatBytes(conv.output_size || 0)}</span>
                    </div>
                    <span class="conversion-status" style="background: rgba(0, 255, 136, 0.2); color: var(--success); border: 1px solid var(--success);">completed</span>
                </div>
                <div class="file-actions">
                    <button class="btn btn-primary btn-small" onclick="downloadCompletedConversion('${conv.id}', '${escapeHtml(conv.output_filename)}', '${conv.tool_type}', '${conv.source_download_id}')">
                        <span>⬇</span> Download
                    </button>
                    <button class="btn btn-danger btn-small" onclick="deleteCompletedConversion('${conv.id}', event)">
                        <span>🗑</span> Delete
                    </button>
                </div>
            </div>
        `;
    }).join('');

    console.log('Setting completed conversions HTML, length:', html.length);
    container.innerHTML = html;
}

/**
 * Download completed conversion
 */
function downloadCompletedConversion(conversionId, filename, toolType, sourceDownloadId) {
    let downloadUrl;

    // MP3 conversions have their own endpoint
    if (toolType === 'video_to_mp3') {
        downloadUrl = `${API_BASE}/api/tools/audio/${conversionId}`;
    }
    // Video transforms modify the original file, so download from video endpoint
    else if (toolType.startsWith('video_transform_')) {
        downloadUrl = `${API_BASE}/api/files/video/${sourceDownloadId}`;
    }
    else {
        // Fallback to audio endpoint for unknown types
        downloadUrl = `${API_BASE}/api/tools/audio/${conversionId}`;
    }

    window.open(downloadUrl, '_blank');
    showToast('Download started', 'success');
}

/**
 * Delete completed conversion
 */
async function deleteCompletedConversion(conversionId, event) {
    const button = event?.target.closest('button');

    // Check if button is already in confirm state
    if (button?.dataset.confirmDelete === 'true') {
        // Second click - actually delete
        button.disabled = true;

        try {
            const response = await fetch(`${API_BASE}/api/tools/conversions/${conversionId}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to delete conversion');
            }

            showToast('Conversion deleted', 'success');
            await loadConversions();

        } catch (error) {
            showToast('Failed to delete conversion: ' + error.message, 'error');
            console.error('Delete error:', error);
            button.disabled = false;
            resetDeleteButton(button);
        }
    } else {
        // First click - show confirmation state with countdown
        if (button) {
            button.dataset.confirmDelete = 'true';
            button.dataset.originalText = button.innerHTML;
            button.dataset.countdown = '3';
            button.innerHTML = 'Confirm Delete? (3s)';
            button.classList.add('btn-confirm-delete');

            // Countdown timer
            const countdownInterval = setInterval(() => {
                const current = parseInt(button.dataset.countdown);
                if (current > 1) {
                    button.dataset.countdown = (current - 1).toString();
                    button.innerHTML = `Confirm Delete? (${current - 1}s)`;
                } else {
                    clearInterval(countdownInterval);
                }
            }, 1000);

            // Store interval ID to clear it if button is clicked
            button.dataset.intervalId = countdownInterval;

            // Reset after 3 seconds if not clicked again
            setTimeout(() => {
                clearInterval(countdownInterval);
                resetDeleteButton(button);
            }, 3000);
        }
    }
}

/**
 * Apply video transformation
 */
async function applyVideoTransformation() {
    const sourceId = document.getElementById('transform-source-video-select')?.value;
    const transformType = document.getElementById('transform-type-select')?.value;
    const transformSelect = document.getElementById('transform-type-select');
    const transformName = transformSelect?.options[transformSelect.selectedIndex]?.text;

    if (!sourceId) {
        showToast('Please select a video', 'error');
        return;
    }

    if (!confirm(`Apply "${transformName}" to this video? This will modify the original file and cannot be undone.`)) {
        return;
    }

    const btn = document.getElementById('apply-transform-btn');
    if (!btn) return;

    const originalContent = btn.innerHTML;

    try {
        // Show loading state
        btn.disabled = true;
        btn.innerHTML = 'Transforming...';

        const response = await fetch(`${API_BASE}/api/tools/transform`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                download_id: sourceId,
                transform_type: transformType
            })
        });

        if (response.ok) {
            const conversion = await response.json();
            console.log('Transformation created:', conversion);

            if (conversion.status === 'completed') {
                showToast('Video transformation completed', 'success');
            } else {
                showToast('Video transformation queued successfully!', 'success');
            }

            // Immediately load conversions to show the queued item
            await loadConversions();

            // Reset form
            const transformSourceSelect = document.getElementById('transform-source-video-select');
            const transformSourceInfo = document.getElementById('transform-source-info');
            if (transformSourceSelect) {
                transformSourceSelect.value = '';
            }
            if (transformSourceInfo) {
                transformSourceInfo.style.display = 'none';
            }
        } else {
            // Enhanced error messages based on HTTP status code
            let errorMessage = 'Transformation failed';
            if (response.status === 400) {
                errorMessage = 'Invalid transformation request. Please check the source video.';
            } else if (response.status === 404) {
                errorMessage = 'Source video not found. It may have been deleted.';
            } else if (response.status === 507) {
                errorMessage = 'Not enough disk space. Free up space or adjust threshold in Settings.';
            } else {
                try {
                    const error = await response.json();
                    errorMessage = error.detail || 'Transformation failed. Check the Logs tab for details.';
                } catch {
                    errorMessage = 'Transformation failed. Check the Logs tab for details.';
                }
            }
            showToast(errorMessage, 'error');
        }
    } catch (error) {
        showToast('Failed to transform video', 'error');
        console.error('Transform error:', error);
    } finally {
        // Restore button state
        btn.disabled = false;
        btn.innerHTML = originalContent;
    }
}

/**
 * Open in Tools from Browse Files
 */
function openInTools(downloadId) {
    // Store in sessionStorage
    sessionStorage.setItem('toolsSourceVideo', downloadId);

    // Switch to tools tab
    const toolsBtn = document.querySelector('[data-tab="tools"]');
    if (toolsBtn) {
        toolsBtn.click();
    }
}

/**
 * Check for preselected video (from "Open in Tools")
 */
function checkForPreselectedVideo() {
    const preselectedId = sessionStorage.getItem('toolsSourceVideo');
    if (!preselectedId) return;

    // Pre-select in MP3 tool (default tool)
    const mp3Select = document.getElementById('mp3-source-video-select');
    if (mp3Select) {
        mp3Select.value = preselectedId;
        mp3Select.dispatchEvent(new Event('change'));
    }

    // Clear sessionStorage
    sessionStorage.removeItem('toolsSourceVideo');

    // Show highlight animation
    const sourceInfo = document.getElementById('mp3-source-info');
    if (sourceInfo) {
        sourceInfo.style.animation = 'highlight 2s ease';
    }
}

/**
 * Poll for conversion progress continuously (not just when Tools tab is active)
 * This ensures active conversions are tracked and displayed in real-time
 */
setInterval(async () => {
    await loadConversions();
}, 2000);

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize preferences first
    initPreferences();

    // Initialize tabs
    initTabs();

    // Download form submission
    document.getElementById('new-download-form').addEventListener('submit', submitDownload);

    // Video upload form submission
    document.getElementById('video-upload-form').addEventListener('submit', submitVideoUpload);

    // Initialize drag and drop for video upload
    initDragAndDrop();

    // URL input for auto-cookie selection
    document.getElementById('video-url').addEventListener('input', handleUrlInput);

    // Settings buttons
    document.getElementById('save-queue-settings-btn').addEventListener('click', saveQueueSettings);
    document.getElementById('update-ytdlp-btn').addEventListener('click', updateYtdlp);
    document.getElementById('refresh-hardware-btn').addEventListener('click', refreshHardwareInfo);
    document.getElementById('clear-cache-btn').addEventListener('click', clearYtdlpCache);

    // Help modal
    document.getElementById('help-modal-btn').addEventListener('click', openHelpModal);
    document.getElementById('help-modal-close').addEventListener('click', closeHelpModal);

    // Close help modal on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const helpModal = document.getElementById('help-modal');
            if (helpModal.style.display === 'flex') {
                closeHelpModal();
            }
        }
    });

    // Close help modal when clicking outside
    document.getElementById('help-modal').addEventListener('click', (e) => {
        if (e.target.id === 'help-modal') {
            closeHelpModal();
        }
    });

    // Load help documentation
    loadHelpDocumentation();

    document.getElementById('cleanup-btn').addEventListener('click', cleanupDownloads);
    document.getElementById('cleanup-conversions-btn').addEventListener('click', cleanupStaleConversions);

    // Cookie management
    document.getElementById('upload-cookie-btn').addEventListener('click', () => {
        document.getElementById('cookie-file-input').click();
    });

    document.getElementById('cookie-file-input').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            showCookieUploadModal(file);
            // Reset input so same file can be selected again
            e.target.value = '';
        }
    });

    // Preference toggles
    document.getElementById('theme-toggle').addEventListener('change', toggleTheme);
    document.getElementById('color-theme-select').addEventListener('change', changeColorTheme);
    document.getElementById('auto-cookie-toggle').addEventListener('change', toggleAutoCookie);
    document.getElementById('accessibility-toggle').addEventListener('change', toggleAccessibility);

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
    document.getElementById('file-sort-select').addEventListener('change', sortAndRenderFiles);

    // Tools tab controls
    const mp3ConversionBtn = document.getElementById('start-mp3-conversion-btn');
    if (mp3ConversionBtn) {
        mp3ConversionBtn.addEventListener('click', submitVideoToMp3Conversion);
    }

    const transformBtn = document.getElementById('apply-transform-btn');
    if (transformBtn) {
        transformBtn.addEventListener('click', applyVideoTransformation);
    }

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
