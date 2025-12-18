/**
 * Video Downloader Frontend Application
 *
 * Handles download management, file browsing, settings, logs, and tools.
 * Uses vanilla JavaScript with REST API polling for updates.
 */

const API_BASE = window.location.origin;
const WS_BASE = API_BASE.replace('http', 'ws');
// Simple debug logger: will be initialized from admin settings at runtime
let DEBUG_LOGS = false;
function debugLog(...args) {
    if (DEBUG_LOGS) {
        console.log(...args);
    }
}

// (removed noisy console filtering — using native console behavior)

// WebSocket tracking (available but HTTP polling is default for compatibility)
const activeWebSockets = new Map();

// Interval ID for updating running time counters on active conversions
let runningTimeInterval = null;

// Domain mappings for display names (loaded from domain_mappings.json)
let domainMappings = {};

/**
 * Authentication Management
 * Handles JWT token storage, retrieval, and logout functionality
 */

// MIGRATION: Clean up old localStorage entries from previous versions
// These are no longer used for security reasons (prevent privilege escalation)
if (localStorage.getItem('username')) {
    localStorage.removeItem('username');
}
if (localStorage.getItem('is_admin')) {
    localStorage.removeItem('is_admin');
}

const AUTH = {
    // SECURITY: Store user info in memory only (not localStorage)
    // This prevents users from editing is_admin to gain privileges
    _userInfo: null,

    /**
     * Get stored JWT token
     * @returns {string|null} JWT token or null if not authenticated
     */
    getToken() {
        return localStorage.getItem('auth_token');
    },

    /**
     * Get stored username from memory
     * @returns {string|null} Username or null if not authenticated
     */
    getUsername() {
        return this._userInfo?.username || null;
    },

    /**
     * Check if current user is admin from memory
     * @returns {boolean} True if user is admin
     */
    isAdmin() {
        return this._userInfo?.is_admin === true;
    },

    /**
     * Get user ID from memory
     * @returns {string|null} User ID or null if not authenticated
     */
    getUserId() {
        return this._userInfo?.user_id || null;
    },

    /**
     * Store authentication data after successful login
     * SECURITY: Only stores token in localStorage
     * User info is stored in memory and fetched from backend
     * @param {string} token - JWT access token
     */
    setAuth(token) {
        localStorage.setItem('auth_token', token);
    },

    /**
     * Store user info in memory (called after /api/auth/me response)
     * @param {object} userInfo - User info from backend
     */
    setUserInfo(userInfo) {
        this._userInfo = userInfo;
    },

    /**
     * Clear authentication data
     */
    clearAuth() {
        localStorage.removeItem('auth_token');
        this._userInfo = null;
    },

    /**
     * Logout user - call logout endpoint and redirect to login
     */
    async logout() {
        try {
            // Call logout endpoint for audit logging
            await apiFetch('/api/auth/logout', { method: 'POST' });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            // Always clear auth and redirect, even if logout call fails
            this.clearAuth();
            window.location.href = '/assets/login.html';
        }
    }
};

/**
 * Helper function to add JWT token to file URLs
 * Used for img src, video src, and download links that can't send Authorization headers
 * @param {string} url - File URL
 * @returns {string} URL with ?token= parameter appended
 */
function addTokenToUrl(url) {
    const token = AUTH.getToken();
    if (!token) return url;

    // Check if URL already has query parameters
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}token=${encodeURIComponent(token)}`;
}

/**
 * Enhanced fetch wrapper with authentication
 * Automatically adds Authorization header with JWT token
 * Handles 401 (unauthorized) and 403 (forbidden) responses
 *
 * @param {string} url - API endpoint URL
 * @param {object} options - Fetch options (method, headers, body, etc.)
 * @returns {Promise<Response>} Fetch response
 */
async function apiFetch(url, options = {}) {
    // Get token from localStorage
    const token = AUTH.getToken();

    // Add Authorization header if token exists
    if (token) {
        options.headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`
        };
    }

    try {
        const response = await fetch(url, options);

        // Handle authentication errors
        if (response.status === 401) {
            // Unauthorized - token expired or invalid
            console.warn('Authentication required - redirecting to login');
            AUTH.clearAuth();
            window.location.href = '/assets/login.html';
            throw new Error('Authentication required');
        }

        if (response.status === 403) {
            // Forbidden - insufficient permissions
            showToast('You do not have permission to perform this action', 'error');
            throw new Error('Insufficient permissions');
        }

        return response;
    } catch (error) {
        // Re-throw for caller to handle
        throw error;
    }
}

/**
 * Security: Escape HTML to prevent XSS attacks
 * Converts special characters to HTML entities
 * @param {string} unsafe - Untrusted user input
 * @returns {string} Safe HTML string
 */
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Check authentication status on page load
 * Verifies token is valid and redirects to login if needed
 */
async function checkAuth() {
    try {
        // Check if auth is enabled
        const statusResponse = await fetch('/api/auth/status');

        if (!statusResponse.ok) {
            // SECURITY: Cannot verify auth status - fail closed by redirecting to login
            // This prevents bypassing auth by causing errors
            console.error('Failed to check auth status - assuming secure mode');
            window.location.href = '/assets/login.html';
            return;
        }

        const statusData = await statusResponse.json();

        // Only allow access if we get explicit confirmation that auth is disabled
        if (statusData.auth_enabled === false) {
            // Authentication is explicitly disabled - allow access
            debugLog('Authentication is disabled');
            // Hide logout button when auth is disabled
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) {
                logoutBtn.style.display = 'none';
            }

            // SHOW admin settings icon when auth is disabled (backward compatibility)
            const adminSettingsIcon = document.getElementById('admin-settings-icon-btn');
            if (adminSettingsIcon) {
                adminSettingsIcon.style.display = 'flex';
            }
            return;
        }

        // Auth is enabled (or status unclear) - require authentication
        const token = AUTH.getToken();
        if (!token) {
            // No token - redirect to login
            debugLog('No auth token found - redirecting to login');
            window.location.href = '/assets/login.html';
            return;
        }

        // Verify token is valid by calling /api/auth/me
        const response = await apiFetch('/api/auth/me');
        if (!response.ok) {
            // Token invalid - redirect to login
            debugLog('Invalid token - redirecting to login');
            AUTH.clearAuth();
            window.location.href = '/assets/login.html';
            return;
        }

        // Token valid - store user info in memory and display
        const userData = await response.json();
        AUTH.setUserInfo(userData);

        // Show logout button when authenticated
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.style.display = 'flex';
        }

        // Show/hide admin settings icon based on admin status
        const adminSettingsIcon = document.getElementById('admin-settings-icon-btn');
        if (adminSettingsIcon) {
            if (AUTH.isAdmin()) {
                adminSettingsIcon.style.display = 'flex';
            } else {
                adminSettingsIcon.style.display = 'none';
            }
        }

        displayUserInfo(userData);
    } catch (error) {
        console.error('Auth check error:', error);
        // SECURITY: On error, fail closed by redirecting to login
        // Never assume auth is disabled on error - this would be a security bypass
        console.error('Cannot verify authentication status - failing secure');
        window.location.href = '/assets/login.html';
    }
}

/**
 * Display user info in header
 * Shows username, admin badge, and logout button
 * @param {object} userData - User data from /api/auth/me
 */
function displayUserInfo(userData) {
    const header = document.querySelector('header .header-content');
    if (!header) return;

    // Check if user info already exists
    let userInfoContainer = document.getElementById('user-info-container');
    if (userInfoContainer) {
        // Already exists, don't add again
        return;
    }

    // Create user info container
    userInfoContainer = document.createElement('div');
    userInfoContainer.id = 'user-info-container';
    userInfoContainer.style.cssText = `
        margin-left: auto;
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 0.5rem 1rem;
        background: var(--glass-bg);
        backdrop-filter: blur(10px);
        border: 1px solid var(--glass-border);
        border-radius: 12px;
    `;

    // Username with admin badge (no logout button - using icon button instead)
    const usernameSpan = document.createElement('span');
    usernameSpan.style.cssText = `
        color: var(--text-light);
        font-weight: 500;
        font-size: 0.9rem;
    `;
    usernameSpan.textContent = userData.username;
    if (userData.is_admin) {
        const adminBadge = document.createElement('span');
        adminBadge.style.cssText = `
            margin-left: 0.5rem;
            padding: 0.125rem 0.5rem;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: #000;
            font-size: 0.7rem;
            font-weight: 600;
            border-radius: 6px;
            text-transform: uppercase;
        `;
        adminBadge.textContent = 'Admin';
        usernameSpan.appendChild(adminBadge);
    }

    userInfoContainer.appendChild(usernameSpan);

    // Insert before the header-icons div (so username appears between logo and icons)
    const headerIcons = header.querySelector('.header-icons');
    if (headerIcons) {
        header.insertBefore(userInfoContainer, headerIcons);
    } else {
        header.appendChild(userInfoContainer);
    }
}

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
                loadHardwareInfo();
                loadCookieFilesSettings();
            }

            if (targetTab === 'files') {
                loadFiles();
            }

            if (targetTab === 'tools') {
                loadToolsTab();
            }

            if (targetTab === 'admin-settings') {
                loadAdminSettingsTab();
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
        const response = await apiFetch(`${API_BASE}/api/downloads`);
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
    const visibility = document.getElementById('download-visibility').value;
    const isPublic = visibility === 'public';

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
                const response = await apiFetch(`${API_BASE}/api/download`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        url,
                        cookies_file: cookiesFile,
                        is_public: isPublic
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
            document.getElementById('download-visibility').value = 'public';
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

        const response = await apiFetch(`${API_BASE}/api/upload`, {
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
        const response = await apiFetch(`${API_BASE}/api/downloads`);
        if (!response.ok) throw new Error('Failed to load downloads');

        const data = await response.json();
        const downloads = data.downloads || data;  // Support both new and old format
        const hiddenActiveCount = data.hidden_active_count || 0;

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

        // Render both lists (active list has special privacy handling)
        renderActiveDownloads('active-downloads-list', active, hiddenActiveCount);
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
 * Render Active Downloads with Privacy Placeholder
 * Shows a placeholder card when there are hidden private downloads in the queue
 */
function renderActiveDownloads(containerId, downloads, hiddenCount = 0) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '';

    // Show placeholder if there are hidden private downloads
    if (hiddenCount > 0) {
        const placeholder = document.createElement('div');
        placeholder.className = 'download-item private-placeholder';
        placeholder.innerHTML = `
            <div class="download-content">
                <div class="download-header">
                    <div class="download-url">🔒 Private Content in Queue</div>
                    <span class="badge badge-secondary">Queued</span>
                </div>
                <div class="download-info">
                    <p style="margin: 0.5rem 0; color: var(--text-muted);">
                        ${hiddenCount} private download${hiddenCount > 1 ? 's' : ''} from other users ${hiddenCount > 1 ? 'are' : 'is'} currently in the queue.
                        Your downloads will begin when the queue is free.
                    </p>
                </div>
            </div>
        `;
        container.appendChild(placeholder);
    }

    // Show user's own downloads and public downloads
    if (downloads.length === 0 && hiddenCount === 0) {
        container.innerHTML = `
            <div class="empty-state-enhanced">
                <span class="empty-icon">📥</span>
                <h3>No active downloads</h3>
                <p>Paste a video URL in the form above to get started</p>
            </div>
        `;
        return;
    }

    // Render visible downloads
    renderDownloads(containerId, downloads, true);
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
function renderDownloads(containerId, downloads, append = false) {
    const container = document.getElementById(containerId);

    if (downloads.length === 0 && !append) {
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

    // If no downloads and we're appending, just return (placeholder already shown)
    if (downloads.length === 0 && append) {
        return;
    }

    // Get current user info for badge display logic
    const currentUserId = AUTH.getUserId();
    const isAdmin = AUTH.isAdmin();

    const html = downloads.map(download => {
        // Determine if this is user's own download
        const isOwnDownload = download.user_id === currentUserId;

        // Build visibility badge (clickable if owner or admin)
        const canToggleVisibility = isAdmin || isOwnDownload;
        let visibilityBadge = '';

        if (download.is_public) {
            // Public badge - green/success themed
            if (canToggleVisibility) {
                visibilityBadge = `<span class="badge badge-success visibility-toggle"
                    onclick="toggleDownloadVisibility('${download.id}', event)"
                    title="Click to make private">🌐 Public</span>`;
            } else {
                visibilityBadge = `<span class="badge badge-success" title="Public download">🌐 Public</span>`;
            }
        } else {
            // Private badge - warning/lock themed
            if (canToggleVisibility) {
                visibilityBadge = `<span class="badge badge-warning visibility-toggle"
                    onclick="toggleDownloadVisibility('${download.id}', event)"
                    title="Click to make public">🔒 Private</span>`;
            } else {
                visibilityBadge = `<span class="badge badge-warning" title="Private download">🔒 Private</span>`;
            }
        }

        // Build ownership badge - use theme colors
        let ownershipBadge = '';
        if (download.username) {
            ownershipBadge = `<span class="badge badge-primary" title="Downloaded by">${escapeHtml(download.username)}</span>`;
        }

        return `
        <div class="download-item ${download.status === 'completed' && download.thumbnail ? 'with-thumbnail' : ''}" data-id="${download.id}">
            ${download.status === 'completed' && download.thumbnail ? `
                <div class="download-thumbnail">
                    <img src="${addTokenToUrl(`${API_BASE}/api/files/thumbnail/${download.id}`)}"
                         alt="Video thumbnail"
                         onerror="this.style.display='none'">
                </div>
            ` : ''}

            <div class="download-content">
                <div class="download-header">
                    <div class="download-url">${download.filename ? escapeHtml(download.filename) : escapeHtml(download.url)}</div>
                    <div class="download-badges">
                        <span class="download-status status-${download.status}">${download.status}</span>
                        ${visibilityBadge}
                        ${ownershipBadge}
                    </div>
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
    `;
    }).join('');

    if (append) {
        // Append to existing content (for active downloads with placeholder)
        container.insertAdjacentHTML('beforeend', html);
    } else {
        // Replace all content
        container.innerHTML = html;
    }
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

/**
 * Toggle download visibility between public and private
 * @param {string} downloadId - Download ID to toggle
 * @param {Event} event - Click event
 */
async function toggleDownloadVisibility(downloadId, event) {
    // Prevent event bubbling
    event?.stopPropagation();

    const badge = event?.target;
    if (!badge) return;

    // Store original content
    const originalContent = badge.innerHTML;
    const wasPublic = badge.classList.contains('badge-success');

    try {
        // Show loading state
        badge.innerHTML = wasPublic ? '🔒 Making private...' : '🌐 Making public...';
        badge.style.opacity = '0.6';

        const response = await apiFetch(`${API_BASE}/api/downloads/${downloadId}/toggle-visibility`, {
            method: 'PATCH'
        });

        if (!response.ok) {
            throw new Error('Failed to toggle visibility');
        }

        const updatedDownload = await response.json();

        // Show success message
        showToast(
            `Download is now ${updatedDownload.is_public ? 'public' : 'private'}`,
            'success'
        );

        // Reload downloads to update the UI
        loadDownloads();

    } catch (error) {
        console.error('Failed to toggle visibility:', error);
        showToast('Failed to change visibility', 'error');

        // Restore original badge content
        badge.innerHTML = originalContent;
        badge.style.opacity = '1';
    }
}

/**
 * Toggle file visibility between public and private (for File Browser)
 * @param {string} downloadId - Download ID to toggle
 * @param {Event} event - Click event
 */
async function toggleFileVisibility(downloadId, event) {
    // Prevent event bubbling
    event?.stopPropagation();

    const badge = event?.target;
    if (!badge) return;

    // Store original content
    const originalContent = badge.innerHTML;
    const wasPublic = badge.classList.contains('badge-success');

    try {
        // Show loading state
        badge.innerHTML = wasPublic ? '🔒 Making private...' : '🌐 Making public...';
        badge.style.opacity = '0.6';

        const response = await apiFetch(`${API_BASE}/api/downloads/${downloadId}/toggle-visibility`, {
            method: 'PATCH'
        });

        if (!response.ok) {
            throw new Error('Failed to toggle visibility');
        }

        const updatedDownload = await response.json();

        // Show success message
        showToast(
            `File is now ${updatedDownload.is_public ? 'public' : 'private'}`,
            'success'
        );

        // Reload files to update the UI
        loadFiles();

    } catch (error) {
        console.error('Failed to toggle file visibility:', error);
        showToast('Failed to change visibility', 'error');

        // Restore original badge content
        badge.innerHTML = originalContent;
        badge.style.opacity = '1';
    }
}

async function deleteDownload(downloadId, event) {
    const button = event?.target.closest('button');

    // Check if button is already in confirm state
    if (button?.dataset.confirmDelete === 'true') {
        // Second click - actually delete
        button.disabled = true;

        try {
            const response = await apiFetch(`${API_BASE}/api/downloads/${downloadId}`, {
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
    window.open(addTokenToUrl(`${API_BASE}/api/files/download/${downloadId}`), '_blank');
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
                <source src="${addTokenToUrl(`${API_BASE}/api/files/video/${downloadId}`)}">
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
        const response = await apiFetch(`${API_BASE}/api/settings/version`);
        if (!response.ok) throw new Error('Failed to load version info');

        const data = await response.json();
        document.getElementById('app-version').textContent = data.app_version;
        document.getElementById('ytdlp-version').textContent = data.ytdlp_version;

    } catch (error) {
        showToast('Failed to load version info', 'error');
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
            debugLog('Hardware info loaded from browser cache');
            return;
        }
    } catch (error) {
        console.warn('Failed to load hardware info from cache:', error);
    }

    // No cache found - fetch from server
    container.innerHTML = '<p class="empty-state">Loading hardware information...</p>';

    try {
        const response = await apiFetch(`${API_BASE}/api/hardware/info`);
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
        const response = await apiFetch(`${API_BASE}/api/hardware/refresh`, {
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
        const response = await apiFetch('/assets/documentation.json');
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
        const response = await apiFetch(`${API_BASE}/api/settings/update-ytdlp`, {
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
        const response = await apiFetch(`${API_BASE}/api/settings/clear-ytdlp-cache`, {
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
        const response = await apiFetch(`${API_BASE}/api/downloads/cleanup?days=${days}`, {
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
        const response = await apiFetch(`${API_BASE}/api/tools/conversions/cleanup?hours=${hours}`, {
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
        const response = await apiFetch(`${API_BASE}/api/settings/cookies`);

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

        const response = await apiFetch(`${API_BASE}/api/settings/cookies/upload`, {
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
        const response = await apiFetch(`${API_BASE}/api/settings/cookies/${encodeURIComponent(filename)}`, {
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
        const response = await apiFetch(`${API_BASE}/api/cookies`);
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
        debugLog('No cookies endpoint available');
    }
}

// Logs Management
let logsPollingInterval = null;
let allLogs = [];
let latestLogSequence = 0;

// Log type management for dual logging system
let currentLogType = 'user';  // Default to user logs
let latestAdminSequence = 0;
let latestUserSequence = 0;

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

    debugLog(`🔍 Filtering logs: Total=${allLogs.length}, Level='${levelFilter}', Component='${componentFilter}', DownloadID='${downloadIdFilter}'`);

    // Component consolidation mapping
    const componentMapping = {
        'Settings': 'System',
        'Test': 'System',
        'ConversionQueue': 'Queue',
        'YT-DLP-ERR': 'YT-DLP',
        'ToolConversion': 'Tools',
        'VideoTransform': 'Tools',
        'Thumbnail': 'Tools'
    };

    let filtered = allLogs;

    if (levelFilter) {
        filtered = filtered.filter(log => log.level === levelFilter);
    }

    if (componentFilter) {
        filtered = filtered.filter(log => {
            // Map the log's component to its filter group
            const mappedComponent = componentMapping[log.component] || log.component;
            return mappedComponent === componentFilter;
        });
    }

    if (downloadIdFilter) {
        filtered = filtered.filter(log => log.download_id && log.download_id.includes(downloadIdFilter));
    }

    debugLog(`✅ After filtering: ${filtered.length} logs to display`);
    displayLogs(filtered);
}

function displayLogs(logs) {
    const display = document.getElementById('logs-display');
    display.innerHTML = '';

    if (logs.length === 0) {
        const isPolling = logsPollingInterval !== null;

        // Determine log type text for display
        let logTypeText = currentLogType === 'both' ? 'all logs' : `${currentLogType} logs`;

        if (isPolling) {
            display.innerHTML = `<p class="empty-state">✅ Connected to log system. Viewing ${logTypeText}. Logs will appear here as events occur...</p>`;
        } else {
            display.innerHTML = '<p class="empty-state">❌ Log polling not running. Check browser console for errors.</p>';
        }
        return;
    }

    logs.forEach(log => {
        display.appendChild(renderLogEntry(log));
    });

    // Auto-scroll to bottom
    display.scrollTop = display.scrollHeight;
}


async function pollLogs() {
    try {
        // Build query parameters
        const params = new URLSearchParams();

        // Add log_type parameter
        params.append('log_type', currentLogType);

        // Use appropriate sequence based on log type
        let sinceSequence = 0;
        if (currentLogType === 'user') {
            sinceSequence = latestUserSequence;
        } else if (currentLogType === 'admin') {
            sinceSequence = latestAdminSequence;
        } else if (currentLogType === 'both') {
            // For "both", use the max of both sequences
            sinceSequence = Math.max(latestAdminSequence, latestUserSequence);
        }

        if (sinceSequence > 0) {
            params.append('since_sequence', sinceSequence);
        }

        const response = await apiFetch(`${API_BASE}/api/logs?${params}`);
        if (!response.ok) {
            // Handle 403 for non-admins trying to access admin logs
            if (response.status === 403) {
                console.warn('⚠️ Access denied to admin logs, switching to user logs');
                currentLogType = 'user';
                return;
            }
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        // Debug logging (only first 10 polls or if new logs received)
        if (!pollLogs.callCount) pollLogs.callCount = 0;
        pollLogs.callCount++;

        if (pollLogs.callCount <= 10 || data.logs.length > 0) {
            debugLog(`📨 Poll #${pollLogs.callCount}: Received ${data.logs.length} new ${data.log_type} logs`);
        }

        // Update sequences based on response
        if (data.latest_admin_sequence > 0) {
            latestAdminSequence = data.latest_admin_sequence;
        }
        if (data.latest_user_sequence > 0) {
            latestUserSequence = data.latest_user_sequence;
        }

        // Add new logs
        data.logs.forEach(log => {
            allLogs.push(log);

            // Keep only last 1000 logs in browser
            if (allLogs.length > 1000) {
                allLogs.shift();
            }
        });

        // Update display if logs tab is active and we have new logs
        if (data.logs.length > 0) {
            const logsTab = document.getElementById('logs-tab');
            if (logsTab && logsTab.classList.contains('active')) {
                filterLogs();
            }
        }

    } catch (error) {
        console.error('❌ Failed to poll logs:', error);
    }
}

function startLogsPolling() {
    if (logsPollingInterval) {
        debugLog('⚠️  Logs polling already running');
        return;
    }

    console.log('✅ Starting logs polling (every 5 seconds)');

    // Poll immediately
    pollLogs();

    // Then poll every 10 seconds
    logsPollingInterval = setInterval(pollLogs, 10000);
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

/**
 * Initialize log type controls for admin users
 * Shows the log type selector for admins and sets up event handling
 * SECURITY: Uses AUTH.isAdmin() which checks server-verified status in memory
 */
function initializeLogControls() {
    // Use AUTH.isAdmin() to check admin status securely
    // This prevents users from manipulating localStorage to gain admin access
    const isAdmin = AUTH.isAdmin();

    if (isAdmin) {
        // Show log type selector for admins
        const container = document.getElementById('log-type-selector-container');
        if (container) {
            container.style.display = 'block';

            // Handle log type changes
            const logTypeSelector = document.getElementById('log-type-selector');
            logTypeSelector.addEventListener('change', async (e) => {
                currentLogType = e.target.value;
                debugLog(`📊 Switching to ${currentLogType} logs`);

                // Clear existing logs and reset sequences
                allLogs = [];
                latestLogSequence = 0;
                latestAdminSequence = 0;
                latestUserSequence = 0;

                // Immediately fetch logs of new type
                await pollLogs();
                filterLogs();
            });
        }
    } else {
        // Regular users always see user logs
        currentLogType = 'user';
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

/**
 * Load domain mappings from domain_mappings.json
 * Creates a reverse lookup map (domain -> display name)
 */
async function loadDomainMappings() {
    try {
        const response = await apiFetch(`${API_BASE}/assets/domain_mappings.json`);
        if (!response.ok) {
            console.warn('Could not load domain_mappings.json, using fallback');
            return;
        }
        const mappings = await response.json();

        // Create reverse lookup: domain -> display name
        // e.g., {"youtu": "Youtube", "youtube": "Youtube", "x": "X", ...}
        domainMappings = {};
        for (const [displayName, domains] of Object.entries(mappings)) {
            for (const domain of domains) {
                domainMappings[domain.toLowerCase()] = displayName;
            }
        }
    } catch (e) {
        console.warn('Failed to load domain mappings:', e);
    }
}

function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;

        // Extract main domain (e.g., instagram.com from www.instagram.com)
        const parts = hostname.split('.');
        let domain;
        if (parts.length >= 2) {
            domain = parts[parts.length - 2]; // e.g., "instagram" from "www.instagram.com"
        } else {
            domain = hostname;
        }

        // Convert to lowercase for lookup
        const domainLower = domain.toLowerCase();

        // Check if we have a mapping for this domain
        if (domainMappings[domainLower]) {
            return domainMappings[domainLower];
        }

        // Otherwise, capitalize first letter
        return domain.charAt(0).toUpperCase() + domain.slice(1);
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
            document.getElementById('download-visibility').value = 'public';
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
        const response = await apiFetch(`${API_BASE}/api/files`);
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

    // Get current user info for badge display logic
    const currentUserId = AUTH.getUserId();
    const isAdmin = AUTH.isAdmin();

    container.innerHTML = files.map(file => {
        // Determine if this is user's own file
        const isOwnFile = file.user_id === currentUserId;
        const canToggleVisibility = isAdmin || isOwnFile;

        // Build visibility badge (clickable if owner or admin)
        let visibilityBadge = '';
        if (file.is_public) {
            // Public badge - green/success themed
            if (canToggleVisibility) {
                visibilityBadge = `<span class="badge badge-success visibility-toggle"
                    onclick="toggleFileVisibility('${file.id}', event)"
                    title="Click to make private">🌐 Public</span>`;
            } else {
                visibilityBadge = `<span class="badge badge-success" title="Public file">🌐 Public</span>`;
            }
        } else {
            // Private badge - warning/lock themed
            if (canToggleVisibility) {
                visibilityBadge = `<span class="badge badge-warning visibility-toggle"
                    onclick="toggleFileVisibility('${file.id}', event)"
                    title="Click to make public">🔒 Private</span>`;
            } else {
                visibilityBadge = `<span class="badge badge-warning" title="Private file">🔒 Private</span>`;
            }
        }

        // Build ownership badge - use theme colors
        let ownershipBadge = '';
        if (file.username) {
            ownershipBadge = `<span class="badge badge-primary" title="Uploaded/Downloaded by">${escapeHtml(file.username)}</span>`;
        }

        return `
        <div class="file-item" data-download-id="${file.id}">
            <input type="checkbox" class="file-checkbox">
            <div class="file-info">
                <div class="file-name-row">
                    <span class="file-name">${escapeHtml(file.filename)}</span>
                    <div class="file-badges">
                        ${visibilityBadge}
                        ${ownershipBadge}
                    </div>
                </div>
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
            const response = await apiFetch(`${API_BASE}/api/files/${downloadId}`, {
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
                const response = await apiFetch(`${API_BASE}/api/files/${downloadId}`, {
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
        const sizeResponse = await apiFetch(`${API_BASE}/api/files/calculate-zip-size`, {
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

        const response = await apiFetch(`${API_BASE}/api/files/download-zip`, {
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
        const response = await apiFetch(`${API_BASE}/api/files`);
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

        const response = await apiFetch(`${API_BASE}/api/tools/video-to-mp3`, {
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
        const response = await apiFetch(`${API_BASE}/api/tools/conversions`);

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
        const response = await apiFetch(`${API_BASE}/api/tools/conversions/${conversionId}/cancel`, {
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
        downloadUrl = addTokenToUrl(`${API_BASE}/api/tools/audio/${conversionId}`);
    }
    // Video transforms modify the original file, so download from download endpoint (not video endpoint)
    else if (toolType.startsWith('video_transform_')) {
        downloadUrl = addTokenToUrl(`${API_BASE}/api/files/download/${sourceDownloadId}`);
    }
    else {
        // Fallback to audio endpoint for unknown types
        downloadUrl = addTokenToUrl(`${API_BASE}/api/tools/audio/${conversionId}`);
    }

    // Create hidden link to trigger download instead of opening in new tab
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename || 'download';
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

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
            const response = await apiFetch(`${API_BASE}/api/tools/conversions/${conversionId}`, {
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

        const response = await apiFetch(`${API_BASE}/api/tools/transform`, {
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

// ============================================
// USER MANAGEMENT
// ============================================

/**
 * Load and display all users in the users table
 */
async function loadUsers() {
    const tbody = document.getElementById('users-table-body');
    const loading = document.getElementById('users-loading');
    const empty = document.getElementById('users-empty');

    if (!tbody || !loading || !empty) {
        console.log('User management elements not found, skipping loadUsers');
        return;
    }

    loading.style.display = 'block';
    tbody.innerHTML = '';
    empty.style.display = 'none';

    try {
        const response = await apiFetch('/api/users');
        if (!response.ok) {
            throw new Error('Failed to load users');
        }

        const users = await response.json();
        loading.style.display = 'none';

        if (users.length === 0) {
            empty.style.display = 'block';
            return;
        }

        users.forEach(user => {
            const row = createUserRow(user);
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading users:', error);
        loading.style.display = 'none';
        showToast('Failed to load users', 'error');
    }
}

/**
 * Create a table row for a user
 */
function createUserRow(user) {
    const row = document.createElement('tr');
    row.dataset.userId = user.id;

    // Auth Type badge
    let authTypeBadge;
    if (user.oidc_provider) {
        // SSO user - show provider name
        const providerName = escapeHtml(user.oidc_provider);
        authTypeBadge = `<span class="badge badge-info" title="SSO: ${providerName}">SSO</span>`;
    } else {
        // Local user
        authTypeBadge = '<span class="badge badge-secondary">Local</span>';
    }

    // Status badge
    const statusBadge = user.is_disabled
        ? '<span class="badge badge-danger">Disabled</span>'
        : '<span class="badge badge-success">Active</span>';

    // Role badge
    const roleBadge = user.is_admin
        ? '<span class="badge badge-primary">Admin</span>'
        : '<span class="badge badge-secondary">User</span>';

    // Format dates
    const lastLogin = user.last_login
        ? new Date(user.last_login).toLocaleString()
        : 'Never';
    const created = new Date(user.created_at).toLocaleString();

    // Prevent editing/deleting current user
    const currentUserId = AUTH.getUserId();
    const isSelf = user.id === currentUserId;

    // SECURITY: Escape username to prevent XSS
    const safeUsername = escapeHtml(user.username);

    row.innerHTML = `
        <td><strong>${safeUsername}</strong></td>
        <td>${escapeHtml(user.oidc_email || '')}</td>
        <td>${authTypeBadge}</td>
        <td>${statusBadge}</td>
        <td>${roleBadge}</td>
        <td>${lastLogin}</td>
        <td class="actions-cell">
            <button class="btn btn-small btn-secondary edit-user-btn"
                    data-user-id="${user.id}" ${isSelf ? 'disabled title="Cannot edit yourself"' : ''}>
                Edit
            </button>
            <button class="btn btn-small btn-danger delete-user-btn"
                    data-user-id="${user.id}" ${isSelf ? 'disabled title="Cannot delete yourself"' : ''}>
                Delete
            </button>
        </td>
    `;

    return row;
}

/**
 * Open create user modal
 */
function openCreateUserModal() {
    const modal = document.getElementById('user-modal');
    const title = document.getElementById('user-modal-title');
    const submitBtn = document.getElementById('user-form-submit');
    const form = document.getElementById('user-form');
    const disabledGroup = document.getElementById('user-form-disabled-group');
    const usernameInput = document.getElementById('user-form-username');

    // Reset form
    form.reset();
    document.getElementById('user-form-id').value = '';
    disabledGroup.style.display = 'none';

    // Clear read-only/display fields
    const emailEl = document.getElementById('user-form-email');
    const authTypeEl = document.getElementById('user-form-auth-type');
    const idDisplay = document.getElementById('user-form-id-display');
    const createdDisplay = document.getElementById('user-form-created');
    const lastLoginDisplay = document.getElementById('user-form-last-login');
    const oidcProviderEl = document.getElementById('user-form-oidc-provider');

    if (emailEl) emailEl.value = '';
    if (authTypeEl) authTypeEl.textContent = 'Local';
    if (idDisplay) idDisplay.textContent = '';
    if (createdDisplay) createdDisplay.textContent = '';
    if (lastLoginDisplay) lastLoginDisplay.textContent = '';
    if (oidcProviderEl) oidcProviderEl.textContent = '';

    // Enable username field
    if (usernameInput) {
        usernameInput.disabled = false;
    }

    // Set modal title and button text
    title.textContent = 'Create New User';
    submitBtn.textContent = 'Create User';

    // Make password required for new users
    document.getElementById('user-form-password').required = true;
    document.getElementById('user-form-password-confirm').required = true;
    document.getElementById('user-form-password').placeholder = '';

    modal.style.display = 'flex';
}

/**
 * Open edit user modal
 */
async function openEditUserModal(userId) {
    const modal = document.getElementById('user-modal');
    const title = document.getElementById('user-modal-title');
    const submitBtn = document.getElementById('user-form-submit');
    const form = document.getElementById('user-form');
    const disabledGroup = document.getElementById('user-form-disabled-group');
    const usernameInput = document.getElementById('user-form-username');

    try {
        // Fetch user details
        const response = await apiFetch(`/api/users`);
        const users = await response.json();
        const user = users.find(u => u.id === userId);

        if (!user) {
            throw new Error('User not found');
        }

        // Populate form
        document.getElementById('user-form-id').value = user.id;
        document.getElementById('user-form-username').value = user.username;
        document.getElementById('user-form-is-admin').checked = user.is_admin;
        document.getElementById('user-form-is-disabled').checked = user.is_disabled;

        // Populate read-only/display fields
        const emailEl = document.getElementById('user-form-email');
        const authTypeEl = document.getElementById('user-form-auth-type');
        const idDisplay = document.getElementById('user-form-id-display');
        const createdDisplay = document.getElementById('user-form-created');
        const lastLoginDisplay = document.getElementById('user-form-last-login');
        const oidcProviderEl = document.getElementById('user-form-oidc-provider');

        if (emailEl) emailEl.value = user.oidc_email || '';
        if (authTypeEl) authTypeEl.textContent = user.oidc_provider ? `SSO: ${user.oidc_provider}` : 'Local';
        if (idDisplay) idDisplay.textContent = user.id;
        if (createdDisplay) createdDisplay.textContent = user.created_at ? new Date(user.created_at).toLocaleString() : '';
        if (lastLoginDisplay) lastLoginDisplay.textContent = user.last_login ? new Date(user.last_login).toLocaleString() : 'Never';
        if (oidcProviderEl) oidcProviderEl.textContent = user.oidc_provider || '';

        // Disable username field (cannot change username)
        if (usernameInput) {
            usernameInput.disabled = true;
        }

        // Password optional for edit
        document.getElementById('user-form-password').required = false;
        document.getElementById('user-form-password-confirm').required = false;
        document.getElementById('user-form-password').placeholder = 'Leave blank to keep current password';

        // Show disabled checkbox
        disabledGroup.style.display = 'block';

        // Set modal title and button text
        title.textContent = `Edit User: ${user.username}`;
        submitBtn.textContent = 'Save Changes';

        modal.style.display = 'flex';
    } catch (error) {
        console.error('Error loading user:', error);
        showToast('Failed to load user details', 'error');
    }
}

/**
 * Handle user form submission (create or update)
 */
async function handleUserFormSubmit(e) {
    e.preventDefault();

    const userId = document.getElementById('user-form-id').value;
    const username = document.getElementById('user-form-username').value.trim();
    const password = document.getElementById('user-form-password').value;
    const passwordConfirm = document.getElementById('user-form-password-confirm').value;
    const isAdmin = document.getElementById('user-form-is-admin').checked;
    const isDisabled = document.getElementById('user-form-is-disabled').checked;

    // Validation
    if (userId === '' && password !== passwordConfirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    if (userId !== '' && password && password !== passwordConfirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    const submitBtn = document.getElementById('user-form-submit');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Saving...';

    try {
        let response;

        if (userId === '') {
            // Create new user
            response = await apiFetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, is_admin: isAdmin })
            });
        } else {
            // Update existing user
            const updateData = { is_admin: isAdmin, is_disabled: isDisabled };
            if (password) {
                updateData.password = password;
            }

            response = await apiFetch(`/api/users/${userId}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updateData)
            });
        }

        if (response.ok) {
            showToast(userId ? 'User updated successfully' : 'User created successfully', 'success');
            closeUserModal();
            loadUsers(); // Refresh users list
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to save user');
        }
    } catch (error) {
        console.error('Error saving user:', error);
        showToast(error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = userId ? 'Save Changes' : 'Create User';
    }
}

/**
 * Close user modal
 */
function closeUserModal() {
    const modal = document.getElementById('user-modal');
    const usernameInput = document.getElementById('user-form-username');
    modal.style.display = 'none';
    document.getElementById('user-form').reset();
    if (usernameInput) {
        usernameInput.disabled = false;
    }
}

/**
 * Open delete user confirmation modal
 */
function openDeleteUserModal(userId) {
    // Find user in table
    const row = document.querySelector(`tr[data-user-id="${userId}"]`);
    if (!row) return;

    const username = row.querySelector('strong').textContent;

    document.getElementById('delete-user-username').textContent = username;
    document.getElementById('delete-user-confirm').dataset.userId = userId;
    document.getElementById('delete-user-modal').style.display = 'flex';
}

/**
 * Handle user deletion
 */
async function handleDeleteUser() {
    const userId = document.getElementById('delete-user-confirm').dataset.userId;
    const confirmBtn = document.getElementById('delete-user-confirm');

    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Deleting...';

    try {
        const response = await apiFetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('User deleted successfully', 'success');
            closeDeleteUserModal();
            loadUsers(); // Refresh users list
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to delete user');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        showToast(error.message, 'error');
    } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Delete User';
    }
}

/**
 * Close delete user modal
 */
function closeDeleteUserModal() {
    document.getElementById('delete-user-modal').style.display = 'none';
}

/**
 * Load admin settings tab
 * Initializes user management and subsection tabs
 */
async function loadAdminSettingsTab() {
    console.log('Loading admin settings tab...');

    // Load user management by default
    loadUsers();

    // Initialize subsection tabs
    initSubsectionTabs();

    // Load all admin settings upfront so everything is ready
    await loadAdminSettings();
    
    // Preload all app management settings so they're available when user clicks any tab
    await loadAllAppManagementSettings();
    
    // Load hardware info for System Info subsection
    loadHardwareInfo();

    console.log('Admin settings tab fully loaded');
}

/**
 * Initialize subsection tabs (for System & App Management)
 */
function initSubsectionTabs() {
    const subsectionButtons = document.querySelectorAll('.subsection-tab');

    subsectionButtons.forEach(button => {
        // Remove any existing listeners to prevent duplicates
        const newButton = button.cloneNode(true);
        button.parentNode.replaceChild(newButton, button);

        newButton.addEventListener('click', () => {
            const subsectionName = newButton.dataset.subsection;
            const tabsContainer = newButton.closest('.subsection-tabs');
            console.log(`Tab clicked: ${subsectionName}`, { button: newButton, container: tabsContainer });
            
            if (!tabsContainer) return;

            // Find the parent container that directly contains this tab group
            // First check if tabs container has a parent with .subsection-content or section
            let parentContainer = tabsContainer.parentElement;
            while (parentContainer && !parentContainer.classList.contains('subsection-content') && !parentContainer.classList.contains('tab-content') && parentContainer.tagName !== 'SECTION') {
                parentContainer = parentContainer.parentElement;
            }
            
            if (!parentContainer) return;

            // Remove active from all tabs in this tab group
            tabsContainer.querySelectorAll('.subsection-tab').forEach(btn => {
                btn.classList.remove('active');
            });
            newButton.classList.add('active');

            // Only hide/show direct children of parentContainer that are subsection-content
            // This ensures we only affect the subsections directly under this parent
            const allSubsections = Array.from(parentContainer.children).filter(child => 
                child.classList.contains('subsection-content')
            );
            allSubsections.forEach(content => {
                content.classList.remove('active');
            });

            // Show target subsection
            const targetSelector = `#${subsectionName}-subsection`;
            const targetSubsection = parentContainer.querySelector(targetSelector);
            console.log(`Target subsection selector: ${targetSelector}, found:`, targetSubsection);
            if (targetSubsection) {
                targetSubsection.classList.add('active');

                // Load subsection-specific data
                loadSubsectionData(subsectionName);
            }
        });
    });
}

/**
 * Load data for specific subsection
 */
async function loadSubsectionData(subsectionName) {
    console.log(`Loading subsection data for: ${subsectionName}`);
    switch(subsectionName) {
        case 'database':
            loadDatabaseStats();
            break;
        case 'cleanup':
            // Cleanup already has event listeners
            console.log('Cleanup subsection selected');
            break;
        case 'system-info':
            loadHardwareInfo();
            break;
        case 'app-config':
            // Already preloaded in loadAllAppManagementSettings()
            break;
        case 'authentication-sso':
            // Both auth forms already preloaded, tabs within this section handle switching
            break;
        case 'local-auth':
            // Tab within authentication-sso, no additional loading needed
            break;
        case 'oidc-auth':
            // Tab within authentication-sso, no additional loading needed
            break;
        case 'security-config':
            // Already preloaded in loadAllAppManagementSettings()
            break;
        case 'audit-log':
            loadAuditLogs();
            break;
    }
}

/**
 * Load all app management settings upfront so they're ready when user clicks tabs
 * This fixes the issue where settings weren't populated until after navigating away and back
 */
async function loadAllAppManagementSettings() {
    try {
        // Ensure admin settings are loaded first
        if (!currentAdminSettings) {
            await loadAdminSettings();
        }
        
        // Preload all subsection data in parallel for better performance
        await Promise.all([
            loadAppConfigForm(),
            Promise.resolve(loadAuthenticationForm()),
            // loadOIDCConfigForm was renamed to loadOIDCConfig; call the existing implementation
            Promise.resolve(loadOIDCConfig()),
            Promise.resolve(loadSecurityConfigForm())
        ]);
        
        console.log('All app management settings preloaded');
    } catch (error) {
        console.error('Error preloading app management settings:', error);
    }
}

/**
 * Load database statistics
 */
async function loadDatabaseStats() {
    try {
        const response = await apiFetch('/api/admin/database/stats');
        if (!response.ok) {
            throw new Error('Failed to load database stats');
        }

        const stats = await response.json();
        const container = document.getElementById('database-stats');
        if (!container) return;

        container.innerHTML = `
            <div class="stat-card">
                <div class="stat-label">Database Size</div>
                <div class="stat-value">${stats.database_size_mb} MB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Users</div>
                <div class="stat-value">${stats.users}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Downloads</div>
                <div class="stat-value">${stats.downloads}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Conversions</div>
                <div class="stat-value">${stats.conversions}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Audit Logs</div>
                <div class="stat-value">${stats.audit_logs}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Login History</div>
                <div class="stat-value">${stats.user_login_history}</div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading database stats:', error);
        showToast('Failed to load database stats', 'error');
    }
}

/**
 * Handle database backup button click
 */
async function handleDatabaseBackup() {
    const btn = document.getElementById('database-backup-btn');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Creating Backup...';

    try {
        const response = await apiFetch('/api/admin/database/backup', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Failed to create backup');
        }

        const result = await response.json();
        showToast(`Backup created: ${result.filename} (${result.size_mb} MB)`, 'success');
    } catch (error) {
        console.error('Error creating backup:', error);
        showToast('Failed to create database backup', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Handle database VACUUM
 */
async function handleDatabaseVacuum() {
    const btn = document.getElementById('database-vacuum-btn');
    if (!btn) return;

    if (!confirm('VACUUM will rebuild the database file to reclaim space. This may take a few moments. Continue?')) {
        return;
    }

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Running VACUUM...';

    try {
        const response = await apiFetch('/api/admin/database/vacuum', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Failed to VACUUM database');
        }

        const result = await response.json();
        showToast(`Database VACUUM completed. New size: ${result.new_size_mb} MB`, 'success');

        // Reload stats to show new size
        loadDatabaseStats();
    } catch (error) {
        console.error('Error running VACUUM:', error);
        showToast('Failed to VACUUM database', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Handle database OPTIMIZE
 */
async function handleDatabaseOptimize() {
    const btn = document.getElementById('database-optimize-btn');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Optimizing...';

    try {
        const response = await apiFetch('/api/admin/database/optimize', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Failed to optimize database');
        }

        const result = await response.json();
        showToast(result.message, 'success');
    } catch (error) {
        console.error('Error optimizing database:', error);
        showToast('Failed to optimize database', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Handle database integrity check
 */
async function handleDatabaseIntegrityCheck() {
    const btn = document.getElementById('database-integrity-btn');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Checking...';

    try {
        const response = await apiFetch('/api/admin/database/integrity-check', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Failed to check database integrity');
        }

        const result = await response.json();

        if (result.status === 'ok') {
            showToast(result.message, 'success');
        } else {
            showToast(`${result.message}: ${result.details.join(', ')}`, 'error');
        }
    } catch (error) {
        console.error('Error checking database integrity:', error);
        showToast('Failed to check database integrity', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Load available backups
 */
async function loadBackups() {
    const container = document.getElementById('backups-list-container');
    const loadBtn = document.getElementById('load-backups-btn');
    const restoreBtn = document.getElementById('restore-backup-btn');

    if (!container) return;

    container.innerHTML = '<p class="loading-state">Loading backups...</p>';
    if (loadBtn) loadBtn.disabled = true;

    try {
        const response = await apiFetch('/api/admin/database/backups');
        if (!response.ok) {
            throw new Error('Failed to load backups');
        }

        const data = await response.json();

        if (data.backups.length === 0) {
            container.innerHTML = '<p class="empty-state">No backup files found</p>';
            if (restoreBtn) restoreBtn.disabled = true;
            return;
        }

        let html = '<div class="backups-list">';

        data.backups.forEach(backup => {
            const created = new Date(backup.created_at).toLocaleString();
            const typeColor = backup.type === 'Safety Backup' ? '#ffa500' : '#00ff88';
            html += `
                <div class="backup-item">
                    <div style="display: flex; align-items: center; gap: 1rem; flex: 1;">
                        <input type="radio" name="backup-select" value="${backup.filename}" id="backup-${backup.filename}">
                        <label for="backup-${backup.filename}" style="cursor: pointer; flex: 1;">
                            <strong>${backup.filename}</strong>
                            <span style="color: ${typeColor}; font-size: 0.75rem; margin-left: 0.5rem;">(${backup.type})</span><br>
                            <small style="color: var(--text-muted);">
                                Created: ${created} | Size: ${backup.size_mb} MB
                            </small>
                        </label>
                    </div>
                    <div style="display: flex; gap: 0.5rem; margin-left: auto;">
                        <button class="btn btn-small btn-primary download-backup-btn" data-filename="${backup.filename}"
                                title="Download this backup">
                            📥 Download
                        </button>
                        <button class="btn btn-small btn-danger delete-backup-btn" data-filename="${backup.filename}"
                                title="Delete this backup">
                            🗑️ Delete
                        </button>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;

        // Enable restore button when a backup is selected
        const radioButtons = container.querySelectorAll('input[name="backup-select"]');
        radioButtons.forEach(radio => {
            radio.addEventListener('change', () => {
                if (restoreBtn) restoreBtn.disabled = false;
            });
        });

        // Add event listeners to download buttons
        const downloadButtons = container.querySelectorAll('.download-backup-btn');
        downloadButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const filename = btn.dataset.filename;
                handleDownloadBackup(filename);
            });
        });

        // Add event listeners to delete buttons
        const deleteButtons = container.querySelectorAll('.delete-backup-btn');
        deleteButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const filename = btn.dataset.filename;
                handleDeleteBackup(filename);
            });
        });

    } catch (error) {
        console.error('Error loading backups:', error);
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to load backups</p>';
    } finally {
        if (loadBtn) loadBtn.disabled = false;
    }
}

/**
 * Handle restore from backup
 */
async function handleRestoreBackup() {
    const selectedRadio = document.querySelector('input[name="backup-select"]:checked');
    if (!selectedRadio) {
        showToast('Please select a backup to restore', 'error');
        return;
    }

    const backupFilename = selectedRadio.value;

    const confirmed = confirm(
        `⚠️ WARNING: This will restore the database from:\n\n${backupFilename}\n\n` +
        `ALL CURRENT DATA WILL BE REPLACED!\n\n` +
        `A safety backup of the current database will be created automatically.\n\n` +
        `Are you absolutely sure you want to continue?`
    );

    if (!confirmed) return;

    const restoreBtn = document.getElementById('restore-backup-btn');
    if (!restoreBtn) return;

    const originalText = restoreBtn.textContent;
    restoreBtn.disabled = true;
    restoreBtn.textContent = 'Restoring...';

    try {
        const response = await apiFetch(`/api/admin/database/restore?backup_filename=${encodeURIComponent(backupFilename)}`, {
            method: 'POST'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to restore backup');
        }

        const result = await response.json();
        showToast(
            `Database restored successfully from ${result.backup_filename}. Safety backup saved as ${result.safety_backup}`,
            'success'
        );

        // Reload stats and clear backup selection
        loadDatabaseStats();
        loadBackups();
    } catch (error) {
        console.error('Error restoring backup:', error);
        showToast(`Failed to restore backup: ${error.message}`, 'error');
    } finally {
        restoreBtn.disabled = false;
        restoreBtn.textContent = originalText;
    }
}

/**
 * Handle delete backup
 */
async function handleDeleteBackup(backupFilename) {
    if (!backupFilename) {
        showToast('Invalid backup filename', 'error');
        return;
    }

    const confirmed = confirm(
        `Are you sure you want to delete this backup?\n\n${backupFilename}\n\n` +
        `This action cannot be undone.`
    );

    if (!confirmed) return;

    try {
        // Extract just the filename part after backups/
        const filename = backupFilename.replace('backups/', '');

        const response = await apiFetch(`/api/admin/database/backups/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to delete backup');
        }

        const result = await response.json();
        showToast(result.message, 'success');

        // Reload backups list
        loadBackups();
    } catch (error) {
        console.error('Error deleting backup:', error);
        showToast(`Failed to delete backup: ${error.message}`, 'error');
    }
}

/**
 * Handle download backup
 */
async function handleDownloadBackup(backupFilename) {
    if (!backupFilename) {
        showToast('Invalid backup filename', 'error');
        return;
    }

    try {
        // Extract just the filename part after backups/
        const filename = backupFilename.replace('backups/', '');

        // Use apiFetch to download the file with auth
        const response = await apiFetch(`/api/admin/database/backups/${encodeURIComponent(filename)}/download`);

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to download backup');
        }

        // Get the blob from the response
        const blob = await response.blob();

        // Create a temporary download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();

        // Cleanup
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showToast('Backup downloaded successfully', 'success');
    } catch (error) {
        console.error('Error downloading backup:', error);
        showToast(`Failed to download backup: ${error.message}`, 'error');
    }
}

/**
 * Load audit logs
 */
async function loadAuditLogs(filterType = null) {
    const container = document.getElementById('audit-logs-container');
    if (!container) return;

    container.innerHTML = '<p class="loading-state">Loading audit logs...</p>';

    try {
        // Build API URL with filter
        let apiUrl = '/api/admin/audit-logs?limit=100';

        // Map filter types to event_type parameter
        if (filterType) {
            switch (filterType) {
                case 'user_management':
                    // Include user-related events
                    apiUrl += '&event_type=user_created,user_updated,user_deleted,user_disabled,user_enabled';
                    break;
                case 'failed_login':
                    apiUrl += '&event_type=login_failed';
                    break;
                case 'authentication':
                    apiUrl += '&event_type=login_success,logout';
                    break;
            }
        }

        const response = await apiFetch(apiUrl);
        if (!response.ok) {
            throw new Error('Failed to load audit logs');
        }

        const data = await response.json();

        if (data.logs.length === 0) {
            container.innerHTML = '<p class="empty-state">No audit logs found for this filter</p>';
            return;
        }

        let tableHTML = `
            <table class="users-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event Type</th>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
        `;

        data.logs.forEach(log => {
            const timestamp = new Date(log.timestamp).toLocaleString();
            const details = log.details ? JSON.stringify(log.details, null, 2) : 'N/A';

            // Color-code event types
            let badgeClass = 'badge-primary';
            if (log.event_type.includes('failed') || log.event_type.includes('deleted') || log.event_type.includes('disabled')) {
                badgeClass = 'badge-danger';
            } else if (log.event_type.includes('success') || log.event_type.includes('created') || log.event_type.includes('enabled')) {
                badgeClass = 'badge-success';
            }

            // SECURITY: Escape all user-controlled data to prevent XSS
            const safeUsername = escapeHtml(log.username || 'N/A');
            const safeIpAddress = escapeHtml(log.ip_address);
            const safeEventType = escapeHtml(log.event_type);
            const safeDetails = escapeHtml(details);
            const safeDetailsPreview = escapeHtml(details.substring(0, 50)) + (details.length > 50 ? '...' : '');

            tableHTML += `
                <tr>
                    <td>${timestamp}</td>
                    <td><span class="badge ${badgeClass}">${safeEventType}</span></td>
                    <td>${safeUsername}</td>
                    <td>${safeIpAddress}</td>
                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${safeDetails}">${safeDetailsPreview}</td>
                </tr>
            `;
        });

        tableHTML += '</tbody></table>';
        container.innerHTML = tableHTML;
    } catch (error) {
        console.error('Error loading audit logs:', error);
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to load audit logs</p>';
    }
}

/**
 * Load failed login attempts
 */
async function loadFailedLogins() {
    const container = document.getElementById('failed-logins-container');
    if (!container) return;

    container.innerHTML = '<p class="loading-state">Loading failed login attempts...</p>';

    try {
        const response = await apiFetch('/api/admin/failed-logins?limit=50');
        if (!response.ok) {
            throw new Error('Failed to load failed logins');
        }

        const data = await response.json();

        if (data.failed_attempts.length === 0) {
            container.innerHTML = '<p class="empty-state">No failed login attempts found</p>';
            return;
        }

        let tableHTML = `
            <table class="users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Attempt Time</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;

        data.failed_attempts.forEach(attempt => {
            const timestamp = new Date(attempt.attempt_time).toLocaleString();
            const statusBadge = attempt.is_locked
                ? '<span class="badge badge-danger">Locked</span>'
                : '<span class="badge badge-secondary">Failed</span>';

            // SECURITY: Escape user-controlled data to prevent XSS
            const safeUsername = escapeHtml(attempt.username);
            const safeIpAddress = escapeHtml(attempt.ip_address);

            tableHTML += `
                <tr>
                    <td><strong>${safeUsername}</strong></td>
                    <td>${safeIpAddress}</td>
                    <td>${timestamp}</td>
                    <td>${statusBadge}</td>
                </tr>
            `;
        });

        tableHTML += '</tbody></table>';
        container.innerHTML = tableHTML;
    } catch (error) {
        console.error('Error loading failed logins:', error);
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to load failed login attempts</p>';
    }
}

/**
 * Load active sessions
 */
async function loadActiveSessions() {
    const container = document.getElementById('sessions-container');
    if (!container) return;

    container.innerHTML = '<p class="loading-state">Loading active sessions...</p>';

    try {
        const response = await apiFetch('/api/admin/sessions');
        if (!response.ok) {
            throw new Error('Failed to load sessions');
        }

        const data = await response.json();

        if (data.sessions.length === 0) {
            container.innerHTML = '<p class="empty-state">No active sessions found</p>';
            return;
        }

        let tableHTML = `
            <p style="color: var(--text-muted); margin-bottom: 1rem; font-style: italic;">${data.note}</p>
            <table class="users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>IP Address</th>
                        <th>Login Time</th>
                        <th>User Agent</th>
                    </tr>
                </thead>
                <tbody>
        `;

        data.sessions.forEach(session => {
            const timestamp = new Date(session.login_time).toLocaleString();
            const roleBadge = session.is_admin
                ? '<span class="badge badge-primary">Admin</span>'
                : '<span class="badge badge-secondary">User</span>';

            // SECURITY: Escape user-controlled data to prevent XSS
            const safeUsername = escapeHtml(session.username);
            const safeIpAddress = escapeHtml(session.ip_address);
            const safeUserAgent = escapeHtml(session.user_agent || 'N/A');

            tableHTML += `
                <tr>
                    <td><strong>${safeUsername}</strong></td>
                    <td>${roleBadge}</td>
                    <td>${safeIpAddress}</td>
                    <td>${timestamp}</td>
                    <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${safeUserAgent}">${safeUserAgent}</td>
                </tr>
            `;
        });

        tableHTML += '</tbody></table>';
        container.innerHTML = tableHTML;
    } catch (error) {
        console.error('Error loading sessions:', error);
        container.innerHTML = '<p class="empty-state" style="color: var(--danger);">Failed to load active sessions</p>';
    }
}

// ============================================
// ADMIN SETTINGS MANAGEMENT
// ============================================

// Global settings state
let currentAdminSettings = null;

/**
 * Load admin settings from API
 */
async function loadAdminSettings() {
    try {
        const response = await apiFetch('/api/admin/settings');
        if (!response.ok) {
            throw new Error('Failed to load admin settings');
        }

        currentAdminSettings = await response.json();

        // Initialize client-side debug flag from admin settings
        try {
            if (currentAdminSettings && currentAdminSettings.security && typeof currentAdminSettings.security.debug_logs !== 'undefined') {
                DEBUG_LOGS = !!currentAdminSettings.security.debug_logs;
                debugLog('DEBUG_LOGS set to', DEBUG_LOGS);
            }
        } catch (e) {
            console.error('Failed to initialize DEBUG_LOGS from admin settings:', e);
        }

        // Load security config tab if visible
        const securityConfigForm = document.getElementById('security-config-form');
        if (securityConfigForm) {
            loadSecurityConfigForm();
        }

        return currentAdminSettings;
    } catch (error) {
        console.error('Error loading admin settings:', error);
        showToast('Failed to load admin settings', 'error');
        return null;
    }
}

/**
 * Load Security Config form with current settings
 */
function loadSecurityConfigForm() {
    if (!currentAdminSettings) return;

    // Load proxy settings
    const isBehindProxy = document.getElementById('is-behind-proxy');
    if (isBehindProxy) {
        isBehindProxy.checked = currentAdminSettings.proxy.is_behind_proxy;
        toggleProxySettings();
    }

    const proxyHeader = document.getElementById('proxy-header');
    if (proxyHeader) {
        proxyHeader.value = currentAdminSettings.proxy.proxy_header;
    }

    // Render trusted proxies list
    renderTrustedProxiesList(currentAdminSettings.proxy.trusted_proxies);

    // Load CORS settings
    const corsEnabled = document.getElementById('cors-enabled');
    if (corsEnabled) {
        corsEnabled.checked = currentAdminSettings.cors.enabled;
        toggleCorsSettings();
    }

    // Render allowed origins list
    renderAllowedOriginsList(currentAdminSettings.cors.allowed_origins);

    // Load rate limiting settings
    const rateLimitingEnabled = document.getElementById('rate-limiting-enabled');
    if (rateLimitingEnabled) {
        rateLimitingEnabled.checked = currentAdminSettings.rate_limiting.enabled;
        toggleRateLimitingSettings();
    }

    const rateLimitMaxRequests = document.getElementById('rate-limit-max-requests');
    if (rateLimitMaxRequests) {
        rateLimitMaxRequests.value = currentAdminSettings.rate_limiting.max_requests_per_window;
    }

    const rateLimitWindow = document.getElementById('rate-limit-window');
    if (rateLimitWindow) {
        rateLimitWindow.value = currentAdminSettings.rate_limiting.window_seconds;
    }
}

/**
 * Load App Config form with current settings
 */
async function loadAppConfigForm() {
    if (!currentAdminSettings) {
        console.warn('loadAppConfigForm: currentAdminSettings is not loaded');
        return;
    }

    console.log('Loading App Config form with settings:', currentAdminSettings.security);

    // Load security settings
    const allowYtdlpUpdate = document.getElementById('allow-ytdlp-update');
    if (allowYtdlpUpdate) {
        allowYtdlpUpdate.checked = currentAdminSettings.security.allow_ytdlp_update;
        console.log('Set allow_ytdlp_update checkbox to:', currentAdminSettings.security.allow_ytdlp_update);
    } else {
        console.warn('allow-ytdlp-update element not found');
    }

    const debugProxyHeaders = document.getElementById('debug-proxy-headers');
    if (debugProxyHeaders) {
        debugProxyHeaders.checked = currentAdminSettings.security.debug_proxy_headers;
        console.log('Set debug_proxy_headers checkbox to:', currentAdminSettings.security.debug_proxy_headers);
    } else {
        console.warn('debug-proxy-headers element not found');
    }

    const debugLogsCheckbox = document.getElementById('debug-logs');
    if (debugLogsCheckbox) {
        debugLogsCheckbox.checked = !!currentAdminSettings.security.debug_logs;
        debugLog('Set debug_logs checkbox to:', currentAdminSettings.security.debug_logs);
    } else {
        console.warn('debug-logs element not found');
    }

    // Load queue settings from settings.json
    try {
        const response = await apiFetch(`${API_BASE}/api/settings`);
        if (response.ok) {
            const settings = await response.json();
            document.getElementById('max-concurrent').value = settings.max_concurrent_downloads || 2;
            document.getElementById('max-concurrent-conversions').value = settings.max_concurrent_conversions || 1;
            document.getElementById('max-speed').value = settings.max_download_speed || 0;
            document.getElementById('min-disk-space').value = settings.min_disk_space_mb || 1000;
        }
    } catch (error) {
        console.error('Failed to load queue settings:', error);
    }
}

/**
 * Load Authentication form with current settings
 */
function loadAuthenticationForm() {
    if (!currentAdminSettings) return;

    // Load auth enabled
    const authEnabled = document.getElementById('auth-enabled');
    if (authEnabled) {
        authEnabled.checked = currentAdminSettings.auth.enabled;
    }

    // Load JWT settings
    const jwtSessionExpiry = document.getElementById('jwt-session-expiry');
    if (jwtSessionExpiry) {
        jwtSessionExpiry.value = currentAdminSettings.auth.jwt_session_expiry_hours;
    }

    const jwtKeyRotation = document.getElementById('jwt-key-rotation');
    if (jwtKeyRotation) {
        jwtKeyRotation.value = currentAdminSettings.auth.jwt_key_rotation_days;
    }

    // Load account lockout settings
    const failedLoginMax = document.getElementById('failed-login-max');
    if (failedLoginMax) {
        failedLoginMax.value = currentAdminSettings.auth.failed_login_attempts_max;
    }

    const failedLoginLockout = document.getElementById('failed-login-lockout');
    if (failedLoginLockout) {
        failedLoginLockout.value = currentAdminSettings.auth.failed_login_lockout_minutes;
    }

    // Load suspicious IP settings
    const suspiciousIpThreshold = document.getElementById('suspicious-ip-threshold');
    if (suspiciousIpThreshold) {
        suspiciousIpThreshold.value = currentAdminSettings.auth.suspicious_ip_threshold;
    }

    const suspiciousIpWindow = document.getElementById('suspicious-ip-window');
    if (suspiciousIpWindow) {
        suspiciousIpWindow.value = currentAdminSettings.auth.suspicious_ip_window_hours;
    }
}

// =================
// OIDC Configuration Functions
// =================

/**
 * Load OIDC configuration
 */
async function loadOIDCConfig() {
    try {
        console.log('Loading OIDC configuration...');
        const response = await apiFetch('/api/admin/oidc/config');

        if (!response.ok) {
            throw new Error(`Failed to load OIDC config: ${response.status}`);
        }

        const data = await response.json();
        console.log('OIDC config loaded:', data);
        const config = data.oidc;

        // Populate OIDC form fields
        document.getElementById('oidc-enabled').checked = config.enabled;
        document.getElementById('oidc-provider-name').value = config.provider_name;
        document.getElementById('oidc-discovery-url').value = config.discovery_url;
        document.getElementById('oidc-logout-url').value = config.logout_url || '';
        document.getElementById('oidc-userinfo-url').value = config.userinfo_url || '';
        document.getElementById('oidc-client-id').value = config.client_id;
        document.getElementById('oidc-client-secret').value = config.client_secret;
        document.getElementById('oidc-button-text').value = config.button_text;
        document.getElementById('oidc-admin-claim').value = config.admin_group_claim;
        document.getElementById('oidc-admin-value').value = config.admin_group_value;
        document.getElementById('oidc-use-pkce').checked = config.use_pkce;
        document.getElementById('oidc-auto-create').checked = config.auto_create_users;
        document.getElementById('oidc-username-claim').value = config.username_claim;
        document.getElementById('oidc-email-claim').value = config.email_claim;

        // Setup PKCE toggle handler for dynamic Client Secret requirement
        const pkceToggle = document.getElementById('oidc-use-pkce');
        if (pkceToggle) {
            // Set initial state
            updateClientSecretRequirement(pkceToggle.checked);

            // Add change listener
            pkceToggle.addEventListener('change', (e) => {
                updateClientSecretRequirement(e.target.checked);
            });
        }

        // Setup form submission handler
        const form = document.getElementById('oidc-config-form');
        if (form) {
            // Remove existing listener if any
            const newForm = form.cloneNode(true);
            form.parentNode.replaceChild(newForm, form);

            newForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await saveOIDCConfig();
            });
        }

    } catch (error) {
        console.error('Failed to load OIDC configuration:', error);
        showToast('Failed to load OIDC configuration', 'error');
    }
}

/**
 * Update Client Secret field requirement based on PKCE setting
 */
function updateClientSecretRequirement(pkceEnabled) {
    const clientSecretInput = document.getElementById('oidc-client-secret');
    const requiredIndicator = document.getElementById('oidc-secret-required-indicator');
    const helpText = document.getElementById('oidc-secret-help');

    if (pkceEnabled) {
        // PKCE enabled - Client Secret is optional
        if (clientSecretInput) clientSecretInput.removeAttribute('required');
        if (requiredIndicator) requiredIndicator.style.display = 'none';
        if (helpText) helpText.textContent = 'OAuth client secret (optional when PKCE is enabled)';
    } else {
        // PKCE disabled - Client Secret is required
        if (clientSecretInput) clientSecretInput.setAttribute('required', 'required');
        if (requiredIndicator) requiredIndicator.style.display = 'inline';
        if (helpText) helpText.textContent = 'OAuth client secret (required when PKCE is disabled)';
    }
}

/**
 * Save OIDC configuration
 */
async function saveOIDCConfig() {
    try {
        console.log('=== Starting OIDC Config Save ===');

        const config = {
            oidc: {
                enabled: document.getElementById('oidc-enabled').checked,
                provider_name: document.getElementById('oidc-provider-name').value,
                discovery_url: document.getElementById('oidc-discovery-url').value,
                logout_url: document.getElementById('oidc-logout-url').value,
                userinfo_url: document.getElementById('oidc-userinfo-url').value,
                client_id: document.getElementById('oidc-client-id').value,
                client_secret: document.getElementById('oidc-client-secret').value,
                button_text: document.getElementById('oidc-button-text').value,
                admin_group_claim: document.getElementById('oidc-admin-claim').value,
                admin_group_value: document.getElementById('oidc-admin-value').value,
                use_pkce: document.getElementById('oidc-use-pkce').checked,
                auto_create_users: document.getElementById('oidc-auto-create').checked,
                username_claim: document.getElementById('oidc-username-claim').value,
                email_claim: document.getElementById('oidc-email-claim').value,
                scopes: ["openid", "profile", "email"]
            }
        };

        console.log('Config to save:', JSON.stringify(config, null, 2));

        console.log('Making API request to /api/admin/oidc/config/update');
        const response = await apiFetch('/api/admin/oidc/config/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
            console.error('Error response:', errorData);
            throw new Error(errorData.detail || 'Failed to save configuration');
        }

        const result = await response.json();
        console.log('Save successful! Result:', result);

        showToast('OIDC configuration saved successfully!', 'success');

        // Reload the config to verify it saved
        console.log('Reloading config to verify save...');
        await loadOIDCConfig();

    } catch (error) {
        console.error('=== OIDC Config Save Failed ===');
        console.error('Error:', error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        showToast('Failed to save OIDC configuration: ' + (error.message || 'Unknown error'), 'error');
    }
}


/**
 * Render trusted proxies list
 */
function renderTrustedProxiesList(proxies) {
    const container = document.getElementById('trusted-proxies-list');
    if (!container) return;

    if (proxies.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted); padding: 0.5rem; text-align: center;">No trusted proxies configured</p>';
        return;
    }

    let html = '';
    proxies.forEach(proxy => {
        html += `
            <div class="list-item">
                <span class="list-item-text">${proxy}</span>
                <button type="button" class="list-item-remove" data-proxy="${proxy}" title="Remove">✕</button>
            </div>
        `;
    });

    container.innerHTML = html;

    // Add event listeners to remove buttons
    container.querySelectorAll('.list-item-remove').forEach(btn => {
        btn.addEventListener('click', () => {
            const proxy = btn.dataset.proxy;
            removeTrustedProxy(proxy);
        });
    });
}

/**
 * Render allowed origins list
 */
function renderAllowedOriginsList(origins) {
    const container = document.getElementById('allowed-origins-list');
    if (!container) return;

    if (origins.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted); padding: 0.5rem; text-align: center;">No origins configured</p>';
        return;
    }

    let html = '';
    origins.forEach(origin => {
        html += `
            <div class="list-item">
                <span class="list-item-text">${origin}</span>
                <button type="button" class="list-item-remove" data-origin="${origin}" title="Remove">✕</button>
            </div>
        `;
    });

    container.innerHTML = html;

    // Add event listeners to remove buttons
    container.querySelectorAll('.list-item-remove').forEach(btn => {
        btn.addEventListener('click', () => {
            const origin = btn.dataset.origin;
            removeAllowedOrigin(origin);
        });
    });
}

/**
 * Add trusted proxy IP
 */
function addTrustedProxy() {
    const input = document.getElementById('new-proxy-ip');
    if (!input) return;

    const proxy = input.value.trim();
    if (!proxy) {
        showToast('Please enter a proxy IP or CIDR', 'error');
        return;
    }

    // Basic validation for IP or CIDR
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (!ipRegex.test(proxy)) {
        showToast('Invalid IP or CIDR format (e.g., 192.168.1.1 or 10.0.0.0/8)', 'error');
        return;
    }

    // Check if already exists
    if (currentAdminSettings.proxy.trusted_proxies.includes(proxy)) {
        showToast('This proxy is already in the list', 'error');
        return;
    }

    // Add to settings
    currentAdminSettings.proxy.trusted_proxies.push(proxy);
    renderTrustedProxiesList(currentAdminSettings.proxy.trusted_proxies);
    input.value = '';
}

/**
 * Remove trusted proxy IP
 */
function removeTrustedProxy(proxy) {
    if (!confirm(`Remove ${proxy} from trusted proxies?`)) return;

    currentAdminSettings.proxy.trusted_proxies = currentAdminSettings.proxy.trusted_proxies.filter(p => p !== proxy);
    renderTrustedProxiesList(currentAdminSettings.proxy.trusted_proxies);
}

/**
 * Add allowed origin
 */
function addAllowedOrigin() {
    const input = document.getElementById('new-origin');
    if (!input) return;

    const origin = input.value.trim();
    if (!origin) {
        showToast('Please enter an origin URL', 'error');
        return;
    }

    // Basic validation for URL
    if (origin !== '*' && !origin.match(/^https?:\/\/.+/)) {
        showToast('Invalid origin format (e.g., https://example.com or *)', 'error');
        return;
    }

    // Check if already exists
    if (currentAdminSettings.cors.allowed_origins.includes(origin)) {
        showToast('This origin is already in the list', 'error');
        return;
    }

    // Add to settings
    currentAdminSettings.cors.allowed_origins.push(origin);
    renderAllowedOriginsList(currentAdminSettings.cors.allowed_origins);
    input.value = '';
}

/**
 * Remove allowed origin
 */
function removeAllowedOrigin(origin) {
    if (!confirm(`Remove ${origin} from allowed origins?`)) return;

    currentAdminSettings.cors.allowed_origins = currentAdminSettings.cors.allowed_origins.filter(o => o !== origin);
    renderAllowedOriginsList(currentAdminSettings.cors.allowed_origins);
}

/**
 * Toggle proxy settings visibility
 */
function toggleProxySettings() {
    const checkbox = document.getElementById('is-behind-proxy');
    const proxyGroup = document.getElementById('proxy-settings-group');

    if (checkbox && proxyGroup) {
        proxyGroup.style.display = checkbox.checked ? 'block' : 'none';
    }
}

/**
 * Toggle CORS settings visibility
 */
function toggleCorsSettings() {
    const checkbox = document.getElementById('cors-enabled');
    const corsGroup = document.getElementById('cors-settings-group');

    if (checkbox && corsGroup) {
        corsGroup.style.display = checkbox.checked ? 'block' : 'none';
    }
}

/**
 * Toggle rate limiting settings visibility
 */
function toggleRateLimitingSettings() {
    const checkbox = document.getElementById('rate-limiting-enabled');
    const rateLimitGroup = document.getElementById('rate-limiting-settings-group');

    if (checkbox && rateLimitGroup) {
        rateLimitGroup.style.display = checkbox.checked ? 'block' : 'none';
    }
}

/**
 * Save security settings
 */
async function saveSecuritySettings(e) {
    e.preventDefault();

    if (!currentAdminSettings) {
        showToast('Settings not loaded', 'error');
        return;
    }

    // Update settings from form
    const isBehindProxy = document.getElementById('is-behind-proxy');
    const proxyHeader = document.getElementById('proxy-header');
    const corsEnabled = document.getElementById('cors-enabled');
    const rateLimitingEnabled = document.getElementById('rate-limiting-enabled');
    const rateLimitMaxRequests = document.getElementById('rate-limit-max-requests');
    const rateLimitWindow = document.getElementById('rate-limit-window');

    currentAdminSettings.proxy.is_behind_proxy = isBehindProxy.checked;
    currentAdminSettings.proxy.proxy_header = proxyHeader.value;
    currentAdminSettings.cors.enabled = corsEnabled.checked;
    currentAdminSettings.rate_limiting.enabled = rateLimitingEnabled.checked;
    currentAdminSettings.rate_limiting.max_requests_per_window = parseInt(rateLimitMaxRequests.value);
    currentAdminSettings.rate_limiting.window_seconds = parseInt(rateLimitWindow.value);

    // Validate
    if (currentAdminSettings.proxy.is_behind_proxy) {
        if (currentAdminSettings.proxy.trusted_proxies.length === 0) {
            showToast('Please add at least one trusted proxy IP', 'error');
            return;
        }
    }

    if (currentAdminSettings.cors.enabled) {
        if (currentAdminSettings.cors.allowed_origins.length === 0) {
            showToast('Please add at least one allowed origin', 'error');
            return;
        }
    }

    if (currentAdminSettings.rate_limiting.enabled) {
        if (currentAdminSettings.rate_limiting.max_requests_per_window < 10 || currentAdminSettings.rate_limiting.max_requests_per_window > 1000) {
            showToast('Maximum requests must be between 10 and 1000', 'error');
            return;
        }
        if (currentAdminSettings.rate_limiting.window_seconds < 10 || currentAdminSettings.rate_limiting.window_seconds > 300) {
            showToast('Time window must be between 10 and 300 seconds', 'error');
            return;
        }
    }

    try {
        const response = await apiFetch('/api/admin/settings/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                proxy: currentAdminSettings.proxy,
                cors: currentAdminSettings.cors,
                rate_limiting: currentAdminSettings.rate_limiting
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to save settings');
        }

        const result = await response.json();
        showToast('Security settings saved successfully! Restart the application to apply changes.', 'success');

        // Reload settings to confirm
        await loadAdminSettings();

        // Refresh the form to show the updated values
        loadSecurityConfigForm();
    } catch (error) {
        console.error('Error saving security settings:', error);
        showToast(`Failed to save settings: ${error.message}`, 'error');
    }
}

/**
 * Save app config settings
 */
async function saveAppConfigSettings(e) {
    e.preventDefault();

    if (!currentAdminSettings) {
        showToast('Settings not loaded', 'error');
        return;
    }

    // Update settings from form
    const allowYtdlpUpdate = document.getElementById('allow-ytdlp-update');
    const debugProxyHeaders = document.getElementById('debug-proxy-headers');

    currentAdminSettings.security.allow_ytdlp_update = allowYtdlpUpdate.checked;
    currentAdminSettings.security.debug_proxy_headers = debugProxyHeaders.checked;
    const debugLogsCheckbox = document.getElementById('debug-logs');
    if (debugLogsCheckbox) {
        currentAdminSettings.security.debug_logs = debugLogsCheckbox.checked;
    }

    try {
        // Save admin settings (security)
        const response = await apiFetch('/api/admin/settings/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                security: currentAdminSettings.security
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to save settings');
        }

        // Save queue settings (settings.json)
        const queueSettings = {
            max_concurrent_downloads: parseInt(document.getElementById('max-concurrent').value),
            max_concurrent_conversions: parseInt(document.getElementById('max-concurrent-conversions').value),
            max_download_speed: parseInt(document.getElementById('max-speed').value),
            min_disk_space_mb: parseInt(document.getElementById('min-disk-space').value)
        };

        const queueResponse = await apiFetch(`${API_BASE}/api/settings/queue`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(queueSettings)
        });

        if (!queueResponse.ok) {
            const error = await queueResponse.json();
            throw new Error(error.detail || 'Failed to save queue settings');
        }

        showToast('App configuration saved successfully! Restart the application to apply changes.', 'success');

        // Reload settings to confirm
        await loadAdminSettings();

        // Refresh the form to show the updated values
        await loadAppConfigForm();
    } catch (error) {
        console.error('Error saving app config settings:', error);
        showToast(`Failed to save settings: ${error.message}`, 'error');
    }
}

/**
 * Save authentication settings
 */
async function saveAuthenticationSettings(e) {
    e.preventDefault();

    if (!currentAdminSettings) {
        showToast('Settings not loaded', 'error');
        return;
    }

    // Update settings from form
    const authEnabled = document.getElementById('auth-enabled');
    const jwtSessionExpiry = document.getElementById('jwt-session-expiry');
    const jwtKeyRotation = document.getElementById('jwt-key-rotation');
    const failedLoginMax = document.getElementById('failed-login-max');
    const failedLoginLockout = document.getElementById('failed-login-lockout');
    const suspiciousIpThreshold = document.getElementById('suspicious-ip-threshold');
    const suspiciousIpWindow = document.getElementById('suspicious-ip-window');

    currentAdminSettings.auth.enabled = authEnabled.checked;
    currentAdminSettings.auth.jwt_session_expiry_hours = parseInt(jwtSessionExpiry.value);
    currentAdminSettings.auth.jwt_key_rotation_days = parseInt(jwtKeyRotation.value);
    currentAdminSettings.auth.failed_login_attempts_max = parseInt(failedLoginMax.value);
    currentAdminSettings.auth.failed_login_lockout_minutes = parseInt(failedLoginLockout.value);
    currentAdminSettings.auth.suspicious_ip_threshold = parseInt(suspiciousIpThreshold.value);
    currentAdminSettings.auth.suspicious_ip_window_hours = parseInt(suspiciousIpWindow.value);

    // Validate ranges
    if (currentAdminSettings.auth.jwt_session_expiry_hours < 1 || currentAdminSettings.auth.jwt_session_expiry_hours > 168) {
        showToast('Session expiry must be between 1 and 168 hours', 'error');
        return;
    }

    if (currentAdminSettings.auth.failed_login_attempts_max < 3 || currentAdminSettings.auth.failed_login_attempts_max > 20) {
        showToast('Failed login attempts must be between 3 and 20', 'error');
        return;
    }

    if (currentAdminSettings.auth.suspicious_ip_threshold < 2 || currentAdminSettings.auth.suspicious_ip_threshold > 10) {
        showToast('Suspicious IP threshold must be between 2 and 10', 'error');
        return;
    }

    try {
        const response = await apiFetch('/api/admin/settings/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                auth: currentAdminSettings.auth
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to save settings');
        }

        const result = await response.json();
        showToast('Authentication settings saved successfully! Restart the application to apply changes.', 'success');

        // Reload settings to confirm
        await loadAdminSettings();

        // Refresh the form to show the updated values
        loadAuthenticationForm();
    } catch (error) {
        console.error('Error saving authentication settings:', error);
        showToast(`Failed to save settings: ${error.message}`, 'error');
    }
}

/**
 * Poll for conversion progress continuously (not just when Tools tab is active)
 * This ensures active conversions are tracked and displayed in real-time
 */
setInterval(async () => {
    await loadConversions();
}, 5000);

// Event Listeners
document.addEventListener('DOMContentLoaded', async () => {
    // Check authentication first
    await checkAuth();

    // Load domain mappings first
    await loadDomainMappings();

    // Initialize preferences first
    initPreferences();

    // Load admin settings early so forms and tabs are populated on startup
    await loadAdminSettings();

    // Initialize tabs
    initTabs();

    // Load data for the initially active tab
    const activeTab = document.querySelector('.tab-button.active');
    if (activeTab) {
        const targetTab = activeTab.dataset.tab;
        if (targetTab === 'settings') {
            loadVersionInfo();
            loadHardwareInfo();
            loadCookieFilesSettings();
        } else if (targetTab === 'files') {
            loadFiles();
        } else if (targetTab === 'tools') {
            loadToolsTab();
        } else if (targetTab === 'admin-settings') {
            loadAdminSettingsTab();
        } else if (targetTab === 'logs') {
            filterLogs();
        }
    }

    // Download form submission
    document.getElementById('new-download-form').addEventListener('submit', submitDownload);

    // Video upload form submission
    document.getElementById('video-upload-form').addEventListener('submit', submitVideoUpload);

    // Initialize drag and drop for video upload
    initDragAndDrop();

    // URL input for auto-cookie selection
    document.getElementById('video-url').addEventListener('input', handleUrlInput);

    // Settings buttons
    document.getElementById('update-ytdlp-btn').addEventListener('click', updateYtdlp);
    document.getElementById('refresh-hardware-btn').addEventListener('click', refreshHardwareInfo);
    document.getElementById('clear-cache-btn').addEventListener('click', clearYtdlpCache);

    // Help modal
    document.getElementById('help-modal-btn').addEventListener('click', openHelpModal);
    document.getElementById('help-modal-close').addEventListener('click', closeHelpModal);

    // Logout button
    document.getElementById('logout-btn').addEventListener('click', async () => {
        if (confirm('Are you sure you want to logout?')) {
            await AUTH.logout();
        }
    });

    // User Management Event Listeners
    const createUserBtn = document.getElementById('create-user-btn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', openCreateUserModal);
    }

    const userForm = document.getElementById('user-form');
    if (userForm) {
        userForm.addEventListener('submit', handleUserFormSubmit);
    }

    const userFormCancel = document.getElementById('user-form-cancel');
    if (userFormCancel) {
        userFormCancel.addEventListener('click', closeUserModal);
    }

    const userModalClose = document.getElementById('user-modal-close');
    if (userModalClose) {
        userModalClose.addEventListener('click', closeUserModal);
    }

    const deleteUserCancel = document.getElementById('delete-user-cancel');
    if (deleteUserCancel) {
        deleteUserCancel.addEventListener('click', closeDeleteUserModal);
    }

    const deleteUserModalClose = document.getElementById('delete-user-modal-close');
    if (deleteUserModalClose) {
        deleteUserModalClose.addEventListener('click', closeDeleteUserModal);
    }

    const deleteUserConfirm = document.getElementById('delete-user-confirm');
    if (deleteUserConfirm) {
        deleteUserConfirm.addEventListener('click', handleDeleteUser);
    }

    // Delegate edit/delete button clicks (for dynamically created buttons)
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('edit-user-btn')) {
            const userId = e.target.dataset.userId;
            openEditUserModal(userId);
        }

        if (e.target.classList.contains('delete-user-btn')) {
            const userId = e.target.dataset.userId;
            openDeleteUserModal(userId);
        }
    });

    // Close modals on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const userModal = document.getElementById('user-modal');
            const deleteModal = document.getElementById('delete-user-modal');

            if (userModal && userModal.style.display === 'flex') {
                closeUserModal();
            }
            if (deleteModal && deleteModal.style.display === 'flex') {
                closeDeleteUserModal();
            }
        }
    });

    // Close modals when clicking outside
    const userModal = document.getElementById('user-modal');
    if (userModal) {
        userModal.addEventListener('click', (e) => {
            if (e.target.id === 'user-modal') {
                closeUserModal();
            }
        });
    }

    const deleteUserModal = document.getElementById('delete-user-modal');
    if (deleteUserModal) {
        deleteUserModal.addEventListener('click', (e) => {
            if (e.target.id === 'delete-user-modal') {
                closeDeleteUserModal();
            }
        });
    }

    // Database management buttons
    const databaseBackupBtn = document.getElementById('database-backup-btn');
    if (databaseBackupBtn) {
        databaseBackupBtn.addEventListener('click', handleDatabaseBackup);
    }

    const databaseVacuumBtn = document.getElementById('database-vacuum-btn');
    if (databaseVacuumBtn) {
        databaseVacuumBtn.addEventListener('click', handleDatabaseVacuum);
    }

    const databaseOptimizeBtn = document.getElementById('database-optimize-btn');
    if (databaseOptimizeBtn) {
        databaseOptimizeBtn.addEventListener('click', handleDatabaseOptimize);
    }

    const databaseIntegrityBtn = document.getElementById('database-integrity-btn');
    if (databaseIntegrityBtn) {
        databaseIntegrityBtn.addEventListener('click', handleDatabaseIntegrityCheck);
    }

    const loadBackupsBtn = document.getElementById('load-backups-btn');
    if (loadBackupsBtn) {
        loadBackupsBtn.addEventListener('click', loadBackups);
    }

    const restoreBackupBtn = document.getElementById('restore-backup-btn');
    if (restoreBackupBtn) {
        restoreBackupBtn.addEventListener('click', handleRestoreBackup);
    }

    // Audit log filter and refresh buttons
    const auditLogFilter = document.getElementById('audit-log-filter');
    if (auditLogFilter) {
        auditLogFilter.addEventListener('change', (e) => {
            const filterValue = e.target.value;
            loadAuditLogs(filterValue || null);
        });
    }

    const auditLogRefreshBtn = document.getElementById('audit-log-refresh-btn');
    if (auditLogRefreshBtn) {
        auditLogRefreshBtn.addEventListener('click', () => {
            const filterValue = auditLogFilter ? auditLogFilter.value : '';
            loadAuditLogs(filterValue || null);
        });
    }

    // Admin Settings - App Config
    const appConfigForm = document.getElementById('app-config-form');
    if (appConfigForm) {
        appConfigForm.addEventListener('submit', saveAppConfigSettings);
    }

    // Admin Settings - Authentication
    const authenticationForm = document.getElementById('authentication-form');
    if (authenticationForm) {
        authenticationForm.addEventListener('submit', saveAuthenticationSettings);
    }

    // Admin Settings - Security Config
    const securityConfigForm = document.getElementById('security-config-form');
    if (securityConfigForm) {
        securityConfigForm.addEventListener('submit', saveSecuritySettings);
    }

    const isBehindProxyCheckbox = document.getElementById('is-behind-proxy');
    if (isBehindProxyCheckbox) {
        isBehindProxyCheckbox.addEventListener('change', toggleProxySettings);
    }

    const corsEnabledCheckbox = document.getElementById('cors-enabled');
    if (corsEnabledCheckbox) {
        corsEnabledCheckbox.addEventListener('change', toggleCorsSettings);
    }

    const rateLimitingEnabledCheckbox = document.getElementById('rate-limiting-enabled');
    if (rateLimitingEnabledCheckbox) {
        rateLimitingEnabledCheckbox.addEventListener('change', toggleRateLimitingSettings);
    }

    const addProxyIpBtn = document.getElementById('add-proxy-ip-btn');
    if (addProxyIpBtn) {
        addProxyIpBtn.addEventListener('click', addTrustedProxy);
    }

    const addOriginBtn = document.getElementById('add-origin-btn');
    if (addOriginBtn) {
        addOriginBtn.addEventListener('click', addAllowedOrigin);
    }

    // Allow adding proxy/origin with Enter key
    const newProxyIpInput = document.getElementById('new-proxy-ip');
    if (newProxyIpInput) {
        newProxyIpInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                addTrustedProxy();
            }
        });
    }

    const newOriginInput = document.getElementById('new-origin');
    if (newOriginInput) {
        newOriginInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                addAllowedOrigin();
            }
        });
    }

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
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogsDisplay);
    initializeLogControls();  // Initialize log type selector for admins

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
    console.log('🚀 INITIALIZING LOGS SYSTEM (HTTP Polling)');
    console.log('🌐 API Base:', API_BASE);
    startLogsPolling();

    // Auto-refresh downloads every 10 seconds
    setInterval(loadDownloads, 10000);
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    activeWebSockets.forEach(ws => ws.close());
    stopLogsPolling();
});
