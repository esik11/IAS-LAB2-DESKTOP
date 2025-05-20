// DOM Elements
const userEmail = document.getElementById('user-email');
const sessionStatus = document.getElementById('session-status');
const sessionId = document.getElementById('session-id');
const lastActivity = document.getElementById('last-activity');
const authenticatedStatus = document.getElementById('authenticated-status');
const debugInfo = document.getElementById('debug-info');
const logoutButton = document.getElementById('logout-button');

// Session management variables
let currentUser = null;
let sessionCheckInterval = null;
let inactivityTimeout = null;
const INACTIVITY_TIMEOUT = 60 * 1000; // 1 minute
const SESSION_CHECK_INTERVAL = 30000; // 30 seconds - Checking more frequently

// Update debug information
async function updateDebugInfo() {
  try {
    const accessToken = window.api.getAccessToken();
    // First verify the session
    const response = await window.api.verifySession();
    
    if (response.success) {
      currentUser = response.user;
      
      // Then get detailed user info including session data
      const userInfo = await window.api.getCurrentUser();
      
      if (userInfo.success) {
        // Format the lastActivity date if it exists
        const lastActivityFormatted = userInfo.session && userInfo.session.lastActivity 
          ? new Date(userInfo.session.lastActivity).toLocaleString() 
          : 'N/A';
        
        debugInfo.innerHTML = `
          <h2>Debug Information</h2>
          <div class="debug-section">
            <p><strong>Session Status:</strong> <span class="status-active">Active</span></p>
            <p><strong>Session ID:</strong> ${userInfo.session ? userInfo.session.sessionId : 'N/A'}</p>
            <p><strong>Authenticated:</strong> Yes</p>
            <p><strong>User Email:</strong> ${currentUser.email || 'N/A'}</p>
            <p><strong>Last Activity:</strong> ${lastActivityFormatted}</p>
            <p><strong>Session Expires:</strong> ${userInfo.session && userInfo.session.accessTokenExpiresAt ? new Date(userInfo.session.accessTokenExpiresAt).toLocaleString() : 'N/A'}</p>
          </div>
        `;
      } else {
        debugInfo.innerHTML = `
          <h2>Debug Information</h2>
          <div class="debug-section">
            <p><strong>Session Status:</strong> <span class="status-active">Active</span></p>
            <p><strong>Session ID:</strong> ${response.sessionId || 'N/A'}</p>
            <p><strong>Authenticated:</strong> Yes</p>
            <p><strong>User Email:</strong> ${currentUser.email || 'N/A'}</p>
            <p><strong>Last Activity:</strong> N/A</p>
          </div>
        `;
      }
    } else {
      debugInfo.innerHTML = `
        <h2>Debug Information</h2>
        <div class="debug-section">
          <p><strong>Session Status:</strong> <span class="status-inactive">Inactive</span></p>
          <p><strong>Error:</strong> ${response.error || 'Session verification failed'}</p>
        </div>
      `;
      // Redirect to login if session is invalid
      await handleLogout();
    }
  } catch (error) {
    console.error('Error updating debug info:', error);
    debugInfo.innerHTML = `
      <h2>Debug Information</h2>
      <div class="debug-section">
        <p><strong>Session Status:</strong> <span class="status-error">Error</span></p>
        <p><strong>Error:</strong> ${error.message}</p>
      </div>
    `;
    await handleLogout();
  }
}

// Reset inactivity timer
function resetInactivityTimer() {
  if (inactivityTimeout) {
    clearTimeout(inactivityTimeout);
  }
  inactivityTimeout = setTimeout(async () => {
    console.log('Session expired due to inactivity');
    await handleLogout();
  }, INACTIVITY_TIMEOUT);
}

// Handle user activity
function handleUserActivity() {
  resetInactivityTimer();
}

// Handle logout
async function handleLogout() {
  try {
    await window.api.logout();
    window.location.href = 'login.html';
  } catch (error) {
    console.error('Logout error:', error);
    // Force redirect to login even if logout fails
    window.location.href = 'login.html';
  }
}

// Initialize dashboard
async function initializeDashboard() {
  try {
    // Set up activity monitoring for all relevant events
    ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'].forEach(eventType => {
      document.addEventListener(eventType, handleUserActivity);
    });
    
    // Initial debug info update
    await updateDebugInfo();
    
    // Set up periodic session check
    sessionCheckInterval = setInterval(async () => {
      await updateDebugInfo();
    }, SESSION_CHECK_INTERVAL);
    
    // Set up initial inactivity timer
    resetInactivityTimer();
    
    // Set up logout button
    if (logoutButton) {
      logoutButton.addEventListener('click', handleLogout);
    }

    // Handle page visibility changes
    document.addEventListener('visibilitychange', async () => {
      if (document.visibilityState === 'visible') {
        await updateDebugInfo();
        resetInactivityTimer();
      }
    });
  } catch (error) {
    console.error('Dashboard initialization error:', error);
    debugInfo.innerHTML = `
      <h2>Debug Information</h2>
      <div class="debug-section">
        <p><strong>Status:</strong> <span class="status-error">Initialization Error</span></p>
        <p><strong>Error:</strong> ${error.message}</p>
      </div>
    `;
  }
}

// Cleanup function
function cleanup() {
  if (sessionCheckInterval) {
    clearInterval(sessionCheckInterval);
  }
  if (inactivityTimeout) {
    clearTimeout(inactivityTimeout);
  }
  ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'].forEach(eventType => {
    document.removeEventListener(eventType, handleUserActivity);
  });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeDashboard);

// Clean up when page is unloaded
window.addEventListener('beforeunload', cleanup); 