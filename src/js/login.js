// DOM Elements
const loginForm = document.getElementById('login-form');
const loginFormContainer = document.getElementById('login-form-container');
const otpForm = document.getElementById('otp-form');
const backupCodeForm = document.getElementById('backup-code-form');
const otpFormContainer = document.getElementById('otp-form-container');
const loginError = document.getElementById('login-error');
const otpError = document.getElementById('otp-error');

// Current user data for OTP verification
let currentUserId = null;

// Session states
const SessionState = {
  NOT_AUTHENTICATED: 'not_authenticated',
  AUTHENTICATING: 'authenticating',
  AWAITING_2FA: 'awaiting_2fa',
  AUTHENTICATED: 'authenticated'
};

let currentSessionState = SessionState.NOT_AUTHENTICATED;

// Update UI based on session state
function updateUI(state) {
  console.log(`Session state changed to: ${state}`);
  currentSessionState = state;
  
  // Hide all forms first
  loginFormContainer.style.display = 'none';
  otpFormContainer.style.display = 'none';
  
  // Clear any previous errors
  loginError.textContent = '';
  otpError.textContent = '';
  
  switch (state) {
    case SessionState.NOT_AUTHENTICATED:
      loginFormContainer.style.display = 'block';
      loginForm.querySelector('button[type="submit"]').disabled = false;
      break;
      
    case SessionState.AUTHENTICATING:
      loginFormContainer.style.display = 'block';
      loginForm.querySelector('button[type="submit"]').disabled = true;
      break;
      
    case SessionState.AWAITING_2FA:
      loginFormContainer.style.display = 'none';
      otpFormContainer.style.display = 'block';
      otpForm.querySelector('button[type="submit"]').disabled = false;
      // Clear the OTP input field
      document.getElementById('otp').value = '';
      break;
      
    case SessionState.AUTHENTICATED:
      window.location.href = 'dashboard.html';
      break;
  }
}

// Attempt to refresh session
async function attemptSessionRefresh() {
  try {
    const refreshToken = window.api.getRefreshToken();
    if (!refreshToken) return false;

    const refreshResult = await window.api.refreshSession(refreshToken);
    if (refreshResult.success) {
      window.api.setAccessToken(refreshResult.accessToken);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Session refresh error:', error);
    return false;
  }
}

// Check for existing session on page load
async function checkExistingSession() {
  const accessToken = window.api.getAccessToken();
  if (!accessToken) {
    updateUI(SessionState.NOT_AUTHENTICATED);
    return;
  }

  try {
    const response = await window.api.verifySession();
    if (response.success) {
      updateUI(SessionState.AUTHENTICATED);
      return;
    }

    // Try to refresh the session if verification failed
    const refreshSuccess = await attemptSessionRefresh();
    if (refreshSuccess) {
      updateUI(SessionState.AUTHENTICATED);
      return;
    }

    // If we get here, session is invalid
    window.api.clearTokens();
    updateUI(SessionState.NOT_AUTHENTICATED);
  } catch (error) {
    console.error('Session verification error:', error);
    window.api.clearTokens();
    updateUI(SessionState.NOT_AUTHENTICATED);
  }
}

// Handle login form submission
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.textContent = '';
  
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  
  if (!email || !password) {
    loginError.textContent = 'Please enter both email and password';
    return;
  }
  
  try {
    console.log('Attempting login...');
    updateUI(SessionState.AUTHENTICATING);
    
    const response = await window.api.login({
      email,
      password
    });
    
    console.log('Login response:', response);
    
    if (response.success) {
      if (response.require2FA) {
        console.log('2FA required, showing OTP form');
        currentUserId = response.userId;
        updateUI(SessionState.AWAITING_2FA);
      } else {
        console.log('No 2FA required, storing tokens');
        // Store tokens and redirect
        window.api.setAccessToken(response.accessToken);
        window.api.setRefreshToken(response.refreshToken);
        updateUI(SessionState.AUTHENTICATED);
      }
    } else {
      console.log('Login failed:', response.error);
      loginError.textContent = response.error || 'Invalid credentials';
      updateUI(SessionState.NOT_AUTHENTICATED);
    }
  } catch (error) {
    console.error('Login error:', error);
    loginError.textContent = 'An error occurred during login. Please try again.';
    updateUI(SessionState.NOT_AUTHENTICATED);
  }
});

// Handle OTP form submission
otpForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  otpError.textContent = '';
  
  const otp = document.getElementById('otp').value.trim();
  
  if (!otp) {
    otpError.textContent = 'Please enter the verification code';
    return;
  }
  
  try {
    const response = await window.api.verify2FA({
      userId: currentUserId,
      otp
    });
    
    if (response.success) {
      // Store tokens and redirect
      window.api.setAccessToken(response.accessToken);
      window.api.setRefreshToken(response.refreshToken);
      updateUI(SessionState.AUTHENTICATED);
    } else {
      otpError.textContent = response.error || 'Invalid verification code';
      document.getElementById('otp').value = '';
    }
  } catch (error) {
    console.error('OTP verification error:', error);
    otpError.textContent = 'An error occurred during verification. Please try again.';
    document.getElementById('otp').value = '';
  }
});

// Handle backup code form submission
backupCodeForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  otpError.textContent = '';
  
  const backupCode = document.getElementById('backup-code').value.trim().toUpperCase();
  
  if (!backupCode) {
    otpError.textContent = 'Please enter a backup code';
    return;
  }
  
  try {
    const response = await window.api.verify2FA({
      userId: currentUserId,
      backupCode
    });
    
    if (response.success) {
      // Store tokens and redirect
      window.api.setAccessToken(response.accessToken);
      window.api.setRefreshToken(response.refreshToken);
      updateUI(SessionState.AUTHENTICATED);
    } else {
      otpError.textContent = response.error || 'Invalid backup code';
      document.getElementById('backup-code').value = '';
    }
  } catch (error) {
    console.error('Backup code verification error:', error);
    otpError.textContent = 'An error occurred during verification. Please try again.';
    document.getElementById('backup-code').value = '';
  }
});

// Add resend OTP functionality
const resendButton = document.getElementById('resend-otp');
if (resendButton) {
  resendButton.addEventListener('click', async () => {
    try {
      const response = await window.api.resend2FA({ userId: currentUserId });
      if (response.success) {
        alert('Verification code has been resent to your email');
      } else {
        alert(response.error || 'Failed to resend verification code');
      }
    } catch (error) {
      console.error('Resend OTP error:', error);
      alert('An error occurred while resending the verification code');
    }
  });
}

// Initialize page
document.addEventListener('DOMContentLoaded', checkExistingSession); 