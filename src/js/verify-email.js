// DOM Elements
const verifyForm = document.getElementById('verify-form');
const verifyError = document.getElementById('verify-error');
const resendButton = document.getElementById('resend-button');

// Get user ID from session storage
const userId = sessionStorage.getItem('pendingVerificationUserId');

// Session states
const SessionState = {
  NOT_AUTHENTICATED: 'not_authenticated',
  VERIFYING: 'verifying',
  AUTHENTICATED: 'authenticated',
  SESSION_ERROR: 'session_error'
};

let currentSessionState = SessionState.NOT_AUTHENTICATED;

// Update session state
function updateSessionState(newState) {
  currentSessionState = newState;
  console.log(`Session state changed to: ${newState}`);
  
  // Update UI based on state
  switch (newState) {
    case SessionState.NOT_AUTHENTICATED:
      verifyForm.querySelector('button[type="submit"]').disabled = false;
      break;
    case SessionState.VERIFYING:
      verifyForm.querySelector('button[type="submit"]').disabled = true;
      break;
    case SessionState.AUTHENTICATED:
      // Clear session storage
      sessionStorage.removeItem('pendingVerificationUserId');
      window.location.href = 'dashboard.html';
      break;
    case SessionState.SESSION_ERROR:
      verifyError.textContent = 'An error occurred. Please try again.';
      verifyForm.querySelector('button[type="submit"]').disabled = false;
      break;
  }
}

// Redirect to login if no pending verification
if (!userId) {
  window.location.href = 'login.html';
}

// Handle verification form submission
verifyForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  verifyError.textContent = '';
  
  const verificationCode = document.getElementById('verification-code').value.trim();
  
  try {
    updateSessionState(SessionState.VERIFYING);
    
    const response = await window.api.verify2FA({
      userId,
      otp: verificationCode
    });
    
    if (response.success) {
      // Store tokens
      window.api.setAccessToken(response.accessToken);
      window.api.setRefreshToken(response.refreshToken);
      updateSessionState(SessionState.AUTHENTICATED);
    } else {
      verifyError.textContent = response.error || 'Invalid verification code';
      document.getElementById('verification-code').value = '';
      updateSessionState(SessionState.NOT_AUTHENTICATED);
    }
  } catch (error) {
    console.error('Verification error:', error);
    verifyError.textContent = 'An error occurred during verification. Please try again.';
    document.getElementById('verification-code').value = '';
    updateSessionState(SessionState.SESSION_ERROR);
  }
});

// Handle resend button click
resendButton.addEventListener('click', async () => {
  try {
    resendButton.disabled = true;
    const response = await window.api.resend2FA({ userId });
    
    if (response.success) {
      alert('A new verification code has been sent.');
    } else {
      verifyError.textContent = response.error || 'Failed to resend code';
    }
  } catch (error) {
    console.error('Resend error:', error);
    verifyError.textContent = 'An error occurred while resending the code.';
  } finally {
    resendButton.disabled = false;
  }
}); 