// DOM Elements
const registerForm = document.getElementById('register-form');
const registerError = document.getElementById('register-error');
const registrationFormDiv = document.getElementById('registration-form');
const backupCodesDiv = document.getElementById('backup-codes');
const backupCodesList = document.getElementById('backup-codes-list');
const copyCodesButton = document.getElementById('copy-codes');
const proceedToLoginButton = document.getElementById('proceed-to-login');

// Verify that we have access to the API
if (!window.api) {
    console.error('window.api is not available');
    registerError.textContent = 'Application initialization error. Please refresh the page.';
    if (registerForm) {
        registerForm.querySelector('button[type="submit"]').disabled = true;
    }
}

// Helper function to validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Helper function to validate password strength
function isValidPassword(password) {
    return password.length >= 8 &&
           /[A-Z]/.test(password) &&
           /[0-9]/.test(password) &&
           /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password);
}

// Helper function to display backup codes
function displayBackupCodes(codes) {
    console.log('displayBackupCodes called with:', codes);
    
    if (!codes || !Array.isArray(codes) || codes.length === 0) {
        console.error('No backup codes provided or invalid format');
        console.error('Codes:', codes);
        console.error('Type:', typeof codes);
        return;
    }

    // Show the backup codes container
    console.log('Showing backup codes container');
    backupCodesDiv.style.display = 'block';
    registrationFormDiv.style.display = 'none';
    
    // Generate the HTML for backup codes
    console.log('Generating backup codes HTML');
    backupCodesList.innerHTML = codes.map(code => 
        `<div class="backup-code">${code}</div>`
    ).join('');
    
    // Log for debugging
    console.log('Backup codes HTML generated:', backupCodesList.innerHTML);
}

// Handle form submission
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    registerError.textContent = '';

    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    // Client-side validation
    if (!name || !email || !password || !confirmPassword) {
        registerError.textContent = 'All fields are required';
        return;
    }

    if (!isValidEmail(email)) {
        registerError.textContent = 'Please enter a valid email address';
        return;
    }

    if (!isValidPassword(password)) {
        registerError.textContent = 'Password must be at least 8 characters long and contain uppercase, number, and special character';
        return;
    }

    if (password !== confirmPassword) {
        registerError.textContent = 'Passwords do not match';
        return;
    }

    try {
        console.log('Attempting registration...');
        const registerButton = registerForm.querySelector('button[type="submit"]');
        registerButton.disabled = true;
        registerButton.textContent = 'Registering...';

        // Register user
        const response = await window.api.register({
            name,
            email,
            password
        });

        console.log('Registration response:', response);

        if (response.success) {
            // Hide registration form first
            registrationFormDiv.style.display = 'none';
            
            // Display backup codes if provided
            if (response.backupCodes && response.backupCodes.length > 0) {
                console.log('Backup codes received:', response.backupCodes);
                displayBackupCodes(response.backupCodes);
            } else {
                console.error('No backup codes in response:', response);
            }
            
            // Show success message with verification info
            backupCodesDiv.style.display = 'block';
            
            // Store user ID for verification if provided
            if (response.userId) {
                console.log('Storing user ID:', response.userId);
                sessionStorage.setItem('pendingVerificationUserId', response.userId);
            }
            
            // Show verification email sent message
            const verificationMessage = document.createElement('p');
            verificationMessage.className = 'verification-message';
            verificationMessage.textContent = response.message || 'A verification email has been sent to your email address. Please check your inbox and verify your email before logging in.';
            backupCodesDiv.insertBefore(verificationMessage, backupCodesDiv.firstChild);

            // Add instructions about email verification
            const verificationInstructions = document.createElement('div');
            verificationInstructions.className = 'verification-instructions';
            verificationInstructions.innerHTML = `
                <p>Important: Please check your email (${email}) for a verification link.</p>
                <p>You must verify your email before you can log in.</p>
                <p>If you don't see the email, please:</p>
                <ul>
                    <li>Check your spam folder</li>
                    <li>Wait a few minutes</li>
                    <li>Click the "Proceed to Login" button and use the "Resend verification email" option if needed</li>
                </ul>
            `;
            backupCodesDiv.insertBefore(verificationInstructions, backupCodesDiv.querySelector('.backup-codes-container'));
        } else {
            registerError.textContent = response.error || 'Registration failed';
            registerButton.disabled = false;
            registerButton.textContent = 'Register';
        }
    } catch (error) {
        console.error('Registration error:', error);
        registerError.textContent = 'An error occurred during registration. Please try again.';
        const registerButton = registerForm.querySelector('button[type="submit"]');
        registerButton.disabled = false;
        registerButton.textContent = 'Register';
    }
});

// Copy backup codes
copyCodesButton.addEventListener('click', () => {
    const codes = Array.from(backupCodesList.querySelectorAll('.backup-code'))
        .map(div => div.textContent)
        .join('\n');
    
    navigator.clipboard.writeText(codes)
        .then(() => {
            copyCodesButton.textContent = 'Copied!';
            setTimeout(() => {
                copyCodesButton.textContent = 'Copy Codes';
            }, 2000);
        })
        .catch(err => {
            console.error('Failed to copy backup codes:', err);
            copyCodesButton.textContent = 'Copy Failed';
            setTimeout(() => {
                copyCodesButton.textContent = 'Copy Codes';
            }, 2000);
        });
});

// Proceed to login
proceedToLoginButton.addEventListener('click', () => {
    window.api.navigateTo('login');
}); 