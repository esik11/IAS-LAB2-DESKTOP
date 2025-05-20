const { ipcMain } = require('electron');
const AuthController = require('../controllers/AuthController');
const User = require('../models/User');
const Session = require('../models/Session');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { auth } = require('../config/firebase');
const { 
  createUserWithEmailAndPassword, 
  sendEmailVerification,
  signInWithEmailAndPassword 
} = require('firebase/auth');
const path = require('path');
const { pool } = require('../config/database');
const otpHelper = require('./otpHelper');
const securityLogger = require('./securityLogger');

// Load environment variables
dotenv.config();

// Set up IPC handlers for authentication
function setupIpcHandlers(mainWindow) {
  if (!mainWindow) {
    throw new Error('mainWindow is required for IPC handler setup');
  }

  // Debug logging
  ipcMain.handle('log', (event, message) => {
    console.log('RENDERER:', message);
  });

  // Register user
  ipcMain.handle('auth:register', async (event, userData) => {
    try {
      console.log('Registration attempt:', { email: userData.email });
      
      if (!userData || !userData.email || !userData.password) {
        console.error('Invalid registration data:', userData);
        return { 
          success: false, 
          error: 'Email and password are required' 
        };
      }

      const { email, password, name } = userData;
      
      // Create user in Firebase first
      console.log('Creating user in Firebase...');
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;
      console.log('Firebase user created:', firebaseUser.uid);

      // Send verification email through Firebase
      console.log('Sending verification email...');
      await sendEmailVerification(firebaseUser);
      console.log('Verification email sent');
      
      // Create user profile in database
      console.log('Creating user profile in database...');
      const user = await User.create({
        name: name || email.split('@')[0],
        email: email,
        password: password,
        firebase_uid: firebaseUser.uid
      });
      console.log('User profile created in database');

      // Generate backup codes
      console.log('Generating backup codes...');
      const backupCodes = await user.generateBackupCodes();
      console.log('Backup codes generated:', backupCodes);
      
      return { 
        success: true, 
        userId: user.id,
        message: 'Registration successful. Please check your email for verification link.',
        backupCodes: backupCodes,
        requireEmailVerification: true
      };
    } catch (error) {
      console.error('Registration error:', error);
      
      // Handle specific Firebase errors
      if (error.code === 'auth/email-already-in-use') {
        return { success: false, error: 'Email is already registered' };
      } else if (error.code === 'auth/invalid-email') {
        return { success: false, error: 'Invalid email format' };
      } else if (error.code === 'auth/weak-password') {
        return { success: false, error: 'Password is too weak' };
      } else if (error.code === 'auth/operation-not-allowed') {
        return { success: false, error: 'Email/password accounts are not enabled. Please contact support.' };
      }
      
      return { 
        success: false, 
        error: error.message || 'Registration failed'
      };
    }
  });

  // Login user
  ipcMain.handle('auth:login', async (event, credentials) => {
    try {
      const { email, password } = credentials;
      console.log('Login attempt:', { email });
      
      // Get IP and user agent for logging
      const ipAddress = '127.0.0.1'; // Default for desktop app
      const userAgent = event.sender.getUserAgent();
      
      // Log login attempt
      await securityLogger.logSecurityEvent({
        userId: null, // Not authenticated yet
        eventType: 'LOGIN_ATTEMPT',
        ipAddress,
        userAgent,
        details: { email }
      });
      
      // First try to authenticate with Firebase
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;
      console.log('Firebase auth successful:', firebaseUser.uid);

      // Check if email is verified
      if (!firebaseUser.emailVerified) {
        console.log('Email not verified, sending verification email');
        await sendEmailVerification(firebaseUser);
        
        // Log verification email sent
        await securityLogger.logSecurityEvent({
          userId: null,
          eventType: 'EMAIL_VERIFICATION_SENT',
          ipAddress,
          userAgent,
          details: { email }
        });
        
        return {
          success: false,
          error: 'Email not verified',
          message: 'Please verify your email first. A new verification email has been sent.',
          requireEmailVerification: true
        };
      }

      // Find user in our database
      const user = await User.findByEmail(email);
      console.log('Database user found:', user ? user.id : 'null');
      
      if (!user) {
        // Log user not found
        await securityLogger.logSecurityEvent({
          userId: null,
          eventType: 'LOGIN_FAILED',
          ipAddress,
          userAgent,
          details: { email, reason: 'User not found in database' }
        });
        
        return { success: false, error: 'User account not found' };
      }

      // Generate and send login OTP for 2FA
      console.log('--- Generating OTP for 2FA login ---');
      const otpResult = await user.generateLoginOTP();
      console.log('OTP generation result:', otpResult);
      
      if (!otpResult.success) {
        console.error('OTP generation failed:', otpResult.error);
        
        // Log OTP generation failure
        await securityLogger.logSecurityEvent({
          userId: user.id,
          eventType: 'OTP_GENERATION_FAILED',
          ipAddress,
          userAgent,
          details: { reason: otpResult.error }
        });
        
        return { success: false, error: 'Failed to send login verification code' };
      }
      
      // Log OTP sent
      await securityLogger.logSecurityEvent({
        userId: user.id,
        eventType: 'OTP_SENT',
        ipAddress,
        userAgent,
        details: { method: 'email' }
      });
      
      console.log('*********************************************');
      console.log('*      LOGIN OTP SENT TO USER EMAIL        *');
      console.log('*                                           *');
      console.log('*********************************************');
      
      return { 
        success: true,
        require2FA: true,
        userId: user.id,
        message: 'A verification code has been sent to your email.'
      };

    } catch (error) {
      console.error('Login error:', error);
      
      // Log login error
      await securityLogger.logSecurityEvent({
        userId: null,
        eventType: 'LOGIN_ERROR',
        ipAddress: '127.0.0.1',
        userAgent: event.sender.getUserAgent(),
        details: { error: error.message, code: error.code }
      });
      
      return { success: false, error: error.message };
    }
  });

  // Verify OTP
  ipcMain.handle('auth:verify-otp', async (event, { userId, otp, isEmailVerification }) => {
    try {
      console.log('Verifying OTP:', { userId, otp, isEmailVerification });
      
      // Get IP and user agent for logging
      const ipAddress = '127.0.0.1'; // Default for desktop app
      const userAgent = event.sender.getUserAgent();
      
      // Validate input
      if (!userId || !otp) {
        console.error('Missing userId or OTP');
        
        // Log validation error
        await securityLogger.logSecurityEvent({
          userId,
          eventType: 'OTP_VERIFICATION_FAILED',
          ipAddress,
          userAgent,
          details: { reason: 'Missing userId or OTP' }
        });
        
        return { success: false, error: 'UserId and OTP are required' };
      }
      
      // Get user from database
      const user = await User.findById(userId);
      if (!user) {
        console.error('User not found:', userId);
        
        // Log user not found
        await securityLogger.logSecurityEvent({
          userId,
          eventType: 'OTP_VERIFICATION_FAILED',
          ipAddress,
          userAgent,
          details: { reason: 'User not found' }
        });
        
        return { success: false, error: 'User not found' };
      }
      
      // Verify OTP from database
      const isValid = await user.verifyOTP(otp);
      
      console.log('OTP verification result:', isValid);
      
      if (!isValid) {
        console.error('Invalid OTP verification attempt');
        
        // Log invalid OTP
        await securityLogger.logSecurityEvent({
          userId: user.id,
          eventType: 'OTP_VERIFICATION_FAILED',
          ipAddress,
          userAgent,
          details: { reason: 'Invalid or expired code' }
        });
        
        return { success: false, error: 'Invalid or expired verification code' };
      }
      
      console.log('OTP verified successfully, creating session...');
      
      // Log successful verification
      await securityLogger.logSecurityEvent({
        userId: user.id,
        eventType: 'OTP_VERIFICATION_SUCCESS',
        ipAddress,
        userAgent
      });
      
      // Create session
      // Use the already declared ipAddress and userAgent variables
      
      // Invalidate previous sessions
      await Session.deleteUserSessions(user.id);
      
      // Create new session
      const session = await Session.create({
        user_id: user.id,
        ipAddress,
        userAgent
      });
      
      console.log('Session created:', {
        userId: user.id,
        sessionId: session.id,
        hasAccessToken: !!session.access_token
      });
      
      // Log successful login
      await securityLogger.logSecurityEvent({
        userId: user.id,
        eventType: 'LOGIN_SUCCESS',
        ipAddress,
        userAgent,
        details: { sessionId: session.id }
      });
      
      return {
        success: true,
        accessToken: session.access_token,
        refreshToken: session.refresh_token,
        expiresAt: session.access_token_expires_at,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      };
    } catch (error) {
      console.error('OTP verification error:', error);
      return { success: false, error: 'An error occurred during verification' };
    }
  });

  // Verify email
  ipcMain.handle('auth:verify-email', async (event, { userId, otp }) => {
    const ipAddress = 'localhost'; // For desktop app
    const userAgent = 'Electron App';
    return await AuthController.verifyOTP(userId, otp, true, ipAddress, userAgent);
  });

  // Resend verification email
  ipcMain.handle('auth:resend-verification', async (event, { userId }) => {
    return await AuthController.resendVerificationOTP(userId);
  });

  // Verify 2FA
  ipcMain.handle('auth:verify-2fa', async (event, { userId, otp }) => {
    try {
      console.log('Verifying 2FA OTP:', { userId, otp });
      
      // Validate input
      if (!userId || !otp) {
        console.error('Missing userId or OTP');
        return { success: false, error: 'UserId and OTP are required' };
      }
      
      // Get user from database
      const user = await User.findById(userId);
      if (!user) {
        console.error('User not found:', userId);
        return { success: false, error: 'User not found' };
      }
      
      // Verify OTP using standalone helper
      const isValid = await otpHelper.verifyOTP(userId, otp);
      
      if (!isValid) {
        console.error('Invalid 2FA OTP verification attempt');
        return { success: false, error: 'Invalid or expired verification code' };
      }
      
      console.log('2FA OTP verified successfully, creating session...');
      
      // Create session
      const userAgent = event.sender.getUserAgent();
      const ipAddress = '127.0.0.1'; // default for desktop app
      
      // Invalidate previous sessions
      await Session.deleteUserSessions(user.id);
      
      // Create new session
      const session = await Session.create({
        user_id: user.id,
        ipAddress,
        userAgent
      });
      
      console.log('Session created:', {
        userId: user.id,
        sessionId: session.id,
        hasAccessToken: !!session.access_token
      });
      
      return {
        success: true,
        accessToken: session.access_token,
        refreshToken: session.refresh_token,
        expiresAt: session.access_token_expires_at,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      };
    } catch (error) {
      console.error('2FA verification error:', error);
      return { success: false, error: 'Error verifying 2FA code' };
    }
  });

  // Resend 2FA OTP
  ipcMain.handle('auth:resend-2fa', async (event, { userId }) => {
    try {
      console.log('Resending 2FA OTP for user:', userId);
      
      // Get user from database
      const user = await User.findById(userId);
      if (!user) {
        console.error('User not found:', userId);
        return { success: false, error: 'User not found' };
      }
      
      // Generate new OTP
      const otpResult = await user.generateLoginOTP();
      console.log('New OTP generation result:', otpResult);
      
      if (!otpResult.success) {
        console.error('OTP generation failed:', otpResult.error);
        return { success: false, error: 'Failed to generate new verification code' };
      }
      
      console.log('*********************************************');
      console.log('*      NEW LOGIN OTP SENT TO USER EMAIL    *');
      console.log('*                                           *');
      console.log('*********************************************');
      
      return { 
        success: true, 
        message: 'A new verification code has been sent to your email.'
      };
    } catch (error) {
      console.error('Error resending 2FA OTP:', error);
      return { success: false, error: 'Failed to resend verification code' };
    }
  });

  // Get user info
  ipcMain.handle('auth:get-user-info', async () => {
    try {
      console.log('Getting current user info');
      const session = await Session.getCurrent();
      if (!session) {
        console.log('No current session for user info');
        return { success: false, error: 'No active session' };
      }
      
      // Get user info from database
      const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [session.user_id]);
      if (users.length === 0) {
        console.log('User not found for session');
        return { success: false, error: 'User not found' };
      }
      
      const user = users[0];
      
      return {
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        },
        session: {
          sessionId: session.id,
          lastActivity: session.updated_at,
          status: session.is_revoked ? 'revoked' : 'active',
          accessTokenExpiresAt: session.access_token_expires_at
        }
      };
    } catch (error) {
      console.error('Get current user error:', error);
      return { success: false, error: error.message };
    }
  });

  // Verify session
  ipcMain.handle('auth:verify-session', async (event) => {
    try {
      console.log('Verifying session...');
      const session = await Session.getCurrent();
      
      const ipAddress = '127.0.0.1'; // Default for desktop app
      const userAgent = event.sender.getUserAgent();
      
      if (!session) {
        console.log('No current session found');
        
        // Log session verification failure
        await securityLogger.logSecurityEvent({
          userId: null,
          eventType: 'SESSION_VERIFICATION_FAILED',
          ipAddress,
          userAgent,
          details: { reason: 'No active session' }
        });
        
        return { success: false, error: 'No active session' };
      }
      
      const isValid = await Session.validate(session.id);
      if (!isValid) {
        console.log('Session is invalid, deleting it');
        
        // Log session expiration
        await securityLogger.logSecurityEvent({
          userId: session.user_id,
          eventType: 'SESSION_EXPIRED',
          ipAddress,
          userAgent,
          details: { sessionId: session.id }
        });
        
        await Session.deleteCurrent();
        return { success: false, error: 'Session expired' };
      }
      
      // Find user from session
      const [userRows] = await pool.query('SELECT * FROM users WHERE id = ?', [session.user_id]);
      
      if (userRows.length === 0) {
        console.log('User not found for session');
        return { success: false, error: 'User not found' };
      }
      
      const user = userRows[0];
      
      // Log session verification success
      await securityLogger.logSecurityEvent({
        userId: user.id,
        eventType: 'SESSION_VERIFICATION_SUCCESS',
        ipAddress,
        userAgent,
        details: { sessionId: session.id }
      });
      
      return { 
        success: true, 
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        },
        sessionId: session.id
      };
    } catch (error) {
      console.error('Session check error:', error);
      return { success: false, error: error.message };
    }
  });

  // Refresh session
  ipcMain.handle('auth:refresh-session', async (event, refreshToken) => {
    try {
      console.log('Refreshing session...');
      const session = await Session.getCurrent();
      if (!session) {
        console.log('No current session to refresh');
        return { success: false, error: 'No active session' };
      }
      
      const refreshResult = await Session.refresh(session.id);
      if (!refreshResult) {
        console.log('Failed to refresh session');
        return { success: false, error: 'Failed to refresh session' };
      }
      
      console.log('Session refreshed successfully');
      return { 
        success: true,
        accessToken: session.access_token,
        expiresAt: session.access_token_expires_at
      };
    } catch (error) {
      console.error('Session refresh error:', error);
      return { success: false, error: error.message };
    }
  });

  // Logout
  ipcMain.handle('auth:logout', async (event) => {
    try {
      const session = await Session.getCurrent();
      const userId = session ? session.user_id : null;
      
      // Get IP and user agent for logging
      const ipAddress = '127.0.0.1'; 
      const userAgent = event.sender.getUserAgent();
      
      await auth.signOut();
      await Session.deleteCurrent();
      
      // Log logout event
      if (userId) {
        await securityLogger.logSecurityEvent({
          userId,
          eventType: 'LOGOUT',
          ipAddress,
          userAgent,
          details: { sessionId: session ? session.id : null }
        });
      }
      
      return { success: true };
    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: error.message };
    }
  });

  // Get user sessions
  ipcMain.handle('auth:get-sessions', async (event, { userId }) => {
    return await AuthController.getUserSessions(userId);
  });
  
  // Terminate other sessions
  ipcMain.handle('auth:terminate-other-sessions', async (event, { userId }) => {
    try {
      const accessToken = await event.sender.executeJavaScript('localStorage.getItem("access_token")');
      if (!accessToken) {
        return { success: false, error: 'No active session' };
      }

      const session = await Session.findByAccessToken(accessToken);
      if (!session) {
        return { success: false, error: 'Current session not found' };
      }

      return await AuthController.terminateOtherSessions(userId, session.session_id);
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  // Enable two-factor authentication
  ipcMain.handle('auth:enable-2fa', async (event, { userId }) => {
    return await AuthController.enableTwoFactor(userId);
  });

  // Email OTP endpoints
  ipcMain.handle('auth:request-email-otp', async (event, { userId }) => {
    return await AuthController.requestEmailOTP(userId);
  });
  
  ipcMain.handle('auth:verify-email-otp', async (event, { userId, otp }) => {
    const ipAddress = 'localhost'; // For desktop app
    const userAgent = 'Electron App';
    return await AuthController.verifyEmailOTP(userId, otp, ipAddress, userAgent);
  });

  // Get current session
  ipcMain.handle('auth:get-current-session', async (event) => {
    try {
      const accessToken = await event.sender.executeJavaScript('localStorage.getItem("access_token")');
      if (!accessToken) {
        return { success: false, error: 'No access token found' };
      }

      const session = await Session.findByAccessToken(accessToken);
      if (!session) {
        return { success: false, error: 'Session not found' };
      }

      return {
        success: true,
        sessionId: session.session_id,
        lastActivity: session.last_activity,
        deviceInfo: session.device_info,
        status: session.status,
        accessTokenExpiresAt: session.access_token_expires_at,
        refreshTokenExpiresAt: session.refresh_token_expires_at
      };
    } catch (error) {
      console.error('Error getting current session:', error);
      return { success: false, error: error.message };
    }
  });

  // Navigation
  ipcMain.handle('navigateTo', (event, page) => {
    mainWindow.loadFile(path.join(__dirname, '..', 'views', `${page}.html`));
  });
}

module.exports = { setupIpcHandlers }; 