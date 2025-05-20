const User = require('../models/User');
const Session = require('../models/Session');
const { auth } = require('../config/firebase');
const jwt = require('jsonwebtoken');
const emailService = require('../utils/emailService');
const { 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  signOut
} = require('firebase/auth');

class AuthController {
  // Register a new user
  static async register(userData) {
    try {
      // Input validation
      if (!userData.email || !userData.password) {
        return { success: false, error: 'Email and password are required' };
      }
      
      // Email format validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(userData.email)) {
        return { success: false, error: 'Invalid email format' };
      }
      
      // Password strength validation
      if (userData.password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters long' };
      }
      
      // Check for password strength
      const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
      if (!passwordRegex.test(userData.password)) {
        return { 
          success: false, 
          error: 'Password must contain at least one uppercase letter, one number, and one special character'
        };
      }
      
      // Check for duplicate email
      const existingUser = await User.findByEmail(userData.email);
      if (existingUser) {
        return { success: false, error: 'Email is already registered' };
      }
      
      // Create user in Firebase Auth
      const userCredential = await createUserWithEmailAndPassword(
        auth, 
        userData.email, 
        userData.password
      );
      
      // Send verification email through Firebase
      await sendEmailVerification(userCredential.user);
      
      // Create user in our database
      const user = await User.create({
        name: userData.name || userData.email.split('@')[0],
        email: userData.email,
        password: userData.password,
        firebase_uid: userCredential.user.uid
      });

      // Generate backup codes
      const backupCodes = await user.generateBackupCodes();
      
      return { 
        success: true, 
        userId: user.id,
        message: 'Verification email has been sent to your email address',
        backupCodes,
        requireEmailVerification: true
      };
    } catch (error) {
      // Handle specific Firebase errors
      if (error.code === 'auth/email-already-in-use') {
        return { success: false, error: 'Email is already registered' };
      } else if (error.code === 'auth/invalid-email') {
        return { success: false, error: 'Invalid email format' };
      } else if (error.code === 'auth/weak-password') {
        return { success: false, error: 'Password is too weak' };
      }
      
      return { success: false, error: error.message };
    }
  }

  // Verify email with token
  static async verifyEmailWithToken(token) {
    try {
      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
      
      // Check if token is for email verification
      if (decoded.type !== 'email_verification') {
        return { success: false, error: 'Invalid verification token' };
      }
      
      // Find user
      const user = await User.findById(decoded.userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }
      
      // Check if email is already verified
      if (user.is_email_verified) {
        return { success: false, error: 'Email is already verified' };
      }
      
      // Mark email as verified
      await user.markEmailAsVerified();
      
      return { 
        success: true,
        message: 'Email verified successfully'
      };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return { success: false, error: 'Verification link has expired' };
      }
      return { success: false, error: 'Invalid verification link' };
    }
  }

  // Login user
  static async login(email, password, ipAddress, userAgent) {
    try {
      console.log('Login attempt:', { email, ipAddress, userAgent });
      
      // First try to authenticate with Firebase
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const firebaseUser = userCredential.user;
      console.log('Firebase auth successful:', firebaseUser.uid);

      // Check if email is verified in Firebase
      if (!firebaseUser.emailVerified) {
        console.log('Email not verified, sending verification email');
        // Send new verification email
        await sendEmailVerification(firebaseUser);
        
        // Log the verification email sent
        await User.logLoginAttempt(email, ipAddress, false, 'Email not verified, verification email sent');
        
        return {
          success: false,
          error: 'Email not verified',
          message: 'A new verification email has been sent to your email address',
          requireEmailVerification: true
        };
      }

      // Find user in our database
      const user = await User.findByEmail(email);
      console.log('Database user found:', user ? user.id : 'null');
      
      if (!user) {
        console.log('User not found in database');
        await User.logLoginAttempt(email, ipAddress, false, 'User not found in database');
        return { success: false, error: 'User account not found' };
      }

      // Check if account is locked
      if (user.isLocked()) {
        const lockTime = new Date(user.locked_until);
        console.log('Account is locked until:', lockTime);
        await User.logLoginAttempt(email, ipAddress, false, `Account locked until ${lockTime.toLocaleString()}`);
        return { 
          success: false, 
          error: `Account is locked. Try again after ${lockTime.toLocaleString()}` 
        };
      }

      // Log successful initial authentication
      await User.logLoginAttempt(email, ipAddress, true, 'Firebase authentication successful, proceeding to 2FA');

      // Generate and send login OTP for 2FA
      console.log('Generating login OTP...');
      const otpResult = await user.generateLoginOTP();
      console.log('OTP generation result:', otpResult);
      
      if (!otpResult.success) {
        console.error('Failed to generate/send OTP:', otpResult.error);
        await User.logLoginAttempt(email, ipAddress, false, 'Failed to generate/send 2FA code');
        return { success: false, error: 'Failed to send login verification code' };
      }
      
      return { 
        success: true,
        require2FA: true,
        userId: user.id,
        message: 'A verification code has been sent to your email'
      };

    } catch (error) {
      console.error('Login error:', error);
      
      // Handle Firebase auth errors
      if (error.code === 'auth/wrong-password' || error.code === 'auth/user-not-found') {
        // Log failed attempt
        await User.logLoginAttempt(email, ipAddress, false, `Firebase auth error: ${error.code}`);
        
        // Check failed attempts
        const failedAttempts = await User.getRecentFailedAttempts(email);
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || 5);
        console.log('Failed attempts:', failedAttempts, 'of', maxAttempts);
        
        if (failedAttempts >= maxAttempts) {
          const user = await User.findByEmail(email);
          if (user) {
            await user.lockAccount();
            console.log('Account locked due to too many failed attempts');
            return { 
              success: false, 
              error: 'Too many failed attempts. Account has been locked.' 
            };
          }
        }
        
        return { 
          success: false, 
          error: 'Invalid email or password',
          attempts: failedAttempts,
          maxAttempts
        };
      }
      
      await User.logLoginAttempt(email, ipAddress, false, `Unexpected error: ${error.message}`);
      return { success: false, error: error.message };
    }
  }

  // Verify OTP (for both email verification and 2FA)
  static async verifyOTP(userId, otp, isEmailVerification, ipAddress, userAgent) {
    try {
      // Find user by ID
      const user = await User.findById(userId);
      
      if (!user) {
        console.error(`User not found for ID: ${userId}`);
        return { success: false, error: 'User not found' };
      }
      
      // Verify OTP
      const isValid = await user.verifyOTP(otp);
      
      if (!isValid) {
        console.error(`Invalid OTP attempt for user ID: ${userId}`);
        return { success: false, error: 'Invalid or expired verification code' };
      }

      // If this is email verification, mark email as verified
      if (isEmailVerification) {
        await user.markEmailAsVerified();
        return { success: true };
      }

      // For login verification, create a session
      try {
        // Invalidate all previous sessions
        await Session.deleteUserSessions(user.id);
        
        // Create new session
        const session = await Session.create({
          user_id: user.id,
          ipAddress,
          userAgent
        });

        console.log('Session created successfully:', {
          userId: user.id,
          sessionId: session.id,
          accessToken: session.access_token ? '***' : undefined,
          refreshToken: session.refresh_token ? '***' : undefined
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
      } catch (sessionError) {
        console.error('Session creation error:', sessionError);
        return { success: false, error: 'Error creating session. Please try again.' };
      }
    } catch (error) {
      console.error('OTP verification error:', error);
      return { success: false, error: 'An error occurred during verification. Please try again.' };
    }
  }

  // Resend verification OTP
  static async resendVerificationOTP(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const verificationData = await user.generateVerificationOTP();
      return {
        success: true,
        verificationOtp: verificationData.otp // In production, this would be sent via email
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Resend login OTP
  static async resendLoginOTP(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const otpData = await user.generateLoginOTP();
      return {
        success: true,
        otp: otpData.otp // In production, this would be sent via email
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Verify two-factor authentication
  static async verifyTwoFactor(userId, token, backupCode, ipAddress, userAgent) {
    try {
      // Find user by ID
      const user = await User.findById(userId);
      
      if (!user) {
        return { success: false, error: 'User not found' };
      }
      
      let isValid = false;
      
      // Check if token or backup code was provided
      if (token) {
        isValid = await user.verifyOTP(token);
      } else if (backupCode) {
        isValid = await user.verifyBackupCode(backupCode);
      }
      
      if (!isValid) {
        return { success: false, error: 'Invalid verification code' };
      }
      
      // Invalidate all previous sessions before creating a new one
      await Session.deleteUserSessions(user.id);
      
      // Create session
      const session = await Session.create({
        user_id: user.id,
        ipAddress,
        userAgent
      });
      
      return { 
        success: true, 
        user, 
        token: session.token,
        expiration: session.expires_at
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Verify session
  static async verifySession(token) {
    try {
      // Verify access token
      const result = await Session.verifyAccessToken(token);
      
      if (!result.success) {
        return result;
      }
      
      // Get user associated with session
      const user = await User.findById(result.userId);
      
      if (!user) {
        // Delete session if user doesn't exist
        const session = await Session.findByAccessToken(token);
        if (session) {
          await session.delete();
        }
        return { success: false, error: 'User not found' };
      }
      
      return { 
        success: true, 
        user,
        sessionId: result.sessionId
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Refresh access token using refresh token
  static async refreshSession(refreshToken) {
    try {
      if (!refreshToken) {
        return { success: false, error: 'No refresh token provided' };
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET || 'default-secret');
      
      if (decoded.type !== 'refresh') {
        return { success: false, error: 'Invalid token type' };
      }
      
      // Get session by refresh token
      const session = await Session.findByRefreshToken(refreshToken);
      
      if (!session) {
        return { success: false, error: 'Session not found' };
      }

      if (session.status !== 'active') {
        return { success: false, error: 'Session is not active' };
      }
      
      if (session.isRefreshTokenExpired()) {
        await session.delete();
        return { success: false, error: 'Refresh token expired' };
      }

      // Generate new access token
      const newAccessToken = jwt.sign(
        { 
          userId: decoded.userId,
          sessionId: decoded.sessionId,
          type: 'access'
        },
        process.env.JWT_SECRET || 'default-secret',
        { 
          expiresIn: '30s', // Changed from 1h to 30s for testing
          algorithm: 'HS256'
        }
      );

      // Update access token and expiration
      const now = new Date();
      const accessTokenExpiresAt = new Date(now.getTime() + 30 * 1000); // 30 seconds
      
      await pool.query(`
        UPDATE user_sessions 
        SET access_token = ?, access_token_expires_at = ?
        WHERE id = ?
      `, [newAccessToken, accessTokenExpiresAt, session.id]);

      return {
        success: true,
        accessToken: newAccessToken,
        expiresAt: accessTokenExpiresAt
      };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return { success: false, error: 'Refresh token expired' };
      }
      return { success: false, error: error.message };
    }
  }

  // Logout user
  static async logout(accessToken) {
    try {
      // Find session by access token
      const session = await Session.findByAccessToken(accessToken);
      
      if (!session) {
        return { success: false, error: 'Invalid session' };
      }
      
      // Delete session
      await session.delete();
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Get user sessions
  static async getUserSessions(userId) {
    try {
      const sessions = await Session.getUserSessions(userId);
      return { 
        success: true, 
        sessions: sessions.map(session => ({
          id: session.id,
          deviceInfo: JSON.parse(session.device_info),
          createdAt: session.created_at,
          status: session.status,
          accessTokenExpiresAt: session.access_token_expires_at,
          refreshTokenExpiresAt: session.refresh_token_expires_at
        }))
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Terminate all other sessions
  static async terminateOtherSessions(userId, currentSessionId) {
    try {
      await Session.deleteUserSessions(userId, currentSessionId);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Enable two-factor authentication
  static async enableTwoFactor(userId) {
    try {
      // Find user by ID
      const user = await User.findById(userId);
      
      if (!user) {
        return { success: false, error: 'User not found' };
      }
      
      // Enable two-factor authentication
      const twoFactorData = await user.enableTwoFactor();
      
      return { 
        success: true, 
        secret: twoFactorData.secret,
        otpauthUrl: twoFactorData.otpauth_url,
        backupCodes: twoFactorData.backupCodes
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Request email OTP
  static async requestEmailOTP(userId) {
    try {
      // Find user by ID
      const user = await User.findById(userId);
      
      if (!user) {
        return { success: false, error: 'User not found' };
      }
      
      // Generate email OTP
      const otpData = await user.generateEmailOTP();
      
      return { 
        success: true,
        message: 'OTP has been sent to your email',
        // In a production app, don't return the actual OTP
        // This is for demonstration purposes only
        otp: otpData.otp,
        expiresAt: otpData.expiresAt
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Verify email OTP
  static async verifyEmailOTP(userId, otp, ipAddress, userAgent) {
    try {
      // Find user by ID
      const user = await User.findById(userId);
      
      if (!user) {
        return { success: false, error: 'User not found' };
      }
      
      // Verify OTP
      const isValid = await user.verifyEmailOTP(otp);
      
      if (!isValid) {
        return { success: false, error: 'Invalid or expired OTP' };
      }
      
      // Invalidate all previous sessions
      await Session.deleteUserSessions(user.id);
      
      // Create new session
      const session = await Session.create({
        user_id: user.id,
        ipAddress,
        userAgent
      });
      
      return { 
        success: true, 
        user, 
        token: session.token,
        expiration: session.expires_at
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

module.exports = AuthController; 