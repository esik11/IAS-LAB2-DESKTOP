const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const emailService = require('../utils/emailService');
const Encryption = require('../utils/encryption');
const rateLimiter = require('../utils/rateLimiter');
const crypto = require('crypto');

// Fields that should be encrypted in the database
const ENCRYPTED_FIELDS = ['phone_number', 'recovery_email', 'backup_codes'];

class User {
  constructor(data = {}) {
    this.id = data.id || null;
    this.name = data.name || null;
    this.email = data.email || null;
    this.password = data.password || null;
    this.phone_number = data.phone_number || null;
    this.recovery_email = data.recovery_email || null;
    this.is_email_verified = data.is_email_verified || false;
    this.is_phone_verified = data.is_phone_verified || false;
    this.two_factor_enabled = data.two_factor_enabled || false;
    this.two_factor_secret = data.two_factor_secret || null;
    this.backup_codes = data.backup_codes || null;
    this.failed_attempts = data.failed_attempts || 0;
    this.last_failed_attempt = data.last_failed_attempt || null;
    this.locked_until = data.locked_until || null;
    this.created_at = data.created_at || new Date();
    this.updated_at = data.updated_at || new Date();
    this.firebase_uid = data.firebase_uid || null;
    this.is_locked = data.is_locked || false;
    this.currentOtp = null;
    this.otpExpiry = null;
  }

  // Create tables if not exists
  static async createTables() {
    try {
      // Create users table if not exists (matching existing schema)
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INT PRIMARY KEY AUTO_INCREMENT,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          firebase_uid VARCHAR(128) UNIQUE NOT NULL,
          is_locked BOOLEAN DEFAULT FALSE,
          locked_until TIMESTAMP NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      
      // Create backup_codes table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS backup_codes (
          id INT PRIMARY KEY AUTO_INCREMENT,
          user_id INT,
          code VARCHAR(8) NOT NULL,
          is_used BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          used_at TIMESTAMP NULL,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);
      
      // Create otp_history table if not exists
      await pool.query(`
        CREATE TABLE IF NOT EXISTS otp_history (
          id INT PRIMARY KEY AUTO_INCREMENT,
          user_id INT,
          otp VARCHAR(6) NOT NULL,
          otp_type ENUM('LOGIN', 'VERIFY_EMAIL') NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL,
          is_used BOOLEAN DEFAULT FALSE,
          used_at TIMESTAMP NULL,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);
      
      console.log('User tables created or already exist');
      return true;
    } catch (error) {
      console.error('Error creating user tables:', error);
      return false;
    }
  }

  // Create a new user
  static async create(userData) {
    try {
      // Hash password using bcrypt
      const hashedPassword = await bcrypt.hash(userData.password, 10);

      const [result] = await pool.query(`
        INSERT INTO users (
          name, email, password, firebase_uid,
          created_at
        ) VALUES (?, ?, ?, ?, NOW())
      `, [
        userData.name,
        userData.email,
        hashedPassword,
        userData.firebase_uid
      ]);

      // Get the created user
      return await User.findById(result.insertId);
    } catch (error) {
      console.error('Error creating user:', error);
      throw new Error(`Failed to create user: ${error.message}`);
    }
  }

  // Find user by ID
  static async findById(id) {
    try {
      const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
      if (rows.length === 0) return null;
      return new User(rows[0]);
    } catch (error) {
      console.error('Error finding user:', error);
      throw new Error(`Failed to find user: ${error.message}`);
    }
  }

  // Find user by email
  static async findByEmail(email) {
    try {
      const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (rows.length === 0) return null;
      return new User(rows[0]);
    } catch (error) {
      console.error('Error finding user by email:', error);
      throw new Error(`Failed to find user by email: ${error.message}`);
    }
  }

  // Find user by Firebase UID
  static async findByFirebaseUID(firebaseUID) {
    try {
      const [rows] = await pool.query('SELECT * FROM users WHERE firebase_uid = ?', [firebaseUID]);
      if (rows.length === 0) return null;
      return new User(rows[0]);
    } catch (error) {
      throw new Error(`Error finding user by Firebase UID: ${error.message}`);
    }
  }

  // Verify password
  async verifyPassword(password) {
    try {
      return await bcrypt.compare(password, this.password);
    } catch (error) {
      console.error('Password verification error:', error);
      throw new Error('Failed to verify password');
    }
  }

  // Update user
  async update(updateData) {
    try {
      // Encrypt sensitive data if present
      const encryptedData = Encryption.encryptFields(updateData, ENCRYPTED_FIELDS);

      const updates = [];
      const values = [];

      // Build dynamic update query
      Object.keys(encryptedData).forEach(key => {
        if (key !== 'id' && encryptedData[key] !== undefined) {
          updates.push(`${key} = ?`);
          values.push(encryptedData[key]);
        }
      });

      values.push(this.id);

      await pool.query(`
        UPDATE users 
        SET ${updates.join(', ')}, updated_at = NOW()
        WHERE id = ?
      `, values);

      // Refresh user data
      const updated = await User.findById(this.id);
      Object.assign(this, updated);

      return true;
    } catch (error) {
      console.error('Error updating user:', error);
      throw new Error(`Failed to update user: ${error.message}`);
    }
  }

  // Check recent failed login attempts
  static async getRecentFailedAttempts(email) {
    try {
      const [rows] = await pool.query(`
        SELECT COUNT(*) as count
        FROM login_attempts
        WHERE email = ? 
        AND is_successful = FALSE 
        AND attempt_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
      `, [email]);
      
      return rows[0].count;
    } catch (error) {
      console.error(`Error checking failed login attempts: ${error.message}`);
      return 0;
    }
  }

  // Lock account
  async lockAccount() {
    try {
      // Lock for 30 minutes
      const lockDuration = 30 * 60 * 1000; // 30 minutes
      const lockedUntil = new Date(Date.now() + lockDuration);
      
      await pool.query(`
        UPDATE users 
        SET is_locked = TRUE, 
            locked_until = ?,
            failed_attempts = 0  -- Reset failed attempts when locking
        WHERE id = ?
      `, [
        lockedUntil.toISOString().slice(0, 19).replace('T', ' '),
        this.id
      ]);
      
      this.locked_until = lockedUntil;
      this.failed_attempts = 0;

      // Log the lockout event
      await pool.query(`
        INSERT INTO login_attempts (email, ip_address, is_successful, notes)
        VALUES (?, NULL, FALSE, 'Account locked due to multiple failed attempts')
      `, [this.email]);
    } catch (error) {
      throw new Error(`Error locking account: ${error.message}`);
    }
  }

  // Enable two-factor authentication
  async enableTwoFactor() {
    try {
      const secret = speakeasy.generateSecret({ length: 20 });
      
      // Check if user already has backup codes
      const [existingCodes] = await pool.query(
        'SELECT id FROM backup_codes WHERE user_id = ? LIMIT 1', 
        [this.id]
      );
      
      // If codes exist, delete them
      if (existingCodes.length > 0) {
        await pool.query('DELETE FROM backup_codes WHERE user_id = ?', [this.id]);
      }
      
      // Generate backup codes
      const backupCodes = [];
      for (let i = 0; i < 10; i++) {
        const code = uuidv4().substring(0, 8);
        backupCodes.push(code);
        
        // Insert backup code
        await pool.query(
          'INSERT INTO backup_codes (user_id, code) VALUES (?, ?)',
          [this.id, code]
        );
      }
      
      this.two_factor_secret = secret.base32;
      this.two_factor_enabled = true;
      
      return {
        secret: secret.base32,
        otpauth_url: secret.otpauth_url,
        backupCodes
      };
    } catch (error) {
      throw new Error(`Error enabling two-factor authentication: ${error.message}`);
    }
  }

  // Verify OTP
  async verifyOTP(otp) {
    try {
      console.log('*** USING UPDATED verifyOTP METHOD ***');
      console.log('Verifying OTP for user:', this.email);
      
      // Find unexpired, unused OTP in database - using simpler query
      const [rows] = await pool.query(`
        SELECT id 
        FROM otp_history 
        WHERE user_id = ? 
        AND otp = ? 
        AND otp_type = 'LOGIN'
        AND is_used = FALSE 
        AND expires_at > NOW()
      `, [this.id, otp]);
      
      if (rows.length === 0) {
        console.error('OTP not found or expired');
        return false;
      }
      
      console.log('Found valid OTP with ID:', rows[0].id);
      
      // Mark OTP as used
      await pool.query(`
        UPDATE otp_history SET is_used = TRUE, used_at = NOW()
        WHERE id = ?
      `, [rows[0].id]);
      
      console.log('OTP verified successfully');
      return true;
    } catch (error) {
      console.error('Error verifying OTP:', error);
      return false;
    }
  }

  // Verify backup code
  async verifyBackupCode(code) {
    try {
      // Find the backup code in the database
      const [backupCode] = await pool.query(
        'SELECT * FROM backup_codes WHERE user_id = ? AND code = ? AND is_used = FALSE',
        [this.id, code.toUpperCase()]
      );

      if (!backupCode || backupCode.length === 0) {
        return false;
      }

      // Mark the code as used
      await pool.query(
        'UPDATE backup_codes SET is_used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = ?',
        [backupCode[0].id]
      );

      return true;
    } catch (error) {
      console.error('Error verifying backup code:', error);
      return false;
    }
  }

  // Log login attempt
  static async logLoginAttempt(email, ipAddress, isSuccessful, details = '') {
    try {
      await pool.query(`
        INSERT INTO login_attempts (email, ip_address, is_successful)
        VALUES (?, ?, ?)
      `, [email, ipAddress, isSuccessful]);

      // Also log to security_logs if we have a user
      const [user] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
      if (user && user.length > 0) {
        await pool.query(`
          INSERT INTO security_logs (user_id, event_type, ip_address, details)
          VALUES (?, ?, ?, ?)
        `, [
          user[0].id,
          isSuccessful ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
          ipAddress,
          details
        ]);
      }
    } catch (error) {
      console.error(`Error logging login attempt: ${error.message}`);
    }
  }

  // Unlock account
  async unlockAccount() {
    try {
      await pool.query(`
        UPDATE users SET is_locked = FALSE, locked_until = NULL
        WHERE id = ?
      `, [this.id]);
      
      this.locked_until = null;
    } catch (error) {
      throw new Error(`Error unlocking account: ${error.message}`);
    }
  }

  // Check if account is locked
  isLocked() {
    if (!this.locked_until) {
      return false;
    }
    
    // Check if lock expired
    const now = new Date();
    const lockTime = new Date(this.locked_until);
    
    if (now > lockTime) {
      // Lock has expired, but record still shows locked
      this.unlockAccount().catch(console.error);
      return false;
    }
    
    return true;
  }
  
  // Check if two-factor authentication is enabled
  async isTwoFactorEnabled() {
    try {
      const [backupCodes] = await pool.query(
        'SELECT id FROM backup_codes WHERE user_id = ? LIMIT 1',
        [this.id]
      );
      
      return backupCodes.length > 0;
    } catch (error) {
      console.error(`Error checking 2FA status: ${error.message}`);
      return false;
    }
  }

  // Generate email OTP
  async generateEmailOTP() {
    try {
      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      
      // Delete any existing email OTPs
      await pool.query(`
        DELETE FROM otp_history 
        WHERE user_id = ? AND otp_type = 'EMAIL'
      `, [this.id]);
      
      // Save OTP to database - let MySQL handle the timestamp calculation
      await pool.query(`
        INSERT INTO otp_history (user_id, otp, otp_type, expires_at, is_used) 
        VALUES (?, ?, 'EMAIL', DATE_ADD(NOW(), INTERVAL 10 MINUTE), FALSE)
      `, [this.id, otp]);
      
      // Return expiry date for UI display only
      const expiryDate = new Date(Date.now() + 10 * 60 * 1000);
      
      return {
        otp,
        expiresAt: expiryDate
      };
    } catch (error) {
      throw new Error(`Error generating email OTP: ${error.message}`);
    }
  }

  // Verify email OTP
  async verifyEmailOTP(otp) {
    try {
      // Find unexpired, unused OTP
      const [rows] = await pool.query(`
        SELECT id FROM otp_history 
        WHERE user_id = ? 
        AND otp = ? 
        AND otp_type = 'EMAIL'
        AND is_used = FALSE 
        AND expires_at > NOW()
      `, [this.id, otp]);
      
      if (rows.length === 0) {
        return false;
      }
      
      // Mark OTP as used
      await pool.query(`
        UPDATE otp_history SET is_used = TRUE 
        WHERE id = ?
      `, [rows[0].id]);

      // Mark email as verified if it's a verification OTP
      if (rows[0].otp_type === 'VERIFY_EMAIL') {
        await this.markEmailAsVerified();
      }
      
      return true;
    } catch (error) {
      throw new Error(`Error verifying email OTP: ${error.message}`);
    }
  }

  // Mark email as verified
  async markEmailAsVerified() {
    try {
      await pool.query(`
        UPDATE users SET is_email_verified = TRUE
        WHERE id = ?
      `, [this.id]);
      
      this.is_email_verified = true;
    } catch (error) {
      throw new Error(`Error marking email as verified: ${error.message}`);
    }
  }

  // Check if email is verified
  async isEmailVerified() {
    try {
      const [rows] = await pool.query(`
        SELECT is_email_verified FROM users
        WHERE id = ?
      `, [this.id]);
      
      return rows[0]?.is_email_verified || false;
    } catch (error) {
      console.error(`Error checking email verification status: ${error.message}`);
      return false;
    }
  }

  // Generate verification email OTP
  async generateVerificationOTP() {
    try {
      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      
      // Delete any existing verification OTPs
      await pool.query(`
        DELETE FROM otp_history 
        WHERE user_id = ? AND is_used = FALSE
      `, [this.id]);
      
      // Save OTP to database - let MySQL handle the timestamp calculation
      await pool.query(`
        INSERT INTO otp_history (user_id, otp, otp_type, expires_at, is_used) 
        VALUES (?, ?, 'VERIFY_EMAIL', DATE_ADD(NOW(), INTERVAL 24 HOUR), FALSE)
      `, [this.id, otp]);
      
      // Send verification email
      await emailService.sendVerificationEmail(this.email, otp);
      
      // Return expiry date for UI display only
      const expiryDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
      
      return {
        success: true,
        expiresAt: expiryDate
      };
    } catch (error) {
      throw new Error(`Error generating verification OTP: ${error.message}`);
    }
  }

  // Generate login OTP
  async generateLoginOTP() {
    try {
      console.log('Generating login OTP for user:', this.email);
      
      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString().padStart(6, '0');
      console.log('Generated OTP:', otp);
      
      // Delete any existing LOGIN OTPs
      await pool.query(`
        DELETE FROM otp_history 
        WHERE user_id = ? AND otp_type = 'LOGIN' AND is_used = FALSE
      `, [this.id]);
      
      // Save OTP to database - let MySQL handle the timestamp calculation
      await pool.query(`
        INSERT INTO otp_history (user_id, otp, otp_type, expires_at) 
        VALUES (?, ?, 'LOGIN', DATE_ADD(NOW(), INTERVAL 5 MINUTE))
      `, [this.id, otp]);
      
      // Send OTP via email
      await emailService.sendLoginOTP(this.email, otp);
      
      return {
        success: true,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000) // Only for UI display
      };
    } catch (error) {
      console.error('Error generating login OTP:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Generate and store OTP
  async generateOTP(type) {
    try {
      const otp = speakeasy.totp({
        secret: speakeasy.generateSecret().base32,
        digits: 6
      });

      // Set expiry time (5 minutes from now)
      const expiryDate = new Date();
      expiryDate.setMinutes(expiryDate.getMinutes() + 5);
      const formattedExpiresAt = expiryDate.toISOString().slice(0, 19).replace('T', ' ');

      // Store OTP in database
      await pool.query(`
        INSERT INTO otp_history (user_id, otp, otp_type, expires_at)
        VALUES (?, ?, ?, ?)
      `, [this.id, otp, type, formattedExpiresAt]);

      return otp;
    } catch (error) {
      throw new Error(`Error generating OTP: ${error.message}`);
    }
  }

  // Generate backup codes
  async generateBackupCodes(count = 8) {
    try {
      // Delete any existing backup codes
      await pool.query('DELETE FROM backup_codes WHERE user_id = ?', [this.id]);
      
      const codes = [];
      for (let i = 0; i < count; i++) {
        const code = crypto.randomBytes(4).toString('hex').toUpperCase();
        codes.push(code);
        
        // Insert each backup code into the database
        await pool.query(
          'INSERT INTO backup_codes (user_id, code) VALUES (?, ?)',
          [this.id, code]
        );
      }

      return codes;
    } catch (error) {
      console.error('Error generating backup codes:', error);
      throw new Error('Failed to generate backup codes');
    }
  }

  // Increment failed attempts
  async incrementFailedAttempts() {
    try {
      await pool.query(`
        UPDATE users SET failed_attempts = failed_attempts + 1, last_failed_attempt = NOW()
        WHERE id = ?
      `, [this.id]);
      
      this.failed_attempts++;
      this.last_failed_attempt = new Date();
    } catch (error) {
      throw new Error(`Error incrementing failed attempts: ${error.message}`);
    }
  }

  // Reset failed attempts
  async resetFailedAttempts() {
    try {
      await pool.query(`
        UPDATE users SET failed_attempts = 0, last_failed_attempt = NULL
        WHERE id = ?
      `, [this.id]);
      
      this.failed_attempts = 0;
      this.last_failed_attempt = null;
    } catch (error) {
      throw new Error(`Error resetting failed attempts: ${error.message}`);
    }
  }
}

module.exports = User; 