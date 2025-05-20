const { pool } = require('../config/database');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

class Session {
  constructor(data = {}) {
    this.id = data.id || null;
    this.user_id = data.user_id || null;
    this.access_token = data.access_token || null;
    this.refresh_token = data.refresh_token || null;
    this.ip_address = data.ip_address || null;
    this.user_agent = data.user_agent || null;
    this.created_at = data.created_at || null;
    this.updated_at = data.updated_at || null;
    this.is_revoked = data.is_revoked || false;
    this.revoked_at = data.revoked_at || null;
    this.access_token_expires_at = data.access_token_expires_at || null;
    this.refresh_token_expires_at = data.refresh_token_expires_at || null;
  }

  // Create table if not exists
  static async createTable() {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS user_sessions (
          id INT PRIMARY KEY AUTO_INCREMENT,
          user_id INT,
          access_token VARCHAR(500) NOT NULL,
          refresh_token VARCHAR(500) NOT NULL,
          access_token_expires_at TIMESTAMP NOT NULL,
          refresh_token_expires_at TIMESTAMP NOT NULL,
          ip_address VARCHAR(45),
          user_agent VARCHAR(255),
          is_revoked BOOLEAN DEFAULT FALSE,
          revoked_at TIMESTAMP NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `);
      return true;
    } catch (error) {
      throw new Error(`Error creating sessions table: ${error.message}`);
    }
  }

  // Create a new session
  static async create(sessionData) {
    try {
      const sessionId = uuidv4();
      const now = new Date();
      
      // Generate access token (1 minute)
      const accessToken = jwt.sign(
        { 
          userId: sessionData.user_id,
          sessionId,
          type: 'access'
        },
        process.env.JWT_SECRET || 'default-secret',
        { 
          expiresIn: '1m',
          algorithm: 'HS256'
        }
      );
      
      // Generate refresh token (24 hours)
      const refreshToken = jwt.sign(
        { 
          userId: sessionData.user_id,
          sessionId,
          type: 'refresh'
        },
        process.env.JWT_SECRET || 'default-secret',
        { 
          expiresIn: '24h',
          algorithm: 'HS256'
        }
      );
      
      // Calculate expiration times
      const accessTokenExpiresAt = new Date(now.getTime() + 60 * 1000); // 1 minute
      const refreshTokenExpiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
      
      const ipAddress = sessionData.ipAddress || 'unknown';
      const userAgent = sessionData.userAgent || 'unknown';

      // Insert session to match the actual database schema
      const [result] = await pool.query(`
        INSERT INTO user_sessions (
          user_id, access_token, refresh_token,
          access_token_expires_at, refresh_token_expires_at,
          ip_address, user_agent, is_revoked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, FALSE, NOW())
      `, [
        sessionData.user_id,
        accessToken,
        refreshToken,
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        ipAddress,
        userAgent
      ]);

      // Get new session
      const [sessionRows] = await pool.query(`
        SELECT * FROM user_sessions WHERE id = ?
      `, [result.insertId]);
      
      if (sessionRows.length === 0) {
        throw new Error('Failed to retrieve created session');
      }
      
      const session = new Session(sessionRows[0]);
      
      // Verify the session was created correctly
      if (!session.access_token || !session.refresh_token) {
        throw new Error('Session created without required tokens');
      }
      
      return session;
    } catch (error) {
      console.error('Detailed session creation error:', error);
      throw new Error(`Error creating session: ${error.message}`);
    }
  }

  // Find session by ID
  static async findById(sessionId) {
    try {
      const [rows] = await pool.query('SELECT * FROM user_sessions WHERE id = ?', [sessionId]);
      return rows.length ? new Session(rows[0]) : null;
    } catch (error) {
      throw new Error(`Error finding session: ${error.message}`);
    }
  }
  
  // Find session by access token
  static async findByAccessToken(token) {
    try {
      const [rows] = await pool.query('SELECT * FROM user_sessions WHERE access_token = ?', [token]);
      return rows.length ? new Session(rows[0]) : null;
    } catch (error) {
      throw new Error(`Error finding session by access token: ${error.message}`);
    }
  }

  // Find session by refresh token
  static async findByRefreshToken(token) {
    try {
      const [rows] = await pool.query('SELECT * FROM user_sessions WHERE refresh_token = ?', [token]);
      return rows.length ? new Session(rows[0]) : null;
    } catch (error) {
      throw new Error(`Error finding session by refresh token: ${error.message}`);
    }
  }

  // Verify access token
  static async verifyAccessToken(token) {
    try {
      if (!token) {
        return { success: false, error: 'No token provided' };
      }

      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
      
      if (decoded.type !== 'access') {
        return { success: false, error: 'Invalid token type' };
      }
      
      // Get session by token
      const session = await Session.findByAccessToken(token);
      
      if (!session) {
        return { success: false, error: 'Session not found' };
      }

      if (session.status !== 'active') {
        return { success: false, error: 'Session is not active' };
      }
      
      if (session.isAccessTokenExpired()) {
        return { success: false, error: 'Access token expired' };
      }
      
      return {
        success: true,
        userId: decoded.userId,
        sessionId: decoded.sessionId
      };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return { success: false, error: 'Token expired' };
      }
      return { success: false, error: error.message };
    }
  }

  // Refresh access token using refresh token
  static async refreshAccessToken(refreshToken) {
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
          expiresIn: '1h',
          algorithm: 'HS256'
        }
      );

      // Update access token and expiration
      const now = new Date();
      const accessTokenExpiresAt = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour
      
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

  // Check if access token is expired
  isAccessTokenExpired() {
    if (!this.access_token_expires_at) return true;
    return new Date() > new Date(this.access_token_expires_at);
  }

  // Check if refresh token is expired
  isRefreshTokenExpired() {
    if (!this.refresh_token_expires_at) return true;
    return new Date() > new Date(this.refresh_token_expires_at);
  }

  // Delete session
  async delete() {
    try {
      await pool.query('DELETE FROM user_sessions WHERE id = ?', [this.id]);
      return true;
    } catch (error) {
      throw new Error(`Error deleting session: ${error.message}`);
    }
  }

  // Get all sessions for a user
  static async getUserSessions(userId) {
    try {
      const [rows] = await pool.query(`
        SELECT * FROM user_sessions 
        WHERE user_id = ? 
        ORDER BY created_at DESC
      `, [userId]);
      
      return rows.map(row => new Session(row));
    } catch (error) {
      throw new Error(`Error getting user sessions: ${error.message}`);
    }
  }
  
  // Delete all sessions for a user (except current)
  static async deleteUserSessions(userId, exceptSessionId = null) {
    try {
      let query = 'DELETE FROM user_sessions WHERE user_id = ?';
      const params = [userId];
      
      if (exceptSessionId) {
        query += ' AND session_id != ?';
        params.push(exceptSessionId);
      }
      
      await pool.query(query, params);
      return true;
    } catch (error) {
      throw new Error(`Error deleting user sessions: ${error.message}`);
    }
  }

  // Update session status
  async updateStatus(newStatus) {
    try {
      await pool.query(`
        UPDATE user_sessions 
        SET status = ?
        WHERE id = ?
      `, [newStatus, this.id]);
      
      this.status = newStatus;
      return true;
    } catch (error) {
      throw new Error(`Error updating session status: ${error.message}`);
    }
  }

  // Update tokens
  static async updateTokens(oldRefreshToken, newAccessToken, newRefreshToken) {
    try {
      console.log('=== Starting token update in database ===');
      console.log('Old refresh token:', oldRefreshToken.substring(0, 20) + '...');
      console.log('New access token:', newAccessToken.substring(0, 20) + '...');
      console.log('New refresh token:', newRefreshToken.substring(0, 20) + '...');

      // First verify the old refresh token exists
      const [existingSession] = await pool.query(
        'SELECT id FROM user_sessions WHERE refresh_token = ?',
        [oldRefreshToken]
      );

      if (!existingSession.length) {
        console.error('No session found with the old refresh token');
        throw new Error('Session not found for token update');
      }

      console.log('Found existing session:', existingSession[0].id);

      const now = new Date();
      const accessTokenExpiresAt = new Date(now.getTime() + 30 * 1000); // 30 seconds
      const refreshTokenExpiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours

      console.log('New expiration times:', {
        accessTokenExpiresAt: accessTokenExpiresAt.toISOString(),
        refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString()
      });

      const [updateResult] = await pool.query(`
        UPDATE user_sessions 
        SET access_token = ?,
            refresh_token = ?,
            access_token_expires_at = ?,
            refresh_token_expires_at = ?
        WHERE refresh_token = ?
      `, [
        newAccessToken,
        newRefreshToken,
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        oldRefreshToken
      ]);

      console.log('Update result:', {
        affectedRows: updateResult.affectedRows,
        changedRows: updateResult.changedRows
      });

      if (updateResult.affectedRows === 0) {
        console.error('No rows were updated in the database');
        throw new Error('Failed to update session tokens');
      }

      // Verify the update
      const [verifyUpdate] = await pool.query(
        'SELECT * FROM user_sessions WHERE refresh_token = ?',
        [newRefreshToken]
      );

      if (verifyUpdate.length === 0) {
        console.error('Failed to verify token update - new refresh token not found');
        throw new Error('Token update verification failed');
      }

      console.log('=== Token update completed successfully ===');
      return true;
    } catch (error) {
      console.error('=== Token update failed ===', error);
      throw new Error(`Error updating session tokens: ${error.message}`);
    }
  }

  // Get current session
  static async getCurrent() {
    try {
      console.log('Looking for current session in database');
      
      // Retrieve the most recent active session
      const [rows] = await pool.query(`
        SELECT * FROM user_sessions 
        WHERE is_revoked = FALSE
        ORDER BY created_at DESC
        LIMIT 1
      `);
      
      if (rows.length === 0) {
        console.log('No current session found');
        return null;
      }
      
      console.log('Found current session:', rows[0].id);
      return new Session(rows[0]);
    } catch (error) {
      console.error('Error getting current session:', error);
      return null;
    }
  }

  // Delete current session
  static async deleteCurrent() {
    try {
      console.log('Attempting to delete current session');
      const currentSession = await this.getCurrent();
      
      if (!currentSession) {
        console.log('No current session to delete');
        return false;
      }
      
      await pool.query(`
        UPDATE user_sessions
        SET is_revoked = TRUE, revoked_at = NOW()
        WHERE id = ?
      `, [currentSession.id]);
      
      console.log('Current session deleted/revoked');
      return true;
    } catch (error) {
      console.error('Error deleting current session:', error);
      return false;
    }
  }

  // Validate session
  static async validate(sessionId) {
    try {
      console.log('Validating session:', sessionId);
      
      const [rows] = await pool.query(`
        SELECT * FROM user_sessions
        WHERE id = ?
        AND (is_revoked = FALSE OR is_revoked IS NULL)
        AND access_token_expires_at > NOW()
      `, [sessionId]);
      
      const isValid = rows.length > 0;
      console.log('Session valid:', isValid);
      
      return isValid;
    } catch (error) {
      console.error('Error validating session:', error);
      return false;
    }
  }

  // Refresh session
  static async refresh(sessionId) {
    try {
      console.log('Refreshing session:', sessionId);
      
      // Get the session
      const [rows] = await pool.query(`
        SELECT * FROM user_sessions WHERE id = ?
      `, [sessionId]);
      
      if (rows.length === 0) {
        console.log('Session not found for refresh');
        return false;
      }
      
      const session = new Session(rows[0]);
      
      // Generate new tokens with updated expiry
      const now = new Date();
      const accessTokenExpiresAt = new Date(now.getTime() + 30 * 60 * 1000); // 30 minutes
      const refreshTokenExpiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
      
      // Update session with new expiry dates
      await pool.query(`
        UPDATE user_sessions
        SET access_token_expires_at = ?,
            refresh_token_expires_at = ?,
            updated_at = NOW()
        WHERE id = ?
      `, [
        accessTokenExpiresAt,
        refreshTokenExpiresAt,
        sessionId
      ]);
      
      console.log('Session refreshed successfully');
      return true;
    } catch (error) {
      console.error('Error refreshing session:', error);
      return false;
    }
  }
}

module.exports = Session;