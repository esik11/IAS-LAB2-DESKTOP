const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
require('dotenv').config();

class SessionManager {
  static async createSession(userId, ipAddress, userAgent) {
    try {
      // Generate access token
      const accessToken = jwt.sign(
        { userId, type: 'access' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRATION }
      );

      // Generate refresh token
      const refreshToken = jwt.sign(
        { userId, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRATION }
      );

      // Calculate expiration times
      const accessExpiresAt = new Date(Date.now() + (process.env.JWT_EXPIRATION * 1000));
      const refreshExpiresAt = new Date(Date.now() + (process.env.JWT_REFRESH_EXPIRATION * 1000));

      // Store session in database
      const [result] = await pool.query(`
        INSERT INTO user_sessions (
          user_id, 
          access_token, 
          refresh_token,
          access_token_expires_at,
          refresh_token_expires_at,
          ip_address,
          user_agent,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
      `, [
        userId,
        accessToken,
        refreshToken,
        accessExpiresAt,
        refreshExpiresAt,
        ipAddress,
        userAgent
      ]);

      return {
        accessToken,
        refreshToken,
        accessExpiresAt,
        refreshExpiresAt
      };
    } catch (error) {
      console.error('Error creating session:', error);
      throw new Error('Failed to create session');
    }
  }

  static async refreshSession(refreshToken) {
    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      // Check if token exists in database and is not expired
      const [sessions] = await pool.query(`
        SELECT * FROM user_sessions 
        WHERE refresh_token = ? 
        AND refresh_token_expires_at > NOW()
        AND is_revoked = FALSE
      `, [refreshToken]);

      if (sessions.length === 0) {
        throw new Error('Invalid or expired refresh token');
      }

      const session = sessions[0];

      // Generate new tokens
      const newAccessToken = jwt.sign(
        { userId: decoded.userId, type: 'access' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRATION }
      );

      const newRefreshToken = jwt.sign(
        { userId: decoded.userId, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRATION }
      );

      // Calculate new expiration times
      const newAccessExpiresAt = new Date(Date.now() + (process.env.JWT_EXPIRATION * 1000));
      const newRefreshExpiresAt = new Date(Date.now() + (process.env.JWT_REFRESH_EXPIRATION * 1000));

      // Update session in database
      await pool.query(`
        UPDATE user_sessions 
        SET 
          access_token = ?,
          refresh_token = ?,
          access_token_expires_at = ?,
          refresh_token_expires_at = ?,
          updated_at = NOW()
        WHERE id = ?
      `, [
        newAccessToken,
        newRefreshToken,
        newAccessExpiresAt,
        newRefreshExpiresAt,
        session.id
      ]);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        accessExpiresAt: newAccessExpiresAt,
        refreshExpiresAt: newRefreshExpiresAt
      };
    } catch (error) {
      console.error('Error refreshing session:', error);
      throw new Error('Failed to refresh session');
    }
  }

  static async revokeSession(sessionId) {
    try {
      await pool.query(`
        UPDATE user_sessions 
        SET is_revoked = TRUE, 
            revoked_at = NOW() 
        WHERE id = ?
      `, [sessionId]);
    } catch (error) {
      console.error('Error revoking session:', error);
      throw new Error('Failed to revoke session');
    }
  }

  static async cleanupExpiredSessions() {
    try {
      await pool.query(`
        UPDATE user_sessions 
        SET is_revoked = TRUE, 
            revoked_at = NOW() 
        WHERE (access_token_expires_at < NOW() OR refresh_token_expires_at < NOW())
        AND is_revoked = FALSE
      `);
    } catch (error) {
      console.error('Error cleaning up expired sessions:', error);
      throw new Error('Failed to cleanup expired sessions');
    }
  }

  static async verifySession(accessToken) {
    try {
      // Verify access token
      const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
      
      // Check if token exists in database and is not expired or revoked
      const [sessions] = await pool.query(`
        SELECT * FROM user_sessions 
        WHERE access_token = ? 
        AND access_token_expires_at > NOW()
        AND is_revoked = FALSE
      `, [accessToken]);

      if (sessions.length === 0) {
        throw new Error('Invalid or expired session');
      }

      return {
        userId: decoded.userId,
        sessionId: sessions[0].id
      };
    } catch (error) {
      console.error('Error verifying session:', error);
      throw new Error('Invalid session');
    }
  }
}

module.exports = SessionManager; 