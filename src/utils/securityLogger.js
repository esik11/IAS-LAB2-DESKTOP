/**
 * Security Logging Utility
 * Used to log security events to the security_logs table
 */

const { pool } = require('../config/database');

/**
 * Log a security event to the database
 * 
 * @param {Object} logData - The security event data
 * @param {number|null} logData.userId - User ID (can be null for unauthenticated events)
 * @param {string} logData.eventType - Type of security event (LOGIN, LOGOUT, LOGIN_FAILED, etc.)
 * @param {string|null} logData.ipAddress - IP address (can be null)
 * @param {string|null} logData.userAgent - User agent string (can be null)
 * @param {string|Object|null} logData.details - Additional event details (will be converted to JSON if object)
 * @returns {Promise<boolean>} - Whether the log was recorded successfully
 */
async function logSecurityEvent(logData) {
  try {
    // Input validation
    if (!logData || !logData.eventType) {
      console.error('Invalid security log data:', logData);
      return false;
    }

    // Format details if it's an object
    let details = logData.details;
    if (details && typeof details === 'object') {
      details = JSON.stringify(details);
    }

    // Insert into security_logs table
    await pool.query(`
      INSERT INTO security_logs (
        user_id, event_type, ip_address, user_agent, details, created_at
      ) VALUES (?, ?, ?, ?, ?, NOW())
    `, [
      logData.userId || null,
      logData.eventType,
      logData.ipAddress || null,
      logData.userAgent || null,
      details || null
    ]);

    console.log(`Security event logged: ${logData.eventType}`, { 
      userId: logData.userId, 
      details: logData.details 
    });
    
    return true;
  } catch (error) {
    console.error('Error logging security event:', error);
    return false;
  }
}

/**
 * Get recent security logs for a user
 * 
 * @param {number} userId - User ID to get logs for
 * @param {number} limit - Maximum number of logs to return
 * @returns {Promise<Array>} - Array of security log entries
 */
async function getUserSecurityLogs(userId, limit = 10) {
  try {
    const [rows] = await pool.query(`
      SELECT * FROM security_logs 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT ?
    `, [userId, limit]);
    
    return rows;
  } catch (error) {
    console.error('Error retrieving user security logs:', error);
    return [];
  }
}

/**
 * Get all security logs with pagination
 * 
 * @param {Object} options - Query options
 * @param {number} options.page - Page number (1-based)
 * @param {number} options.limit - Items per page
 * @param {string} options.eventType - Filter by event type (optional)
 * @returns {Promise<Object>} - Paginated results
 */
async function getAllSecurityLogs(options = {}) {
  try {
    const page = options.page || 1;
    const limit = options.limit || 20;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT sl.*, u.email as user_email 
      FROM security_logs sl
      LEFT JOIN users u ON sl.user_id = u.id
      WHERE 1=1
    `;
    
    const params = [];
    
    // Add filters
    if (options.eventType) {
      query += ' AND sl.event_type = ?';
      params.push(options.eventType);
    }
    
    // Add sorting
    query += ' ORDER BY sl.created_at DESC';
    
    // Add pagination
    query += ' LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    const [rows] = await pool.query(query, params);
    
    // Get total count for pagination
    const [countResult] = await pool.query(`
      SELECT COUNT(*) as total FROM security_logs
      WHERE 1=1 ${options.eventType ? ' AND event_type = ?' : ''}
    `, options.eventType ? [options.eventType] : []);
    
    const total = countResult[0].total;
    
    return {
      data: rows,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    };
  } catch (error) {
    console.error('Error retrieving security logs:', error);
    return {
      data: [],
      pagination: {
        total: 0,
        page: 1,
        limit: 20,
        pages: 0
      }
    };
  }
}

module.exports = {
  logSecurityEvent,
  getUserSecurityLogs,
  getAllSecurityLogs
}; 