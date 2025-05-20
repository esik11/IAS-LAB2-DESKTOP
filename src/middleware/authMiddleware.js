const { auth } = require('../config/firebase');
const SessionManager = require('../utils/sessionManager');
const SecurityLogger = require('../utils/securityLogger');
const CSRFProtection = require('./csrfProtection');

class AuthMiddleware {
  static async verifyFirebaseToken(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'No token provided'
        });
      }

      const token = authHeader.split('Bearer ')[1];
      const decodedToken = await auth.verifyIdToken(token);
      
      req.user = {
        uid: decodedToken.uid,
        email: decodedToken.email
      };
      
      next();
    } catch (error) {
      console.error('Token verification error:', error);
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }
  }

  static async verifySession(req, res, next) {
    try {
      const accessToken = req.headers['x-access-token'];
      if (!accessToken) {
        return res.status(401).json({
          success: false,
          error: 'No access token provided'
        });
      }

      const session = await SessionManager.verifySession(accessToken);
      req.session = session;
      
      // Log session verification
      await SecurityLogger.logSessionEvent(
        session.userId,
        'SESSION_VERIFIED',
        session.sessionId,
        req.ip,
        req.headers['user-agent']
      );
      
      next();
    } catch (error) {
      console.error('Session verification error:', error);
      return res.status(401).json({
        success: false,
        error: 'Invalid session'
      });
    }
  }

  static async refreshToken(req, res, next) {
    try {
      const refreshToken = req.headers['x-refresh-token'];
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          error: 'No refresh token provided'
        });
      }

      const newSession = await SessionManager.refreshSession(refreshToken);
      
      // Set new tokens in response headers
      res.setHeader('x-access-token', newSession.accessToken);
      res.setHeader('x-refresh-token', newSession.refreshToken);
      
      // Log token refresh
      await SecurityLogger.logSessionEvent(
        req.session?.userId,
        'TOKEN_REFRESHED',
        req.session?.sessionId,
        req.ip,
        req.headers['user-agent']
      );
      
      next();
    } catch (error) {
      console.error('Token refresh error:', error);
      return res.status(401).json({
        success: false,
        error: 'Failed to refresh token'
      });
    }
  }

  static async requireAuth(req, res, next) {
    try {
      // Verify Firebase token
      await this.verifyFirebaseToken(req, res, () => {});
      
      // Verify session
      await this.verifySession(req, res, () => {});
      
      // Verify CSRF token for non-GET requests
      if (req.method !== 'GET') {
        const csrfToken = req.headers['x-csrf-token'];
        if (!csrfToken || !CSRFProtection.validateToken(csrfToken, req.session.csrfToken)) {
          return res.status(403).json({
            success: false,
            error: 'Invalid CSRF token'
          });
        }
      }
      
      next();
    } catch (error) {
      console.error('Authentication error:', error);
      return res.status(401).json({
        success: false,
        error: 'Authentication failed'
      });
    }
  }
}

module.exports = AuthMiddleware; 