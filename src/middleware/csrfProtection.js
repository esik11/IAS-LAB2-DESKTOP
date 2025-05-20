const crypto = require('crypto');

class CSRFProtection {
  static generateToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  static validateToken(token, storedToken) {
    if (!token || !storedToken) {
      return false;
    }
    return crypto.timingSafeEqual(
      Buffer.from(token),
      Buffer.from(storedToken)
    );
  }

  static middleware() {
    return async (req, res, next) => {
      // Skip CSRF check for GET requests
      if (req.method === 'GET') {
        return next();
      }

      const csrfToken = req.headers['x-csrf-token'];
      const storedToken = req.session?.csrfToken;

      if (!csrfToken || !storedToken || !this.validateToken(csrfToken, storedToken)) {
        return res.status(403).json({
          success: false,
          error: 'Invalid CSRF token'
        });
      }

      next();
    };
  }
}

module.exports = CSRFProtection; 