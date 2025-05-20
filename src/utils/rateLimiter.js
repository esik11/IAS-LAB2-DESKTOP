class RateLimiter {
  constructor() {
    this.requests = new Map();
    this.lockouts = new Map();
    
    // Clean up old entries every hour
    setInterval(() => this.cleanup(), 60 * 60 * 1000);
  }

  isRateLimited(key, maxAttempts = 3, windowMs = 60000) {
    const now = Date.now();
    const windowStart = now - windowMs;

    // Check if key is locked out
    if (this.isLockedOut(key)) {
      return true;
    }

    // Get or initialize requests array for this key
    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }

    // Get requests within the time window
    const keyRequests = this.requests.get(key);
    const recentRequests = keyRequests.filter(timestamp => timestamp > windowStart);

    // Update requests array with only recent requests
    this.requests.set(key, recentRequests);

    // Check if rate limit is exceeded
    if (recentRequests.length >= maxAttempts) {
      // Lock out the key for 30 minutes (increased from 15)
      this.lockout(key, 30 * 60 * 1000);
      return true;
    }

    // Add current request
    recentRequests.push(now);
    this.requests.set(key, recentRequests);

    return false;
  }

  lockout(key, duration = 15 * 60 * 1000) { // 15 minutes default
    const now = Date.now();
    this.lockouts.set(key, now + duration);
  }

  isLockedOut(key) {
    const lockoutExpiry = this.lockouts.get(key);
    if (!lockoutExpiry) {
      return false;
    }

    const now = Date.now();
    if (now >= lockoutExpiry) {
      // Lockout expired, remove it
      this.lockouts.delete(key);
      return false;
    }

    return true;
  }

  getLockoutRemaining(key) {
    const lockoutExpiry = this.lockouts.get(key);
    if (!lockoutExpiry) {
      return 0;
    }

    const remaining = lockoutExpiry - Date.now();
    return remaining > 0 ? remaining : 0;
  }

  cleanup() {
    const now = Date.now();

    // Clean up expired lockouts
    for (const [key, expiry] of this.lockouts.entries()) {
      if (now >= expiry) {
        this.lockouts.delete(key);
      }
    }

    // Clean up old requests
    for (const [key, timestamps] of this.requests.entries()) {
      const recentRequests = timestamps.filter(timestamp => timestamp > now - 24 * 60 * 60 * 1000);
      if (recentRequests.length === 0) {
        this.requests.delete(key);
      } else {
        this.requests.set(key, recentRequests);
      }
    }
  }

  reset(key) {
    this.requests.delete(key);
    this.lockouts.delete(key);
  }
}

// Create a single instance for the application
const rateLimiter = new RateLimiter();

module.exports = rateLimiter; 