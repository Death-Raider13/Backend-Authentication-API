const rateLimit = require('express-rate-limit');

/**
 * Rate limiting middleware configurations
 * Implements different rate limiting strategies for various endpoints
 */

/**
 * General rate limiter for all API endpoints
 * Prevents abuse by limiting requests per IP address
 */
const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests from this IP, please try again later'
    },
    timestamp: new Date().toISOString()
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests from this IP, please try again later',
        details: {
          limit: req.rateLimit.limit,
          remaining: req.rateLimit.remaining,
          resetTime: new Date(req.rateLimit.resetTime)
        }
      },
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Strict rate limiter for authentication endpoints
 * More restrictive to prevent brute force attacks
 */
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 authentication attempts per windowMs
  message: {
    success: false,
    error: {
      code: 'AUTH_RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts, please try again later'
    },
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'AUTH_RATE_LIMIT_EXCEEDED',
        message: 'Too many authentication attempts, please try again later',
        details: {
          limit: req.rateLimit.limit,
          remaining: req.rateLimit.remaining,
          resetTime: new Date(req.rateLimit.resetTime)
        }
      },
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * OTP-specific rate limiter
 * Limits OTP requests to 3 per 15 minutes per IP/user combination
 */
const otpRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit to 3 OTP requests per windowMs
  message: {
    success: false,
    error: {
      code: 'OTP_RATE_LIMIT_EXCEEDED',
      message: 'Too many OTP requests, please try again later'
    },
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator to track both IP and user
  keyGenerator: (req) => {
    // Use email from request body if available, otherwise fall back to IP
    const email = req.body?.email || req.user?.email;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (email) {
      return `otp_${email}_${ip}`;
    }
    return `otp_${ip}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'OTP_RATE_LIMIT_EXCEEDED',
        message: 'Too many OTP requests. You can request up to 3 OTPs per 15 minutes',
        details: {
          limit: req.rateLimit.limit,
          remaining: req.rateLimit.remaining,
          resetTime: new Date(req.rateLimit.resetTime),
          windowMs: 15 * 60 * 1000
        }
      },
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Password reset rate limiter
 * Limits password reset attempts to prevent abuse
 */
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit to 5 password reset attempts per hour
  message: {
    success: false,
    error: {
      code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
      message: 'Too many password reset attempts, please try again later'
    },
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use email from request body if available, otherwise fall back to IP
    const email = req.body?.email;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (email) {
      return `password_reset_${email}_${ip}`;
    }
    return `password_reset_${ip}`;
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
        message: 'Too many password reset attempts. Please try again in an hour',
        details: {
          limit: req.rateLimit.limit,
          remaining: req.rateLimit.remaining,
          resetTime: new Date(req.rateLimit.resetTime)
        }
      },
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Custom rate limiter for user-specific actions
 * Tracks rate limits per authenticated user
 */
const createUserRateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 20, // 20 requests per window
    message = 'Too many requests for this user'
  } = options;

  return rateLimit({
    windowMs,
    max,
    keyGenerator: (req) => {
      // Use user ID if authenticated, otherwise fall back to IP
      if (req.user && req.user._id) {
        return `user_${req.user._id}`;
      }
      return req.ip || req.connection.remoteAddress;
    },
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        error: {
          code: 'USER_RATE_LIMIT_EXCEEDED',
          message,
          details: {
            limit: req.rateLimit.limit,
            remaining: req.rateLimit.remaining,
            resetTime: new Date(req.rateLimit.resetTime)
          }
        },
        timestamp: new Date().toISOString()
      });
    }
  });
};

/**
 * Rate limiter for registration endpoints
 * Prevents mass account creation
 */
const registrationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit to 5 registrations per hour per IP
  message: {
    success: false,
    error: {
      code: 'REGISTRATION_RATE_LIMIT_EXCEEDED',
      message: 'Too many registration attempts, please try again later'
    },
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      error: {
        code: 'REGISTRATION_RATE_LIMIT_EXCEEDED',
        message: 'Too many registration attempts from this IP. Please try again in an hour',
        details: {
          limit: req.rateLimit.limit,
          remaining: req.rateLimit.remaining,
          resetTime: new Date(req.rateLimit.resetTime)
        }
      },
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = {
  generalRateLimit,
  authRateLimit,
  otpRateLimit,
  passwordResetRateLimit,
  registrationRateLimit,
  createUserRateLimit
};