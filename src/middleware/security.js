const helmet = require('helmet');
const SecurityService = require('../services/SecurityService');

/**
 * Enhanced security middleware for comprehensive protection
 * Implements security headers, response sanitization, and request/response logging
 */
class SecurityMiddleware {
  constructor() {
    this.securityService = new SecurityService();
  }

  /**
   * Enhanced helmet configuration with strict security policies
   * @returns {Function} Configured helmet middleware
   */
  getHelmetConfig() {
    return helmet({
      // Content Security Policy
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: []
        }
      },
      
      // Cross-Origin Embedder Policy
      crossOriginEmbedderPolicy: {
        policy: "require-corp"
      },
      
      // Cross-Origin Opener Policy
      crossOriginOpenerPolicy: {
        policy: "same-origin"
      },
      
      // Cross-Origin Resource Policy
      crossOriginResourcePolicy: {
        policy: "same-origin"
      },
      
      // DNS Prefetch Control
      dnsPrefetchControl: {
        allow: false
      },
      
      // Expect-CT
      expectCt: {
        maxAge: 86400,
        enforce: true
      },
      
      // Feature Policy / Permissions Policy
      permissionsPolicy: {
        features: {
          geolocation: ["'none'"],
          microphone: ["'none'"],
          camera: ["'none'"],
          payment: ["'none'"],
          usb: ["'none'"],
          magnetometer: ["'none'"],
          gyroscope: ["'none'"],
          speaker: ["'none'"],
          vibrate: ["'none'"],
          fullscreen: ["'self'"],
          syncXhr: ["'none'"]
        }
      },
      
      // Frame Options
      frameguard: {
        action: 'deny'
      },
      
      // Hide Powered-By
      hidePoweredBy: true,
      
      // HSTS (HTTP Strict Transport Security)
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      },
      
      // IE No Open
      ieNoOpen: true,
      
      // No Sniff
      noSniff: true,
      
      // Origin Agent Cluster
      originAgentCluster: true,
      
      // Referrer Policy
      referrerPolicy: {
        policy: "strict-origin-when-cross-origin"
      },
      
      // XSS Filter
      xssFilter: true
    });
  }

  /**
   * Enhanced CORS configuration with security considerations
   * @returns {Object} CORS configuration
   */
  getCorsConfig() {
    const { config } = require('../config/env');
    
    // Use environment-specific CORS origin
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
      : [config.cors.origin]; // Use config from env.js

    return {
      origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        // Check if origin is in allowed list
        if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
        
        // Log unauthorized CORS attempt
        this.securityService.logSecurityAction({
          action: 'cors_violation',
          metadata: {
            origin,
            allowedOrigins,
            timestamp: new Date().toISOString(),
            severity: 'medium'
          }
        });
        
        return callback(new Error('Not allowed by CORS'), false);
      },
      credentials: config.cors.credentials,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-Request-ID'
      ],
      exposedHeaders: [
        'X-Request-ID',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset'
      ],
      maxAge: 86400 // 24 hours
    };
  }

  /**
   * Response sanitization middleware
   * Ensures no sensitive data leaks in API responses
   */
  responseSanitizer = (req, res, next) => {
    const originalJson = res.json;
    const originalSend = res.send;

    // Override res.json to sanitize response data
    res.json = function(data) {
      const sanitizedData = this.sanitizeResponseData(data, req.path);
      return originalJson.call(this, sanitizedData);
    }.bind(this);

    // Override res.send to sanitize response data
    res.send = function(data) {
      if (typeof data === 'object') {
        const sanitizedData = this.sanitizeResponseData(data, req.path);
        return originalSend.call(this, sanitizedData);
      }
      return originalSend.call(this, data);
    }.bind(this);

    next();
  };

  /**
   * Sanitize response data to remove sensitive information
   * @param {*} data - Response data
   * @param {string} path - Request path for context
   * @returns {*} Sanitized data
   */
  sanitizeResponseData(data, path) {
    if (!data || typeof data !== 'object') {
      return data;
    }

    // Deep clone to avoid modifying original data
    const sanitized = JSON.parse(JSON.stringify(data));

    // Remove sensitive fields from any level of the response
    this.removeSensitiveFields(sanitized);

    // Add security headers to response metadata
    if (sanitized.success !== undefined) {
      sanitized.security = {
        sanitized: true,
        timestamp: new Date().toISOString()
      };
    }

    return sanitized;
  }

  /**
   * Recursively remove sensitive fields from response data
   * @param {Object} obj - Object to sanitize
   */
  removeSensitiveFields(obj) {
    if (!obj || typeof obj !== 'object') return;

    const sensitiveFields = [
      'password',
      'passwordHash',
      'newPassword',
      'currentPassword',
      'otp',
      'token', // Remove from nested objects, but allow in main response
      'secret',
      'key',
      'privateKey',
      'accessToken',
      'refreshToken'
    ];

    // Handle arrays
    if (Array.isArray(obj)) {
      obj.forEach(item => this.removeSensitiveFields(item));
      return;
    }

    // Handle objects
    Object.keys(obj).forEach(key => {
      if (sensitiveFields.includes(key.toLowerCase())) {
        // Special handling for token in main response (keep it)
        if (key === 'token' && obj.success !== undefined) {
          return; // Keep main response tokens
        }
        delete obj[key];
      } else if (typeof obj[key] === 'object') {
        this.removeSensitiveFields(obj[key]);
      }
    });
  }

  /**
   * Request/Response logging middleware for debugging and monitoring
   */
  requestResponseLogger = (req, res, next) => {
    const { config } = require('../config/env');
    const startTime = Date.now();
    
    // Log request details (non-sensitive)
    const requestLog = {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      contentType: req.get('Content-Type'),
      contentLength: req.get('Content-Length'),
      timestamp: new Date().toISOString()
    };

    // Use environment-specific logging configuration
    if (config.nodeEnv === 'development' || config.logging.enableRequestLogging) {
      console.log('Request:', JSON.stringify(requestLog, null, 2));
    }

    // Capture response details
    const originalJson = res.json;
    res.json = function(data) {
      const responseTime = Date.now() - startTime;
      
      const responseLog = {
        statusCode: res.statusCode,
        responseTime: `${responseTime}ms`,
        contentType: res.get('Content-Type'),
        timestamp: new Date().toISOString()
      };

      // Log response details (non-sensitive)
      if (config.nodeEnv === 'development' || config.logging.enableRequestLogging) {
        console.log('Response:', JSON.stringify(responseLog, null, 2));
      }

      // Log slow requests
      if (responseTime > 5000) { // > 5 seconds
        this.securityService.logSecurityAction({
          action: 'slow_request',
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          metadata: {
            ...requestLog,
            ...responseLog,
            severity: 'warning'
          }
        });
      }

      return originalJson.call(this, data);
    }.bind(this);

    next();
  };

  /**
   * Security headers middleware for additional protection
   */
  additionalSecurityHeaders = (req, res, next) => {
    const { config } = require('../config/env');
    
    // Add custom security headers
    res.setHeader('X-Request-ID', req.requestId || 'unknown');
    res.setHeader('X-API-Version', config.app.version);
    res.setHeader('X-Response-Time', Date.now());
    
    // Remove server information
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    
    // Add cache control for sensitive endpoints
    if (this.isSensitiveEndpoint(req.path)) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }

    next();
  };

  /**
   * Check if endpoint contains sensitive data
   * @param {string} path - Request path
   * @returns {boolean} True if sensitive endpoint
   */
  isSensitiveEndpoint(path) {
    const sensitivePatterns = [
      '/auth/',
      '/login',
      '/signup',
      '/password',
      '/otp',
      '/profile',
      '/user'
    ];
    
    return sensitivePatterns.some(pattern => path.includes(pattern));
  }

  /**
   * Input validation and sanitization middleware
   */
  inputSanitizer = (req, res, next) => {
    // Sanitize query parameters
    if (req.query) {
      Object.keys(req.query).forEach(key => {
        if (typeof req.query[key] === 'string') {
          req.query[key] = this.securityService.sanitizeInput(req.query[key]);
        }
      });
    }

    // Sanitize request body (but preserve structure for validation)
    if (req.body && typeof req.body === 'object') {
      this.sanitizeObjectInputs(req.body);
    }

    next();
  };

  /**
   * Recursively sanitize object inputs
   * @param {Object} obj - Object to sanitize
   */
  sanitizeObjectInputs(obj) {
    if (!obj || typeof obj !== 'object') return;

    Object.keys(obj).forEach(key => {
      if (typeof obj[key] === 'string') {
        // Don't sanitize password fields (they need to be validated as-is)
        if (!key.toLowerCase().includes('password') && !key.toLowerCase().includes('otp')) {
          obj[key] = this.securityService.sanitizeInput(obj[key], {
            removeHtml: true,
            removeScripts: true,
            removeSql: true,
            trimWhitespace: true,
            maxLength: 1000
          });
        }
      } else if (typeof obj[key] === 'object') {
        this.sanitizeObjectInputs(obj[key]);
      }
    });
  }

  /**
   * Rate limit headers middleware
   */
  rateLimitHeaders = (req, res, next) => {
    // Add rate limit information to response headers
    res.on('finish', () => {
      if (req.rateLimit) {
        res.setHeader('X-RateLimit-Limit', req.rateLimit.limit);
        res.setHeader('X-RateLimit-Remaining', req.rateLimit.remaining);
        res.setHeader('X-RateLimit-Reset', new Date(req.rateLimit.resetTime).toISOString());
      }
    });

    next();
  };
}

// Create singleton instance
const securityMiddleware = new SecurityMiddleware();

module.exports = {
  helmet: securityMiddleware.getHelmetConfig(),
  cors: securityMiddleware.getCorsConfig(),
  responseSanitizer: securityMiddleware.responseSanitizer,
  requestResponseLogger: securityMiddleware.requestResponseLogger,
  additionalSecurityHeaders: securityMiddleware.additionalSecurityHeaders,
  inputSanitizer: securityMiddleware.inputSanitizer,
  rateLimitHeaders: securityMiddleware.rateLimitHeaders
};