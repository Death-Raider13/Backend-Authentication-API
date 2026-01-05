const AuditLog = require('../models/AuditLog');

class SecurityService {
  constructor() {
    // Password strength requirements
    this.passwordRequirements = {
      minLength: 8,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} Validation result with details
   */
  validatePasswordStrength(password) {
    const errors = [];
    const warnings = [];

    // Check if password exists
    if (!password) {
      return {
        isValid: false,
        errors: ['Password is required'],
        warnings: [],
        score: 0
      };
    }

    // Length checks
    if (password.length < this.passwordRequirements.minLength) {
      errors.push(`Password must be at least ${this.passwordRequirements.minLength} characters long`);
    }
    if (password.length > this.passwordRequirements.maxLength) {
      errors.push(`Password must not exceed ${this.passwordRequirements.maxLength} characters`);
    }

    // Character type checks
    if (this.passwordRequirements.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (this.passwordRequirements.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (this.passwordRequirements.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    if (this.passwordRequirements.requireSpecialChars) {
      const specialCharRegex = new RegExp(`[${this.escapeRegExp(this.passwordRequirements.specialChars)}]`);
      if (!specialCharRegex.test(password)) {
        errors.push('Password must contain at least one special character');
      }
    }

    // Common password patterns to avoid
    const commonPatterns = [
      /(.)\1{2,}/, // Repeated characters (aaa, 111)
      /123456|654321|abcdef|qwerty|password/i, // Common sequences
      /^[a-zA-Z]+$/, // Only letters
      /^\d+$/ // Only numbers
    ];

    commonPatterns.forEach(pattern => {
      if (pattern.test(password)) {
        warnings.push('Password contains common patterns that make it easier to guess');
      }
    });

    // Calculate password strength score (0-100)
    let score = 0;
    if (password.length >= 8) score += 25;
    if (password.length >= 12) score += 10;
    if (/[A-Z]/.test(password)) score += 15;
    if (/[a-z]/.test(password)) score += 15;
    if (/\d/.test(password)) score += 15;
    if (new RegExp(`[${this.escapeRegExp(this.passwordRequirements.specialChars)}]`).test(password)) score += 20;

    // Deduct points for common patterns
    if (warnings.length > 0) score -= 10;

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      score: Math.max(0, Math.min(100, score)),
      strength: this.getPasswordStrengthLabel(score)
    };
  }

  /**
   * Get password strength label based on score
   * @param {number} score - Password strength score (0-100)
   * @returns {string} Strength label
   */
  getPasswordStrengthLabel(score) {
    if (score >= 80) return 'Very Strong';
    if (score >= 60) return 'Strong';
    if (score >= 40) return 'Moderate';
    if (score >= 20) return 'Weak';
    return 'Very Weak';
  }

  /**
   * Sanitize input to prevent injection attacks
   * @param {string} input - Input string to sanitize
   * @param {Object} options - Sanitization options
   * @returns {string} Sanitized input
   */
  sanitizeInput(input, options = {}) {
    if (typeof input !== 'string') {
      return input;
    }

    let sanitized = input;

    // Default sanitization options
    const defaultOptions = {
      removeHtml: true,
      removeScripts: true,
      removeSql: true,
      trimWhitespace: true,
      maxLength: 1000
    };

    const opts = { ...defaultOptions, ...options };

    // Trim whitespace
    if (opts.trimWhitespace) {
      sanitized = sanitized.trim();
    }

    // Remove HTML tags
    if (opts.removeHtml) {
      sanitized = sanitized.replace(/<[^>]*>/g, '');
    }

    // Remove script tags and javascript
    if (opts.removeScripts) {
      sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
      sanitized = sanitized.replace(/javascript:/gi, '');
      sanitized = sanitized.replace(/on\w+\s*=/gi, '');
    }

    // Remove common SQL injection patterns
    if (opts.removeSql) {
      const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
        /(--|\/\*|\*\/|;)/g,
        /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi
      ];
      
      sqlPatterns.forEach(pattern => {
        sanitized = sanitized.replace(pattern, '');
      });
    }

    // Limit length
    if (opts.maxLength && sanitized.length > opts.maxLength) {
      sanitized = sanitized.substring(0, opts.maxLength);
    }

    // Encode special characters
    sanitized = sanitized
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');

    return sanitized;
  }

  /**
   * Log security-relevant actions with enhanced metadata
   * @param {Object} actionData - Action data to log
   * @returns {Promise<Object>} Created audit log entry
   */
  async logSecurityAction(actionData) {
    const {
      userId,
      action,
      ipAddress,
      userAgent,
      metadata = {},
      severity = 'info',
      requestId,
      endpoint,
      method,
      statusCode,
      responseTime,
      requestSize,
      responseSize
    } = actionData;

    // Add comprehensive security metadata
    const securityMetadata = {
      ...metadata,
      severity,
      timestamp: new Date().toISOString(),
      source: 'SecurityService',
      requestId,
      endpoint,
      method,
      statusCode,
      responseTime,
      requestSize,
      responseSize,
      // Add geolocation info if available
      ...(ipAddress && { ipHash: this.hashForLogging(ipAddress) }),
      // Add user agent analysis
      ...(userAgent && { 
        userAgentHash: this.hashForLogging(userAgent),
        userAgentInfo: this.parseUserAgent(userAgent)
      })
    };

    return AuditLog.logAction({
      userId,
      action,
      ipAddress,
      userAgent,
      metadata: securityMetadata
    });
  }

  /**
   * Log authentication events with detailed context
   * @param {Object} eventData - Authentication event data
   * @returns {Promise<Object>} Created audit log entry
   */
  async logAuthenticationEvent(eventData) {
    const {
      userId,
      email,
      action,
      success,
      ipAddress,
      userAgent,
      requestId,
      endpoint,
      method,
      failureReason,
      additionalMetadata = {}
    } = eventData;

    const metadata = {
      ...additionalMetadata,
      email: email ? this.hashForLogging(email) : undefined,
      success,
      failureReason,
      timestamp: new Date().toISOString(),
      source: 'AuthenticationEvent',
      requestId,
      endpoint,
      method,
      // Security analysis
      suspiciousActivity: await this.detectSuspiciousActivity(ipAddress, action, success),
      // Rate limiting context
      rateLimitStatus: await this.getRateLimitStatus(ipAddress, userId)
    };

    return this.logSecurityAction({
      userId,
      action,
      ipAddress,
      userAgent,
      metadata,
      severity: success ? 'info' : 'warning',
      requestId,
      endpoint,
      method
    });
  }

  /**
   * Log failed authentication attempts with enhanced analysis
   * @param {Object} failureData - Failure data
   * @returns {Promise<Object>} Created audit log entry
   */
  async logAuthenticationFailure(failureData) {
    const {
      email,
      ipAddress,
      userAgent,
      failureReason,
      requestId,
      endpoint,
      method,
      additionalMetadata = {}
    } = failureData;

    // Analyze failure patterns
    const failureAnalysis = await this.analyzeFailurePatterns(ipAddress, email);
    
    const metadata = {
      ...additionalMetadata,
      email: email ? this.hashForLogging(email) : undefined,
      failureReason,
      failureAnalysis,
      timestamp: new Date().toISOString(),
      source: 'AuthenticationFailure',
      requestId,
      endpoint,
      method,
      // Enhanced security context
      consecutiveFailures: failureAnalysis.consecutiveFailures,
      timeToNextAttempt: failureAnalysis.timeToNextAttempt,
      riskScore: failureAnalysis.riskScore
    };

    return this.logSecurityAction({
      action: 'user_login_failed',
      ipAddress,
      userAgent,
      metadata,
      severity: failureAnalysis.riskScore > 70 ? 'critical' : 'warning',
      requestId,
      endpoint,
      method
    });
  }

  /**
   * Detect suspicious activity patterns
   * @param {string} ipAddress - IP address to analyze
   * @param {string} action - Action being performed
   * @param {boolean} success - Whether the action was successful
   * @returns {Promise<Object>} Suspicion analysis
   */
  async detectSuspiciousActivity(ipAddress, action, success) {
    if (!ipAddress) return { suspicious: false, reasons: [] };

    const timeWindow = 60 * 60 * 1000; // 1 hour
    const since = new Date(Date.now() - timeWindow);

    const [recentFailures, recentActions, ipAnalysis] = await Promise.all([
      AuditLog.countDocuments({
        ipAddress,
        action: { $in: ['user_login_failed', 'otp_failed'] },
        createdAt: { $gte: since }
      }),
      AuditLog.countDocuments({
        ipAddress,
        createdAt: { $gte: since }
      }),
      this.analyzeIPSuspicion(ipAddress, 1)
    ]);

    const reasons = [];
    let suspicious = false;

    // High failure rate
    if (recentFailures > 10) {
      suspicious = true;
      reasons.push('high_failure_rate');
    }

    // High activity volume
    if (recentActions > 100) {
      suspicious = true;
      reasons.push('high_activity_volume');
    }

    // IP already flagged as suspicious
    if (ipAnalysis.isSuspicious) {
      suspicious = true;
      reasons.push('ip_flagged_suspicious');
    }

    return {
      suspicious,
      reasons,
      recentFailures,
      recentActions,
      riskLevel: ipAnalysis.riskLevel
    };
  }

  /**
   * Get current rate limit status for IP/user
   * @param {string} ipAddress - IP address
   * @param {string} userId - User ID (optional)
   * @returns {Promise<Object>} Rate limit status
   */
  async getRateLimitStatus(ipAddress, userId) {
    const timeWindow = 15 * 60 * 1000; // 15 minutes
    const since = new Date(Date.now() - timeWindow);

    const [ipRequests, userRequests] = await Promise.all([
      AuditLog.countDocuments({
        ipAddress,
        createdAt: { $gte: since }
      }),
      userId ? AuditLog.countDocuments({
        userId,
        createdAt: { $gte: since }
      }) : Promise.resolve(0)
    ]);

    return {
      ipRequests,
      userRequests,
      timeWindow: '15 minutes',
      ipLimitApproaching: ipRequests > 80, // 80% of typical 100 request limit
      userLimitApproaching: userRequests > 16 // 80% of typical 20 request limit
    };
  }

  /**
   * Analyze failure patterns for an IP/email combination
   * @param {string} ipAddress - IP address
   * @param {string} email - Email address (optional)
   * @returns {Promise<Object>} Failure analysis
   */
  async analyzeFailurePatterns(ipAddress, email) {
    const timeWindow = 60 * 60 * 1000; // 1 hour
    const since = new Date(Date.now() - timeWindow);

    const query = {
      action: { $in: ['user_login_failed', 'otp_failed'] },
      createdAt: { $gte: since }
    };

    // Add IP filter
    if (ipAddress) query.ipAddress = ipAddress;

    // Add email filter if provided
    if (email) {
      query['metadata.email'] = this.hashForLogging(email);
    }

    const failures = await AuditLog.find(query)
      .sort({ createdAt: -1 })
      .limit(50);

    const consecutiveFailures = failures.length;
    const timeSpan = failures.length > 1 ? 
      failures[0].createdAt - failures[failures.length - 1].createdAt : 0;

    // Calculate risk score based on patterns
    let riskScore = 0;
    if (consecutiveFailures > 5) riskScore += 30;
    if (consecutiveFailures > 10) riskScore += 40;
    if (timeSpan < 5 * 60 * 1000 && consecutiveFailures > 3) riskScore += 30; // Fast attempts

    return {
      consecutiveFailures,
      timeSpan,
      riskScore: Math.min(100, riskScore),
      timeToNextAttempt: this.calculateBackoffTime(consecutiveFailures),
      pattern: this.identifyAttackPattern(failures)
    };
  }

  /**
   * Calculate exponential backoff time for failed attempts
   * @param {number} failureCount - Number of consecutive failures
   * @returns {number} Backoff time in milliseconds
   */
  calculateBackoffTime(failureCount) {
    if (failureCount <= 3) return 0;
    return Math.min(Math.pow(2, failureCount - 3) * 1000, 30 * 60 * 1000); // Max 30 minutes
  }

  /**
   * Identify potential attack patterns from failure data
   * @param {Array} failures - Array of failure records
   * @returns {string} Identified pattern
   */
  identifyAttackPattern(failures) {
    if (failures.length < 3) return 'none';

    const timeIntervals = [];
    for (let i = 1; i < failures.length; i++) {
      timeIntervals.push(failures[i-1].createdAt - failures[i].createdAt);
    }

    const avgInterval = timeIntervals.reduce((a, b) => a + b, 0) / timeIntervals.length;

    if (avgInterval < 1000) return 'rapid_fire'; // Less than 1 second between attempts
    if (avgInterval < 10000) return 'brute_force'; // Less than 10 seconds
    if (avgInterval > 300000) return 'slow_scan'; // More than 5 minutes
    return 'systematic'; // Regular intervals
  }

  /**
   * Parse user agent string for basic information
   * @param {string} userAgent - User agent string
   * @returns {Object} Parsed user agent info
   */
  parseUserAgent(userAgent) {
    if (!userAgent) return {};

    const info = {
      isMobile: /Mobile|Android|iPhone|iPad/.test(userAgent),
      isBot: /bot|crawler|spider|scraper/i.test(userAgent),
      browser: 'unknown',
      os: 'unknown'
    };

    // Basic browser detection
    if (userAgent.includes('Chrome')) info.browser = 'Chrome';
    else if (userAgent.includes('Firefox')) info.browser = 'Firefox';
    else if (userAgent.includes('Safari')) info.browser = 'Safari';
    else if (userAgent.includes('Edge')) info.browser = 'Edge';

    // Basic OS detection
    if (userAgent.includes('Windows')) info.os = 'Windows';
    else if (userAgent.includes('Mac')) info.os = 'macOS';
    else if (userAgent.includes('Linux')) info.os = 'Linux';
    else if (userAgent.includes('Android')) info.os = 'Android';
    else if (userAgent.includes('iOS')) info.os = 'iOS';

    return info;
  }

  /**
   * Get security headers for HTTP responses
   * @returns {Object} Security headers
   */
  getSecurityHeaders() {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    };
  }

  /**
   * Validate email format
   * @param {string} email - Email to validate
   * @returns {Object} Validation result
   */
  validateEmail(email) {
    if (!email || typeof email !== 'string') {
      return {
        isValid: false,
        error: 'Email is required'
      };
    }

    // Basic email regex (more permissive than the model validation)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    // More comprehensive email validation
    const isValidFormat = emailRegex.test(email);
    const isValidLength = email.length <= 254; // RFC 5321 limit
    const hasValidLocalPart = email.split('@')[0]?.length <= 64; // RFC 5321 limit

    if (!isValidFormat) {
      return {
        isValid: false,
        error: 'Invalid email format'
      };
    }

    if (!isValidLength) {
      return {
        isValid: false,
        error: 'Email address is too long'
      };
    }

    if (!hasValidLocalPart) {
      return {
        isValid: false,
        error: 'Email local part is too long'
      };
    }

    return {
      isValid: true,
      normalizedEmail: email.toLowerCase().trim()
    };
  }

  /**
   * Check if IP address is suspicious based on recent activity
   * @param {string} ipAddress - IP address to check
   * @param {number} timeWindowHours - Time window to check (default: 1 hour)
   * @returns {Promise<Object>} Suspicion analysis
   */
  async analyzeIPSuspicion(ipAddress, timeWindowHours = 1) {
    const since = new Date(Date.now() - timeWindowHours * 60 * 60 * 1000);

    // Get recent failed attempts from this IP
    const failedAttempts = await AuditLog.countDocuments({
      ipAddress,
      action: { $in: ['user_login_failed', 'otp_failed'] },
      createdAt: { $gte: since }
    });

    // Get rate limit violations
    const rateLimitViolations = await AuditLog.countDocuments({
      ipAddress,
      action: 'rate_limit_exceeded',
      createdAt: { $gte: since }
    });

    // Calculate suspicion score
    let suspicionScore = 0;
    if (failedAttempts > 5) suspicionScore += 30;
    if (failedAttempts > 10) suspicionScore += 40;
    if (rateLimitViolations > 0) suspicionScore += 20;
    if (rateLimitViolations > 3) suspicionScore += 30;

    const isSuspicious = suspicionScore >= 50;

    return {
      ipAddress,
      timeWindow: `${timeWindowHours} hour(s)`,
      failedAttempts,
      rateLimitViolations,
      suspicionScore,
      isSuspicious,
      riskLevel: this.getRiskLevel(suspicionScore)
    };
  }

  /**
   * Get risk level based on suspicion score
   * @param {number} score - Suspicion score
   * @returns {string} Risk level
   */
  getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Minimal';
  }

  /**
   * Escape special characters for regex
   * @param {string} string - String to escape
   * @returns {string} Escaped string
   */
  escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Generate secure random string
   * @param {number} length - Length of random string
   * @param {string} charset - Character set to use
   * @returns {string} Random string
   */
  generateSecureRandom(length = 32, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
    let result = '';
    for (let i = 0; i < length; i++) {
      result += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return result;
  }

  /**
   * Hash sensitive data for logging (one-way hash for privacy)
   * @param {string} data - Data to hash
   * @returns {string} Hashed data
   */
  hashForLogging(data) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }
}

module.exports = SecurityService;