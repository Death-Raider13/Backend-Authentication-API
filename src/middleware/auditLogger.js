const AuditLog = require('../models/AuditLog');
const SecurityService = require('../services/SecurityService');
const crypto = require('crypto');

/**
 * Comprehensive audit logging middleware
 * Logs all requests, responses, and security events for compliance and monitoring
 */
class AuditLoggerMiddleware {
  constructor() {
    this.securityService = new SecurityService();
    
    // Define sensitive endpoints that require enhanced logging
    this.sensitiveEndpoints = [
      '/auth/signup',
      '/auth/login',
      '/auth/logout',
      '/auth/forgot-password',
      '/auth/reset-password',
      '/auth/change-password',
      '/auth/request-otp',
      '/auth/verify-otp',
      '/auth/resend-otp'
    ];

    // Define endpoints that should not log request/response bodies
    this.excludeBodyLogging = [
      '/auth/signup',
      '/auth/login',
      '/auth/reset-password',
      '/auth/change-password'
    ];
  }

  /**
   * Main audit logging middleware
   * Captures comprehensive request/response data for security analysis
   */
  auditLogger = (req, res, next) => {
    const startTime = Date.now();
    const requestId = crypto.randomUUID();
    
    // Add request ID to request object for correlation
    req.requestId = requestId;
    
    // Extract request metadata
    const requestMetadata = this.extractRequestMetadata(req);
    
    // Store original res.json and res.send methods
    const originalJson = res.json;
    const originalSend = res.send;
    
    // Override res.json to capture response data
    res.json = function(data) {
      res.responseData = data;
      return originalJson.call(this, data);
    };
    
    // Override res.send to capture response data
    res.send = function(data) {
      res.responseData = data;
      return originalSend.call(this, data);
    };

    // Log request initiation for sensitive endpoints
    if (this.isSensitiveEndpoint(req.path)) {
      this.logRequestStart(requestMetadata, requestId);
    }

    // Capture response when request finishes
    res.on('finish', () => {
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      this.logRequestCompletion({
        ...requestMetadata,
        requestId,
        statusCode: res.statusCode,
        responseTime,
        responseData: res.responseData,
        responseSize: res.get('Content-Length') || 0
      });
    });

    next();
  };

  /**
   * Extract comprehensive metadata from request
   * @param {Object} req - Express request object
   * @returns {Object} Request metadata
   */
  extractRequestMetadata(req) {
    const ipAddress = this.getClientIP(req);
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    return {
      method: req.method,
      url: req.originalUrl,
      path: req.path,
      query: req.query,
      headers: this.sanitizeHeaders(req.headers),
      ipAddress,
      userAgent,
      userId: req.user?._id,
      userEmail: req.user?.email,
      timestamp: new Date().toISOString(),
      requestSize: req.get('Content-Length') || 0,
      contentType: req.get('Content-Type'),
      // Include request body for non-sensitive endpoints
      body: this.shouldLogBody(req.path) ? this.sanitizeRequestBody(req.body) : '[REDACTED]',
      // Security context
      isAuthenticated: !!req.user,
      authMethod: req.headers.authorization ? 'Bearer' : 'None',
      // Geographic and network info
      forwardedFor: req.get('X-Forwarded-For'),
      realIP: req.get('X-Real-IP'),
      // Session context
      sessionInfo: this.extractSessionInfo(req)
    };
  }

  /**
   * Get the real client IP address
   * @param {Object} req - Express request object
   * @returns {string} Client IP address
   */
  getClientIP(req) {
    return req.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
           req.get('X-Real-IP') ||
           req.connection.remoteAddress ||
           req.socket.remoteAddress ||
           req.ip ||
           'unknown';
  }

  /**
   * Sanitize request headers to remove sensitive information
   * @param {Object} headers - Request headers
   * @returns {Object} Sanitized headers
   */
  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    
    // Remove or mask sensitive headers
    if (sanitized.authorization) {
      sanitized.authorization = sanitized.authorization.startsWith('Bearer ') 
        ? 'Bearer [REDACTED]' 
        : '[REDACTED]';
    }
    
    if (sanitized.cookie) {
      sanitized.cookie = '[REDACTED]';
    }
    
    // Keep important headers for security analysis
    return {
      'user-agent': sanitized['user-agent'],
      'accept': sanitized['accept'],
      'accept-language': sanitized['accept-language'],
      'accept-encoding': sanitized['accept-encoding'],
      'content-type': sanitized['content-type'],
      'content-length': sanitized['content-length'],
      'x-forwarded-for': sanitized['x-forwarded-for'],
      'x-real-ip': sanitized['x-real-ip'],
      'authorization': sanitized.authorization,
      'referer': sanitized.referer,
      'origin': sanitized.origin
    };
  }

  /**
   * Sanitize request body to remove sensitive information
   * @param {Object} body - Request body
   * @returns {Object} Sanitized body
   */
  sanitizeRequestBody(body) {
    if (!body || typeof body !== 'object') return body;
    
    const sanitized = { ...body };
    
    // Remove sensitive fields
    const sensitiveFields = ['password', 'newPassword', 'currentPassword', 'otp'];
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }

  /**
   * Extract session information from request
   * @param {Object} req - Express request object
   * @returns {Object} Session information
   */
  extractSessionInfo(req) {
    return {
      hasValidToken: !!req.user,
      tokenPayload: req.tokenPayload ? {
        userId: req.tokenPayload.userId,
        email: req.tokenPayload.email,
        isVerified: req.tokenPayload.isVerified,
        role: req.tokenPayload.role,
        exp: req.tokenPayload.exp,
        iat: req.tokenPayload.iat
      } : null,
      userStatus: req.user?.status,
      userVerified: req.user?.isVerified
    };
  }

  /**
   * Check if endpoint is sensitive and requires enhanced logging
   * @param {string} path - Request path
   * @returns {boolean} True if sensitive endpoint
   */
  isSensitiveEndpoint(path) {
    return this.sensitiveEndpoints.some(endpoint => path.includes(endpoint));
  }

  /**
   * Check if request body should be logged
   * @param {string} path - Request path
   * @returns {boolean} True if body should be logged
   */
  shouldLogBody(path) {
    return !this.excludeBodyLogging.some(endpoint => path.includes(endpoint));
  }

  /**
   * Log request initiation for sensitive endpoints
   * @param {Object} metadata - Request metadata
   * @param {string} requestId - Request ID
   */
  async logRequestStart(metadata, requestId) {
    try {
      await AuditLog.logAction({
        userId: metadata.userId,
        action: 'request_initiated',
        ipAddress: metadata.ipAddress,
        userAgent: metadata.userAgent,
        metadata: {
          ...metadata,
          requestId,
          phase: 'start',
          source: 'AuditLoggerMiddleware'
        }
      });
    } catch (error) {
      console.error('Failed to log request start:', error);
    }
  }

  /**
   * Log request completion with comprehensive analysis
   * @param {Object} data - Complete request/response data
   */
  async logRequestCompletion(data) {
    try {
      const {
        requestId,
        method,
        path,
        statusCode,
        responseTime,
        ipAddress,
        userAgent,
        userId,
        userEmail,
        responseData
      } = data;

      // Determine log action based on endpoint and status
      const action = this.determineLogAction(path, method, statusCode);
      
      // Analyze response for security events
      const securityAnalysis = await this.analyzeResponseSecurity(data);
      
      // Enhanced metadata with security analysis
      const enhancedMetadata = {
        ...data,
        requestId,
        phase: 'completion',
        source: 'AuditLoggerMiddleware',
        securityAnalysis,
        // Performance metrics
        performanceMetrics: {
          responseTime,
          isSlowRequest: responseTime > 5000, // > 5 seconds
          isFastRequest: responseTime < 100   // < 100ms
        },
        // Response analysis
        responseAnalysis: {
          isError: statusCode >= 400,
          isServerError: statusCode >= 500,
          isClientError: statusCode >= 400 && statusCode < 500,
          isSuccess: statusCode >= 200 && statusCode < 300,
          hasResponseData: !!responseData
        }
      };

      // Log with appropriate severity
      const severity = this.determineSeverity(statusCode, securityAnalysis);
      
      await this.securityService.logSecurityAction({
        userId,
        action,
        ipAddress,
        userAgent,
        metadata: enhancedMetadata,
        severity,
        requestId,
        endpoint: path,
        method,
        statusCode,
        responseTime
      });

      // Log additional security events if detected
      if (securityAnalysis.suspiciousActivity) {
        await this.logSecurityEvent({
          userId,
          ipAddress,
          userAgent,
          requestId,
          securityAnalysis,
          endpoint: path,
          method
        });
      }

    } catch (error) {
      console.error('Failed to log request completion:', error);
    }
  }

  /**
   * Determine appropriate log action based on request characteristics
   * @param {string} path - Request path
   * @param {string} method - HTTP method
   * @param {number} statusCode - Response status code
   * @returns {string} Log action
   */
  determineLogAction(path, method, statusCode) {
    // Authentication endpoints
    if (path.includes('/login')) {
      return statusCode < 400 ? 'user_login_success' : 'user_login_failed';
    }
    if (path.includes('/signup')) {
      return statusCode < 400 ? 'user_signup' : 'user_signup_failed';
    }
    if (path.includes('/logout')) {
      return 'user_logout';
    }
    if (path.includes('/forgot-password')) {
      return statusCode < 400 ? 'password_reset_requested' : 'password_reset_request_failed';
    }
    if (path.includes('/reset-password')) {
      return statusCode < 400 ? 'password_reset_completed' : 'password_reset_failed';
    }
    if (path.includes('/change-password')) {
      return statusCode < 400 ? 'password_changed' : 'password_change_failed';
    }
    if (path.includes('/request-otp')) {
      return statusCode < 400 ? 'otp_requested' : 'otp_request_failed';
    }
    if (path.includes('/verify-otp')) {
      return statusCode < 400 ? 'otp_verified' : 'otp_failed';
    }
    if (path.includes('/resend-otp')) {
      return statusCode < 400 ? 'otp_requested' : 'otp_request_failed';
    }

    // Rate limiting
    if (statusCode === 429) {
      return 'rate_limit_exceeded';
    }

    // General API access
    return statusCode < 400 ? 'api_access' : 'api_access_failed';
  }

  /**
   * Analyze response for security implications
   * @param {Object} data - Request/response data
   * @returns {Promise<Object>} Security analysis
   */
  async analyzeResponseSecurity(data) {
    const { statusCode, responseTime, ipAddress, path, method, userId } = data;
    
    const analysis = {
      suspiciousActivity: false,
      riskFactors: [],
      riskScore: 0
    };

    // Analyze response patterns
    if (statusCode === 401 || statusCode === 403) {
      analysis.riskFactors.push('authentication_failure');
      analysis.riskScore += 20;
    }

    if (statusCode === 429) {
      analysis.riskFactors.push('rate_limit_exceeded');
      analysis.riskScore += 30;
      analysis.suspiciousActivity = true;
    }

    if (responseTime > 10000) { // > 10 seconds
      analysis.riskFactors.push('slow_response');
      analysis.riskScore += 10;
    }

    // Check for suspicious IP activity
    if (ipAddress) {
      const ipAnalysis = await this.securityService.analyzeIPSuspicion(ipAddress, 1);
      if (ipAnalysis.isSuspicious) {
        analysis.riskFactors.push('suspicious_ip');
        analysis.riskScore += ipAnalysis.suspicionScore;
        analysis.suspiciousActivity = true;
      }
    }

    // Check for brute force patterns
    if (path.includes('/login') && statusCode >= 400) {
      const recentFailures = await this.countRecentFailures(ipAddress, userId);
      if (recentFailures > 5) {
        analysis.riskFactors.push('potential_brute_force');
        analysis.riskScore += 40;
        analysis.suspiciousActivity = true;
      }
    }

    analysis.riskLevel = this.securityService.getRiskLevel(analysis.riskScore);
    
    return analysis;
  }

  /**
   * Count recent authentication failures for IP/user
   * @param {string} ipAddress - IP address
   * @param {string} userId - User ID (optional)
   * @returns {Promise<number>} Number of recent failures
   */
  async countRecentFailures(ipAddress, userId) {
    const timeWindow = 60 * 60 * 1000; // 1 hour
    const since = new Date(Date.now() - timeWindow);

    const query = {
      action: { $in: ['user_login_failed', 'otp_failed'] },
      createdAt: { $gte: since }
    };

    if (ipAddress) query.ipAddress = ipAddress;
    if (userId) query.userId = userId;

    return AuditLog.countDocuments(query);
  }

  /**
   * Determine log severity based on status code and security analysis
   * @param {number} statusCode - HTTP status code
   * @param {Object} securityAnalysis - Security analysis results
   * @returns {string} Severity level
   */
  determineSeverity(statusCode, securityAnalysis) {
    if (securityAnalysis.riskScore > 80) return 'critical';
    if (securityAnalysis.riskScore > 60) return 'high';
    if (statusCode >= 500) return 'high';
    if (statusCode === 429) return 'medium';
    if (statusCode >= 400) return 'warning';
    return 'info';
  }

  /**
   * Log specific security events
   * @param {Object} eventData - Security event data
   */
  async logSecurityEvent(eventData) {
    const {
      userId,
      ipAddress,
      userAgent,
      requestId,
      securityAnalysis,
      endpoint,
      method
    } = eventData;

    await this.securityService.logSecurityAction({
      userId,
      action: 'security_event_detected',
      ipAddress,
      userAgent,
      metadata: {
        requestId,
        endpoint,
        method,
        securityAnalysis,
        eventType: 'suspicious_activity',
        source: 'AuditLoggerMiddleware',
        timestamp: new Date().toISOString()
      },
      severity: 'high',
      requestId,
      endpoint,
      method
    });
  }

  /**
   * Middleware for logging authentication events specifically
   * Use this for authentication endpoints that need special handling
   */
  authEventLogger = (eventType) => {
    const self = this;
    return async (req, res, next) => {
      const originalJson = res.json;
      
      res.json = function(data) {
        // Log authentication event after response is sent
        setImmediate(async () => {
          try {
            const success = res.statusCode < 400;
            const failureReason = success ? null : data?.error?.code || 'unknown';
            
            await self.securityService.logAuthenticationEvent({
              userId: req.user?._id,
              email: req.body?.email,
              action: eventType,
              success,
              ipAddress: self.getClientIP(req),
              userAgent: req.get('User-Agent'),
              requestId: req.requestId,
              endpoint: req.path,
              method: req.method,
              failureReason,
              additionalMetadata: {
                statusCode: res.statusCode,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
              }
            });
          } catch (error) {
            console.error('Failed to log authentication event:', error);
          }
        });
        
        return originalJson.call(this, data);
      };
      
      next();
    };
  };
}

// Create singleton instance
const auditLoggerMiddleware = new AuditLoggerMiddleware();

module.exports = {
  auditLogger: auditLoggerMiddleware.auditLogger,
  authEventLogger: auditLoggerMiddleware.authEventLogger
};