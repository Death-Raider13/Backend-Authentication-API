const AuthService = require('../services/AuthService');

/**
 * Authentication middleware for JWT token validation
 * Validates JWT tokens and extracts user context for protected routes
 */
class AuthMiddleware {
  constructor() {
    this.authService = new AuthService();
  }

  /**
   * Middleware to authenticate JWT tokens
   * Extracts token from Authorization header and validates it
   * Adds user context to request object for downstream handlers
   */
  authenticate = async (req, res, next) => {
    try {
      // Extract token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'MISSING_TOKEN',
            message: 'Authorization header is required'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Check if header follows Bearer token format
      const tokenParts = authHeader.split(' ');
      if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_TOKEN_FORMAT',
            message: 'Authorization header must be in format: Bearer <token>'
          },
          timestamp: new Date().toISOString()
        });
      }

      const token = tokenParts[1];

      // Validate JWT token
      const decoded = await this.authService.validateJWTToken(token);

      // Add user context to request
      req.user = decoded.user;
      req.tokenPayload = decoded;

      next();
    } catch (error) {
      // Handle different types of token errors
      let errorCode = 'INVALID_TOKEN';
      let statusCode = 401;
      let message = 'Invalid or expired token';

      if (error.message.includes('expired')) {
        errorCode = 'TOKEN_EXPIRED';
        message = 'Token has expired';
      } else if (error.message.includes('user not found')) {
        errorCode = 'USER_NOT_FOUND';
        message = 'User associated with token not found';
      } else if (error.message.includes('inactive')) {
        errorCode = 'ACCOUNT_INACTIVE';
        message = 'User account is inactive';
      }

      return res.status(statusCode).json({
        success: false,
        error: {
          code: errorCode,
          message
        },
        timestamp: new Date().toISOString()
      });
    }
  };

  /**
   * Middleware to check if user is verified
   * Should be used after authenticate middleware
   */
  requireVerified = (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication required'
        },
        timestamp: new Date().toISOString()
      });
    }

    if (!req.user.isVerified) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'VERIFICATION_REQUIRED',
          message: 'Account verification required'
        },
        timestamp: new Date().toISOString()
      });
    }

    next();
  };

  /**
   * Middleware to check if user has active status
   * Should be used after authenticate middleware
   */
  requireActive = (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication required'
        },
        timestamp: new Date().toISOString()
      });
    }

    if (req.user.status !== 'active') {
      return res.status(403).json({
        success: false,
        error: {
          code: 'ACCOUNT_BLOCKED',
          message: 'Account is blocked or inactive'
        },
        timestamp: new Date().toISOString()
      });
    }

    next();
  };

  /**
   * Optional authentication middleware
   * Validates token if present but doesn't require it
   * Useful for endpoints that work for both authenticated and anonymous users
   */
  optionalAuth = async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        // No token provided, continue without user context
        return next();
      }

      const tokenParts = authHeader.split(' ');
      if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        // Invalid format, continue without user context
        return next();
      }

      const token = tokenParts[1];
      const decoded = await this.authService.validateJWTToken(token);

      // Add user context to request if token is valid
      req.user = decoded.user;
      req.tokenPayload = decoded;

      next();
    } catch (error) {
      // Token validation failed, continue without user context
      next();
    }
  };
}

// Create singleton instance
const authMiddleware = new AuthMiddleware();

module.exports = {
  authenticate: authMiddleware.authenticate,
  requireVerified: authMiddleware.requireVerified,
  requireActive: authMiddleware.requireActive,
  optionalAuth: authMiddleware.optionalAuth
};