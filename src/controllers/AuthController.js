const AuthService = require('../services/AuthService');
const SecurityService = require('../services/SecurityService');

class AuthController {
  constructor() {
    this.authService = new AuthService();
    this.securityService = new SecurityService();
  }

  /**
   * User registration endpoint
   * POST /auth/signup
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async signup(req, res) {
    try {
      const { email, password, phone, displayName } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Additional password strength validation
      const passwordValidation = this.securityService.validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'WEAK_PASSWORD',
            message: 'Password does not meet security requirements',
            details: {
              errors: passwordValidation.errors,
              warnings: passwordValidation.warnings,
              strength: passwordValidation.strength
            }
          },
          timestamp: new Date().toISOString()
        });
      }

      // Additional email validation
      const emailValidation = this.securityService.validateEmail(email);
      if (!emailValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_EMAIL',
            message: emailValidation.error
          },
          timestamp: new Date().toISOString()
        });
      }

      // Register user with AuthService
      const result = await this.authService.registerUser({
        email: emailValidation.normalizedEmail,
        password,
        phone,
        displayName
      }, ipAddress, userAgent);

      // Generate JWT token for immediate login after registration
      const token = this.authService.generateJWTToken(result.user);

      // Remove sensitive data from response
      const userResponse = { ...result.user };
      delete userResponse.passwordHash;

      res.status(201).json({
        success: true,
        data: {
          user: userResponse,
          profile: result.profile,
          token,
          message: 'User registered successfully'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Signup error:', error);

      // Log failed registration attempt with enhanced details
      await this.securityService.logAuthenticationFailure({
        email,
        ipAddress,
        userAgent,
        failureReason: error.message.includes('already exists') ? 'email_already_exists' : 'registration_failed',
        requestId: req.requestId,
        endpoint: req.path,
        method: req.method,
        additionalMetadata: {
          attemptedEmail: emailValidation?.normalizedEmail,
          passwordStrength: passwordValidation?.strength,
          errorType: error.name
        }
      });

      // Handle specific error types
      if (error.message.includes('already exists')) {
        return res.status(409).json({
          success: false,
          error: {
            code: 'EMAIL_ALREADY_EXISTS',
            message: 'An account with this email already exists'
          },
          timestamp: new Date().toISOString()
        });
      }

      if (error.name === 'ValidationError') {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid input data',
            details: Object.values(error.errors).map(err => ({
              field: err.path,
              message: err.message
            }))
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generic server error
      res.status(500).json({
        success: false,
        error: {
          code: 'REGISTRATION_FAILED',
          message: 'Registration failed due to server error'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * User login endpoint
   * POST /auth/login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async login(req, res) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Additional email validation
      const emailValidation = this.securityService.validateEmail(email);
      if (!emailValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_EMAIL',
            message: emailValidation.error
          },
          timestamp: new Date().toISOString()
        });
      }

      // Authenticate user with AuthService
      const result = await this.authService.loginUser(
        emailValidation.normalizedEmail,
        password,
        ipAddress,
        userAgent
      );

      // Remove sensitive data from response
      const userResponse = { ...result.user };
      delete userResponse.passwordHash;

      res.status(200).json({
        success: true,
        data: {
          user: userResponse,
          token: result.token,
          message: 'Login successful'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Login error:', error);

      // Log failed login attempt with enhanced details
      await this.securityService.logAuthenticationFailure({
        email,
        ipAddress,
        userAgent,
        failureReason: error.message === 'Invalid credentials' ? 'invalid_credentials' : 
                      error.message === 'Account is blocked' ? 'account_blocked' : 'login_failed',
        requestId: req.requestId,
        endpoint: req.path,
        method: req.method,
        additionalMetadata: {
          attemptedEmail: emailValidation?.normalizedEmail,
          errorType: error.name
        }
      });

      // Handle specific error types
      if (error.message === 'Invalid credentials') {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password'
          },
          timestamp: new Date().toISOString()
        });
      }

      if (error.message === 'Account is blocked') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'ACCOUNT_BLOCKED',
            message: 'Your account has been blocked. Please contact support'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generic server error
      res.status(500).json({
        success: false,
        error: {
          code: 'LOGIN_FAILED',
          message: 'Login failed due to server error'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Get current user profile (protected endpoint)
   * GET /auth/profile
   * @param {Object} req - Express request object (with authenticated user)
   * @param {Object} res - Express response object
   */
  async getProfile(req, res) {
    try {
      // User information is available from auth middleware
      const user = req.user;

      // Get user status to ensure account is still active
      const userStatus = await this.authService.checkUserStatus(user._id);

      // Remove sensitive data
      const userResponse = { ...userStatus };
      delete userResponse.passwordHash;

      res.status(200).json({
        success: true,
        data: {
          user: userResponse,
          message: 'Profile retrieved successfully'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get profile error:', error);

      if (error.message === 'User not found') {
        return res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User account not found'
          },
          timestamp: new Date().toISOString()
        });
      }

      res.status(500).json({
        success: false,
        error: {
          code: 'PROFILE_FETCH_FAILED',
          message: 'Failed to retrieve user profile'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Logout endpoint (invalidate token)
   * POST /auth/logout
   * @param {Object} req - Express request object (with authenticated user)
   * @param {Object} res - Express response object
   */
  async logout(req, res) {
    try {
      const user = req.user;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Invalidate user tokens (in a real implementation, this would blacklist the token)
      await this.authService.invalidateUserTokens(user._id);

      // Log security action
      await this.securityService.logSecurityAction({
        userId: user._id,
        action: 'user_logout',
        ipAddress,
        userAgent,
        metadata: {
          email: user.email,
          logoutTime: new Date().toISOString()
        }
      });

      res.status(200).json({
        success: true,
        data: {
          message: 'Logout successful'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Logout error:', error);

      res.status(500).json({
        success: false,
        error: {
          code: 'LOGOUT_FAILED',
          message: 'Logout failed due to server error'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Verify JWT token endpoint
   * POST /auth/verify-token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async verifyToken(req, res) {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'TOKEN_REQUIRED',
            message: 'Token is required'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Validate token with AuthService
      const decoded = await this.authService.validateJWTToken(token);

      // Remove sensitive data
      const userResponse = { ...decoded.user };
      delete userResponse.passwordHash;

      res.status(200).json({
        success: true,
        data: {
          valid: true,
          user: userResponse,
          tokenData: {
            userId: decoded.userId,
            email: decoded.email,
            isVerified: decoded.isVerified,
            role: decoded.role,
            exp: decoded.exp,
            iat: decoded.iat
          },
          message: 'Token is valid'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Token verification error:', error);

      if (error.message.includes('Invalid token') || error.message.includes('Token expired')) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_TOKEN',
            message: error.message
          },
          timestamp: new Date().toISOString()
        });
      }

      res.status(500).json({
        success: false,
        error: {
          code: 'TOKEN_VERIFICATION_FAILED',
          message: 'Token verification failed due to server error'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
}

module.exports = AuthController;