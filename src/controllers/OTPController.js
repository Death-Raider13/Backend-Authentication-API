const OTPService = require('../services/OTPService');
const SecurityService = require('../services/SecurityService');
const User = require('../models/User');

class OTPController {
  constructor() {
    this.otpService = new OTPService();
    this.securityService = new SecurityService();
  }

  /**
   * Request OTP endpoint
   * POST /auth/request-otp
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async requestOTP(req, res) {
    try {
      const { email, type } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Validate email format
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

      // Find user by email
      const user = await User.findOne({ email: emailValidation.normalizedEmail });
      if (!user) {
        // For security, don't reveal if email exists or not
        return res.status(200).json({
          success: true,
          data: {
            message: 'If the email exists in our system, an OTP has been sent',
            type,
            expiresInMinutes: 10
          },
          timestamp: new Date().toISOString()
        });
      }

      // Check if user account is active
      if (user.status !== 'active') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'ACCOUNT_BLOCKED',
            message: 'Account is blocked. Please contact support'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generate OTP using OTPService
      const otpResult = await this.otpService.generateOTP(
        user._id,
        type,
        ipAddress,
        userAgent
      );

      // In production, the OTP would be sent via SMS/email service
      // For development/testing, we include it in the response
      const responseData = {
        message: 'OTP sent successfully',
        type: otpResult.type,
        expiresInMinutes: otpResult.expiresInMinutes,
        expiresAt: otpResult.expiresAt
      };

      // Include OTP in response only in development mode
      if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
        responseData.otp = otpResult.otp; // Only for testing purposes
      }

      res.status(200).json({
        success: true,
        data: responseData,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Request OTP error:', error);

      // Log failed OTP request with enhanced details
      await this.securityService.logAuthenticationFailure({
        email,
        ipAddress,
        userAgent,
        failureReason: error.message.includes('Too many OTP requests') ? 'rate_limit_exceeded' : 'otp_request_failed',
        requestId: req.requestId,
        endpoint: req.path,
        method: req.method,
        additionalMetadata: {
          otpType: type,
          attemptedEmail: emailValidation?.normalizedEmail,
          errorType: error.name
        }
      });

      // Handle rate limiting errors
      if (error.message.includes('Too many OTP requests')) {
        return res.status(429).json({
          success: false,
          error: {
            code: 'OTP_RATE_LIMIT_EXCEEDED',
            message: error.message
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generic server error
      res.status(500).json({
        success: false,
        error: {
          code: 'OTP_REQUEST_FAILED',
          message: 'Failed to process OTP request'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Verify OTP endpoint
   * POST /auth/verify-otp
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async verifyOTP(req, res) {
    try {
      const { email, otp, type } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Validate email format
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

      // Find user by email
      const user = await User.findOne({ email: emailValidation.normalizedEmail });
      if (!user) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Check if user account is active
      if (user.status !== 'active') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'ACCOUNT_BLOCKED',
            message: 'Account is blocked. Please contact support'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Verify OTP using OTPService
      const verificationResult = await this.otpService.verifyOTP(
        user._id,
        otp,
        type,
        ipAddress,
        userAgent
      );

      // Handle successful verification based on type
      let responseData = {
        message: 'OTP verified successfully',
        type: verificationResult.type,
        verifiedAt: verificationResult.verifiedAt
      };

      // For login type OTP, we might want to generate a JWT token
      if (type === 'login') {
        const AuthService = require('../services/AuthService');
        const authService = new AuthService();
        const token = authService.generateJWTToken(user);
        
        responseData.token = token;
        responseData.user = {
          _id: user._id,
          email: user.email,
          isVerified: user.isVerified,
          status: user.status
        };
      }

      // For signup type OTP, mark user as verified
      if (type === 'signup') {
        user.isVerified = true;
        await user.save();
        responseData.message = 'Email verified successfully';
      }

      res.status(200).json({
        success: true,
        data: responseData,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Verify OTP error:', error);

      // Log failed OTP verification with enhanced details
      await this.securityService.logAuthenticationFailure({
        email,
        ipAddress,
        userAgent,
        failureReason: error.message.includes('Invalid or expired OTP') ? 'invalid_otp' : 'otp_verification_failed',
        requestId: req.requestId,
        endpoint: req.path,
        method: req.method,
        additionalMetadata: {
          otpType: type,
          attemptedEmail: emailValidation?.normalizedEmail,
          providedOTP: otp ? '[REDACTED]' : 'missing',
          errorType: error.name
        }
      });

      // Handle specific OTP errors
      if (error.message.includes('Invalid or expired OTP') || error.message.includes('OTP has expired')) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_OTP',
            message: error.message
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generic server error
      res.status(500).json({
        success: false,
        error: {
          code: 'OTP_VERIFICATION_FAILED',
          message: 'Failed to verify OTP'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Resend OTP endpoint
   * POST /auth/resend-otp
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async resendOTP(req, res) {
    try {
      const { email, type } = req.body;
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Validate email format
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

      // Find user by email
      const user = await User.findOne({ email: emailValidation.normalizedEmail });
      if (!user) {
        // For security, don't reveal if email exists or not
        return res.status(200).json({
          success: true,
          data: {
            message: 'If the email exists in our system, a new OTP has been sent',
            type,
            expiresInMinutes: 10
          },
          timestamp: new Date().toISOString()
        });
      }

      // Check if user account is active
      if (user.status !== 'active') {
        return res.status(403).json({
          success: false,
          error: {
            code: 'ACCOUNT_BLOCKED',
            message: 'Account is blocked. Please contact support'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Resend OTP using OTPService (this will invalidate previous OTPs)
      const otpResult = await this.otpService.resendOTP(
        user._id,
        type,
        ipAddress,
        userAgent
      );

      // In production, the OTP would be sent via SMS/email service
      const responseData = {
        message: 'New OTP sent successfully',
        type: otpResult.type,
        expiresInMinutes: otpResult.expiresInMinutes,
        expiresAt: otpResult.expiresAt
      };

      // Include OTP in response only in development mode
      if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
        responseData.otp = otpResult.otp; // Only for testing purposes
      }

      res.status(200).json({
        success: true,
        data: responseData,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Resend OTP error:', error);

      // Handle rate limiting errors
      if (error.message.includes('Too many OTP requests')) {
        return res.status(429).json({
          success: false,
          error: {
            code: 'OTP_RATE_LIMIT_EXCEEDED',
            message: error.message
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generic server error
      res.status(500).json({
        success: false,
        error: {
          code: 'OTP_RESEND_FAILED',
          message: 'Failed to resend OTP'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Get OTP statistics endpoint (for monitoring/admin purposes)
   * GET /auth/otp-stats
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getOTPStatistics(req, res) {
    try {
      const hours = parseInt(req.query.hours) || 24;

      // Get OTP statistics from OTPService
      const stats = await this.otpService.getOTPStatistics(hours);

      res.status(200).json({
        success: true,
        data: {
          statistics: stats,
          message: 'OTP statistics retrieved successfully'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get OTP statistics error:', error);

      res.status(500).json({
        success: false,
        error: {
          code: 'STATS_FETCH_FAILED',
          message: 'Failed to retrieve OTP statistics'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Check if user has valid OTP endpoint
   * POST /auth/check-otp
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async checkValidOTP(req, res) {
    try {
      const { email, type } = req.body;

      // Validate email format
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

      // Find user by email
      const user = await User.findOne({ email: emailValidation.normalizedEmail });
      if (!user) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Check if user has valid OTP
      const hasValidOTP = await this.otpService.hasValidOTP(user._id, type);

      res.status(200).json({
        success: true,
        data: {
          hasValidOTP,
          type,
          message: hasValidOTP ? 'User has valid OTP' : 'No valid OTP found'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Check valid OTP error:', error);

      res.status(500).json({
        success: false,
        error: {
          code: 'OTP_CHECK_FAILED',
          message: 'Failed to check OTP status'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
}

module.exports = OTPController;