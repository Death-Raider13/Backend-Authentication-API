const OTPService = require('../services/OTPService');
const AuthService = require('../services/AuthService');
const SecurityService = require('../services/SecurityService');
const User = require('../models/User');

class PasswordController {
  constructor() {
    this.otpService = new OTPService();
    this.authService = new AuthService();
    this.securityService = new SecurityService();
  }

  /**
   * Forgot password endpoint - initiate password reset
   * POST /auth/forgot-password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async forgotPassword(req, res) {
    try {
      const { email } = req.body;
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
            message: 'If the email exists in our system, a password reset OTP has been sent',
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

      // Generate password reset OTP
      const otpResult = await this.otpService.generateOTP(
        user._id,
        'reset',
        ipAddress,
        userAgent
      );

      // Log security action
      await this.securityService.logSecurityAction({
        userId: user._id,
        action: 'password_reset_requested',
        ipAddress,
        userAgent,
        metadata: {
          email: user.email,
          otpId: otpResult.otpId
        }
      });

      // In production, the OTP would be sent via SMS/email service
      const responseData = {
        message: 'Password reset OTP sent successfully',
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
      console.error('Forgot password error:', error);

      // Handle rate limiting errors
      if (error.message.includes('Too many OTP requests')) {
        return res.status(429).json({
          success: false,
          error: {
            code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
            message: error.message
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generic server error
      res.status(500).json({
        success: false,
        error: {
          code: 'PASSWORD_RESET_REQUEST_FAILED',
          message: 'Failed to process password reset request'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Reset password endpoint - complete password reset with OTP
   * POST /auth/reset-password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async resetPassword(req, res) {
    try {
      const { email, otp, newPassword } = req.body;
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

      // Validate new password strength
      const passwordValidation = this.securityService.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'WEAK_PASSWORD',
            message: 'New password does not meet security requirements',
            details: {
              errors: passwordValidation.errors,
              warnings: passwordValidation.warnings,
              strength: passwordValidation.strength
            }
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

      // Verify the reset OTP
      const verificationResult = await this.otpService.verifyOTP(
        user._id,
        otp,
        'reset',
        ipAddress,
        userAgent
      );

      // Update user password (will be hashed by pre-save middleware)
      user.passwordHash = newPassword;
      await user.save();

      // Invalidate all existing JWT tokens for this user
      await this.authService.invalidateUserTokens(user._id);

      // Log successful password reset
      await this.securityService.logSecurityAction({
        userId: user._id,
        action: 'password_reset_completed',
        ipAddress,
        userAgent,
        metadata: {
          email: user.email,
          otpId: verificationResult.otpId,
          tokensInvalidated: true
        },
        severity: 'high'
      });

      res.status(200).json({
        success: true,
        data: {
          message: 'Password reset successfully. Please login with your new password',
          tokensInvalidated: true
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Reset password error:', error);

      // Log failed password reset with enhanced details
      await this.securityService.logAuthenticationFailure({
        email,
        ipAddress,
        userAgent,
        failureReason: error.message.includes('Invalid or expired OTP') ? 'invalid_reset_otp' : 'password_reset_failed',
        requestId: req.requestId,
        endpoint: req.path,
        method: req.method,
        additionalMetadata: {
          attemptedEmail: emailValidation?.normalizedEmail,
          providedOTP: otp ? '[REDACTED]' : 'missing',
          passwordStrength: passwordValidation?.strength,
          errorType: error.name
        }
      });

      // Handle specific OTP errors
      if (error.message.includes('Invalid or expired OTP') || error.message.includes('OTP has expired')) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_RESET_OTP',
            message: error.message
          },
          timestamp: new Date().toISOString()
        });
      }

      // Handle validation errors
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
          code: 'PASSWORD_RESET_FAILED',
          message: 'Failed to reset password'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Change password endpoint (for authenticated users)
   * POST /auth/change-password
   * @param {Object} req - Express request object (with authenticated user)
   * @param {Object} res - Express response object
   */
  async changePassword(req, res) {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = req.user; // From auth middleware
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Validate required fields
      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'MISSING_FIELDS',
            message: 'Current password and new password are required'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Validate new password strength
      const passwordValidation = this.securityService.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'WEAK_PASSWORD',
            message: 'New password does not meet security requirements',
            details: {
              errors: passwordValidation.errors,
              warnings: passwordValidation.warnings,
              strength: passwordValidation.strength
            }
          },
          timestamp: new Date().toISOString()
        });
      }

      // Get full user record from database
      const fullUser = await User.findById(user._id);
      if (!fullUser) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Verify current password
      const isCurrentPasswordValid = await fullUser.comparePassword(currentPassword);
      if (!isCurrentPasswordValid) {
        // Log failed password change attempt
        await this.securityService.logSecurityAction({
          userId: user._id,
          action: 'password_change_failed',
          ipAddress,
          userAgent,
          metadata: {
            email: user.email,
            reason: 'invalid_current_password'
          },
          severity: 'medium'
        });

        return res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_CURRENT_PASSWORD',
            message: 'Current password is incorrect'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Check if new password is different from current password
      const isSamePassword = await fullUser.comparePassword(newPassword);
      if (isSamePassword) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'SAME_PASSWORD',
            message: 'New password must be different from current password'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Update password (will be hashed by pre-save middleware)
      fullUser.passwordHash = newPassword;
      await fullUser.save();

      // Invalidate all existing JWT tokens for this user
      await this.authService.invalidateUserTokens(user._id);

      // Log successful password change
      await this.securityService.logSecurityAction({
        userId: user._id,
        action: 'password_changed',
        ipAddress,
        userAgent,
        metadata: {
          email: user.email,
          tokensInvalidated: true
        },
        severity: 'high'
      });

      res.status(200).json({
        success: true,
        data: {
          message: 'Password changed successfully. Please login with your new password',
          tokensInvalidated: true
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Change password error:', error);

      // Handle validation errors
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
          code: 'PASSWORD_CHANGE_FAILED',
          message: 'Failed to change password'
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Validate password strength endpoint
   * POST /auth/validate-password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async validatePassword(req, res) {
    try {
      const { password } = req.body;

      if (!password) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'PASSWORD_REQUIRED',
            message: 'Password is required'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Validate password strength
      const validation = this.securityService.validatePasswordStrength(password);

      res.status(200).json({
        success: true,
        data: {
          isValid: validation.isValid,
          strength: validation.strength,
          score: validation.score,
          errors: validation.errors,
          warnings: validation.warnings,
          message: validation.isValid ? 'Password meets security requirements' : 'Password does not meet security requirements'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Validate password error:', error);

      res.status(500).json({
        success: false,
        error: {
          code: 'PASSWORD_VALIDATION_FAILED',
          message: 'Failed to validate password'
        },
        timestamp: new Date().toISOString()
      });
    }
  }
}

module.exports = PasswordController;