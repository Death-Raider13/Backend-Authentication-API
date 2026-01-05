const express = require('express');
const PasswordController = require('../controllers/PasswordController');
const { validate } = require('../middleware/validation');
const { passwordResetRateLimit, generalRateLimit } = require('../middleware/rateLimiter');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const passwordController = new PasswordController();

/**
 * Password Management Routes
 * All routes are prefixed with /auth (when mounted)
 */

/**
 * POST /auth/forgot-password
 * Initiate password reset process
 * - Validates email format
 * - Applies password reset rate limiting (5 attempts per hour)
 * - Generates password reset OTP
 * - Includes security headers and audit logging
 */
router.post('/forgot-password',
  passwordResetRateLimit,
  validate('forgotPassword'),
  passwordController.forgotPassword.bind(passwordController)
);

/**
 * POST /auth/reset-password
 * Complete password reset with OTP
 * - Validates email, OTP, and new password
 * - Applies password reset rate limiting
 * - Verifies reset OTP and updates password
 * - Invalidates all existing JWT tokens
 * - Includes comprehensive audit logging
 */
router.post('/reset-password',
  passwordResetRateLimit,
  validate('resetPassword'),
  passwordController.resetPassword.bind(passwordController)
);

/**
 * POST /auth/change-password
 * Change password for authenticated users
 * - Requires valid JWT token (protected endpoint)
 * - Validates current and new passwords
 * - Applies general rate limiting
 * - Verifies current password before update
 * - Invalidates all existing JWT tokens
 */
router.post('/change-password',
  authenticate,
  generalRateLimit,
  passwordController.changePassword.bind(passwordController)
);

/**
 * POST /auth/validate-password
 * Validate password strength
 * - Validates password against security requirements
 * - Applies general rate limiting
 * - Returns password strength analysis
 * - Useful for client-side password validation feedback
 */
router.post('/validate-password',
  generalRateLimit,
  passwordController.validatePassword.bind(passwordController)
);

module.exports = router;