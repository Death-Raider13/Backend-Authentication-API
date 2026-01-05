const express = require('express');
const OTPController = require('../controllers/OTPController');
const { validate } = require('../middleware/validation');
const { otpRateLimit, generalRateLimit } = require('../middleware/rateLimiter');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const otpController = new OTPController();

/**
 * OTP Routes
 * All routes are prefixed with /auth (when mounted)
 */

/**
 * POST /auth/request-otp
 * Request OTP for verification
 * - Validates email and OTP type
 * - Applies OTP-specific rate limiting (3 requests per 15 minutes)
 * - Generates and sends OTP to user
 */
router.post('/request-otp',
  otpRateLimit,
  validate('requestOtp'),
  otpController.requestOTP.bind(otpController)
);

/**
 * POST /auth/verify-otp
 * Verify OTP code
 * - Validates email, OTP, and type
 * - Applies general rate limiting
 * - Verifies OTP and marks as used
 * - May return JWT token for login type OTPs
 */
router.post('/verify-otp',
  generalRateLimit,
  validate('verifyOtp'),
  otpController.verifyOTP.bind(otpController)
);

/**
 * POST /auth/resend-otp
 * Resend OTP with rate limiting
 * - Validates email and OTP type
 * - Applies OTP-specific rate limiting (3 requests per 15 minutes)
 * - Invalidates previous OTPs and generates new one
 */
router.post('/resend-otp',
  otpRateLimit,
  validate('resendOtp'),
  otpController.resendOTP.bind(otpController)
);

/**
 * POST /auth/check-otp
 * Check if user has valid OTP (utility endpoint)
 * - Validates email and OTP type
 * - Applies general rate limiting
 * - Returns whether user has valid unexpired OTP
 */
router.post('/check-otp',
  generalRateLimit,
  validate('requestOtp'), // Reuse requestOtp validation (email + type)
  otpController.checkValidOTP.bind(otpController)
);

/**
 * GET /auth/otp-stats
 * Get OTP statistics (protected endpoint for monitoring)
 * - Requires authentication
 * - Returns OTP usage statistics
 * - Useful for monitoring and admin purposes
 */
router.get('/otp-stats',
  authenticate,
  generalRateLimit,
  otpController.getOTPStatistics.bind(otpController)
);

module.exports = router;