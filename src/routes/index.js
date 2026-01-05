const express = require('express');
const authRoutes = require('./auth');
const otpRoutes = require('./otp');
const passwordRoutes = require('./password');
const { generalRateLimit } = require('../middleware/rateLimiter');

const router = express.Router();

/**
 * Main Routes Configuration
 * Mounts all authentication-related routes under /auth prefix
 */

// Apply general rate limiting to all routes
router.use(generalRateLimit);

// Mount authentication routes
router.use('/auth', authRoutes);

// Mount OTP routes under /auth prefix
router.use('/auth', otpRoutes);

// Mount password management routes under /auth prefix
router.use('/auth', passwordRoutes);

// API information endpoint
router.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      service: 'Backend Authentication Service',
      version: '1.0.0',
      endpoints: {
        authentication: [
          'POST /auth/signup',
          'POST /auth/login',
          'GET /auth/profile',
          'POST /auth/logout',
          'POST /auth/verify-token'
        ],
        otp: [
          'POST /auth/request-otp',
          'POST /auth/verify-otp',
          'POST /auth/resend-otp',
          'POST /auth/check-otp',
          'GET /auth/otp-stats'
        ],
        password: [
          'POST /auth/forgot-password',
          'POST /auth/reset-password',
          'POST /auth/change-password',
          'POST /auth/validate-password'
        ]
      },
      documentation: 'See API documentation for detailed endpoint specifications'
    },
    timestamp: new Date().toISOString()
  });
});

module.exports = router;