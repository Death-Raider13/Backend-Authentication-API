const express = require('express');
const AuthController = require('../controllers/AuthController');
const { validate } = require('../middleware/validation');
const { authRateLimit, registrationRateLimit } = require('../middleware/rateLimiter');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
const authController = new AuthController();

/**
 * Authentication Routes
 * All routes are prefixed with /auth
 */

/**
 * POST /auth/signup
 * User registration endpoint
 * - Validates registration data
 * - Applies registration rate limiting
 * - Creates new user account and profile
 */
router.post('/signup', 
  registrationRateLimit,
  validate('register'),
  authController.signup.bind(authController)
);

/**
 * POST /auth/login
 * User login endpoint
 * - Validates login credentials
 * - Applies authentication rate limiting
 * - Returns JWT token on successful authentication
 */
router.post('/login',
  authRateLimit,
  validate('login'),
  authController.login.bind(authController)
);

/**
 * GET /auth/profile
 * Get current user profile (protected endpoint)
 * - Requires valid JWT token
 * - Returns user profile information
 */
router.get('/profile',
  authenticate,
  authController.getProfile.bind(authController)
);

/**
 * POST /auth/logout
 * User logout endpoint (protected)
 * - Requires valid JWT token
 * - Invalidates user tokens
 * - Logs security action
 */
router.post('/logout',
  authenticate,
  authController.logout.bind(authController)
);

/**
 * POST /auth/verify-token
 * JWT token verification endpoint
 * - Validates provided JWT token
 * - Returns token validity and user information
 */
router.post('/verify-token',
  authRateLimit,
  authController.verifyToken.bind(authController)
);

module.exports = router;