const jwt = require('jsonwebtoken');
const User = require('../models/User');
const UserProfile = require('../models/UserProfile');
const AuditLog = require('../models/AuditLog');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key';
    this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '24h';
  }

  /**
   * Register a new user with email and password
   * @param {Object} userData - User registration data
   * @param {string} userData.email - User email
   * @param {string} userData.password - User password
   * @param {string} userData.phone - User phone (optional)
   * @param {string} userData.displayName - Display name (optional)
   * @param {string} ipAddress - Client IP address
   * @param {string} userAgent - Client user agent
   * @returns {Promise<Object>} Created user and profile
   */
  async registerUser(userData, ipAddress, userAgent) {
    const { email, password, phone, displayName } = userData;

    try {
      // Check if user already exists
      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Create new user (password will be hashed by pre-save middleware)
      const user = new User({
        email: email.toLowerCase(),
        phone,
        passwordHash: password // Will be hashed by pre-save middleware
      });

      await user.save();

      // Create user profile
      const userProfile = new UserProfile({
        userId: user._id,
        displayName: displayName || email.split('@')[0]
      });

      await userProfile.save();

      // Log successful registration
      await AuditLog.logAction({
        userId: user._id,
        action: 'user_signup',
        ipAddress,
        userAgent,
        metadata: { email: user.email }
      });

      return {
        user: user.toJSON(),
        profile: userProfile
      };
    } catch (error) {
      // Log failed registration attempt
      await AuditLog.logAction({
        action: 'user_signup',
        ipAddress,
        userAgent,
        metadata: { 
          email: email.toLowerCase(),
          error: error.message 
        }
      });
      throw error;
    }
  }

  /**
   * Authenticate user with email and password
   * @param {string} email - User email
   * @param {string} password - User password
   * @param {string} ipAddress - Client IP address
   * @param {string} userAgent - Client user agent
   * @returns {Promise<Object>} User data and JWT token
   */
  async loginUser(email, password, ipAddress, userAgent) {
    try {
      // Find user by email
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        await AuditLog.logAction({
          action: 'user_login_failed',
          ipAddress,
          userAgent,
          metadata: { 
            email: email.toLowerCase(),
            reason: 'user_not_found'
          }
        });
        throw new Error('Invalid credentials');
      }

      // Check if user is active
      if (user.status !== 'active') {
        await AuditLog.logAction({
          userId: user._id,
          action: 'user_login_failed',
          ipAddress,
          userAgent,
          metadata: { 
            email: user.email,
            reason: 'account_blocked'
          }
        });
        throw new Error('Account is blocked');
      }

      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        await AuditLog.logAction({
          userId: user._id,
          action: 'user_login_failed',
          ipAddress,
          userAgent,
          metadata: { 
            email: user.email,
            reason: 'invalid_password'
          }
        });
        throw new Error('Invalid credentials');
      }

      // Update last login timestamp
      user.lastLoginAt = new Date();
      await user.save();

      // Generate JWT token
      const token = this.generateJWTToken(user);

      // Log successful login
      await AuditLog.logAction({
        userId: user._id,
        action: 'user_login_success',
        ipAddress,
        userAgent,
        metadata: { email: user.email }
      });

      return {
        user: user.toJSON(),
        token
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * Generate JWT token for user
   * @param {Object} user - User object
   * @returns {string} JWT token
   */
  generateJWTToken(user) {
    const payload = {
      userId: user._id,
      email: user.email,
      status: user.status,
      isVerified: user.isVerified,
      role: 'user' // Default role, can be extended later
    };

    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.jwtExpiresIn,
      issuer: 'auth-service',
      subject: user._id.toString()
    });
  }

  /**
   * Validate JWT token
   * @param {string} token - JWT token to validate
   * @returns {Promise<Object>} Decoded token payload
   */
  async validateJWTToken(token) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      
      // Check if user still exists and is active
      const user = await User.findById(decoded.userId);
      if (!user || user.status !== 'active') {
        throw new Error('Invalid token - user not found or inactive');
      }

      return {
        ...decoded,
        user: user.toJSON()
      };
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      } else if (error.name === 'TokenExpiredError') {
        throw new Error('Token expired');
      }
      throw error;
    }
  }

  /**
   * Check user status
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User status information
   */
  async checkUserStatus(userId) {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    return {
      userId: user._id,
      email: user.email,
      status: user.status,
      isVerified: user.isVerified,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt
    };
  }

  /**
   * Update user status (block/unblock)
   * @param {string} userId - User ID
   * @param {string} status - New status ('active' or 'blocked')
   * @param {string} ipAddress - Admin IP address
   * @param {string} userAgent - Admin user agent
   * @returns {Promise<Object>} Updated user
   */
  async updateUserStatus(userId, status, ipAddress, userAgent) {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const oldStatus = user.status;
    user.status = status;
    await user.save();

    // Log status change
    const action = status === 'blocked' ? 'account_blocked' : 'account_unblocked';
    await AuditLog.logAction({
      userId: user._id,
      action,
      ipAddress,
      userAgent,
      metadata: { 
        email: user.email,
        oldStatus,
        newStatus: status
      }
    });

    return user.toJSON();
  }

  /**
   * Invalidate all JWT tokens for a user (useful for password reset)
   * Note: This is a placeholder for token blacklisting functionality
   * In a production system, you'd maintain a blacklist or use token versioning
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} Success status
   */
  async invalidateUserTokens(userId) {
    // In a real implementation, you would:
    // 1. Add tokens to a blacklist with expiration
    // 2. Or increment a token version in the user record
    // 3. Or use a distributed cache like Redis
    
    // For now, we'll just log the action
    await AuditLog.logAction({
      userId,
      action: 'user_logout',
      metadata: { reason: 'tokens_invalidated' }
    });

    return true;
  }
}

module.exports = AuthService;