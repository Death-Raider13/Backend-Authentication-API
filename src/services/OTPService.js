const OTPVerification = require('../models/OTPVerification');
const AuditLog = require('../models/AuditLog');
const User = require('../models/User');

class OTPService {
  constructor() {
    this.otpExpirationMinutes = 10; // 10 minutes expiration
    this.maxOTPAttempts = 3; // Maximum OTP requests per time window
    this.rateLimitWindowMinutes = 15; // Rate limit window in minutes
  }

  /**
   * Generate and store OTP for user
   * @param {string} userId - User ID
   * @param {string} type - OTP type ('signup', 'login', 'reset')
   * @param {string} ipAddress - Client IP address
   * @param {string} userAgent - Client user agent
   * @returns {Promise<Object>} Generated OTP information
   */
  async generateOTP(userId, type, ipAddress, userAgent) {
    try {
      // Verify user exists
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Check rate limiting
      await this.checkRateLimit(userId, ipAddress);

      // Generate 6-digit OTP
      const otp = this.generateSixDigitOTP();

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + this.otpExpirationMinutes * 60 * 1000);

      // Invalidate any existing unused OTPs of the same type for this user
      await OTPVerification.updateMany(
        { userId, type, used: false },
        { used: true }
      );

      // Create new OTP record
      const otpRecord = new OTPVerification({
        userId,
        otp,
        type,
        expiresAt
      });

      await otpRecord.save();

      // Log OTP generation
      await AuditLog.logAction({
        userId,
        action: 'otp_requested',
        ipAddress,
        userAgent,
        metadata: {
          type,
          expiresAt: expiresAt.toISOString()
        }
      });

      return {
        otpId: otpRecord._id,
        otp, // In production, this would be sent via SMS/email, not returned
        type,
        expiresAt,
        expiresInMinutes: this.otpExpirationMinutes
      };
    } catch (error) {
      // Log failed OTP generation
      await AuditLog.logAction({
        userId,
        action: 'otp_failed',
        ipAddress,
        userAgent,
        metadata: {
          type,
          error: error.message,
          reason: 'generation_failed'
        }
      });
      throw error;
    }
  }

  /**
   * Verify OTP code
   * @param {string} userId - User ID
   * @param {string} otp - OTP code to verify
   * @param {string} type - OTP type ('signup', 'login', 'reset')
   * @param {string} ipAddress - Client IP address
   * @param {string} userAgent - Client user agent
   * @returns {Promise<Object>} Verification result
   */
  async verifyOTP(userId, otp, type, ipAddress, userAgent) {
    try {
      // Find valid OTP
      const otpRecord = await OTPVerification.findValidOTP(userId, otp, type);
      
      if (!otpRecord) {
        // Log failed verification
        await AuditLog.logAction({
          userId,
          action: 'otp_failed',
          ipAddress,
          userAgent,
          metadata: {
            type,
            reason: 'invalid_or_expired_otp'
          }
        });
        throw new Error('Invalid or expired OTP');
      }

      // Check if OTP is still valid (double-check)
      if (!otpRecord.isValid()) {
        await AuditLog.logAction({
          userId,
          action: 'otp_failed',
          ipAddress,
          userAgent,
          metadata: {
            type,
            reason: 'otp_expired'
          }
        });
        throw new Error('OTP has expired');
      }

      // Mark OTP as used
      await otpRecord.markAsUsed();

      // Log successful verification
      await AuditLog.logAction({
        userId,
        action: 'otp_verified',
        ipAddress,
        userAgent,
        metadata: {
          type,
          otpId: otpRecord._id.toString()
        }
      });

      return {
        success: true,
        otpId: otpRecord._id,
        type,
        verifiedAt: new Date()
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * Resend OTP (generates new OTP and invalidates old ones)
   * @param {string} userId - User ID
   * @param {string} type - OTP type
   * @param {string} ipAddress - Client IP address
   * @param {string} userAgent - Client user agent
   * @returns {Promise<Object>} New OTP information
   */
  async resendOTP(userId, type, ipAddress, userAgent) {
    // This uses the same logic as generateOTP, which already handles
    // invalidating existing OTPs and rate limiting
    return this.generateOTP(userId, type, ipAddress, userAgent);
  }

  /**
   * Check rate limiting for OTP requests
   * @param {string} userId - User ID
   * @param {string} ipAddress - Client IP address
   * @throws {Error} If rate limit is exceeded
   */
  async checkRateLimit(userId, ipAddress) {
    const timeWindow = this.rateLimitWindowMinutes * 60 * 1000;
    const since = new Date(Date.now() - timeWindow);

    // Count OTP requests in the time window for this user
    const userRequestCount = await OTPVerification.countDocuments({
      userId,
      createdAt: { $gte: since }
    });

    if (userRequestCount >= this.maxOTPAttempts) {
      // Log rate limit exceeded
      await AuditLog.logAction({
        userId,
        action: 'rate_limit_exceeded',
        ipAddress,
        metadata: {
          type: 'otp_requests',
          requestCount: userRequestCount,
          timeWindowMinutes: this.rateLimitWindowMinutes
        }
      });
      throw new Error(`Too many OTP requests. Please wait ${this.rateLimitWindowMinutes} minutes before requesting again.`);
    }

    // Also check IP-based rate limiting (additional security)
    const ipRequestCount = await AuditLog.countDocuments({
      action: 'otp_requested',
      ipAddress,
      createdAt: { $gte: since }
    });

    if (ipRequestCount >= this.maxOTPAttempts * 2) { // Allow more requests per IP than per user
      await AuditLog.logAction({
        action: 'rate_limit_exceeded',
        ipAddress,
        metadata: {
          type: 'otp_requests_ip',
          requestCount: ipRequestCount,
          timeWindowMinutes: this.rateLimitWindowMinutes
        }
      });
      throw new Error(`Too many OTP requests from this IP. Please wait ${this.rateLimitWindowMinutes} minutes.`);
    }
  }

  /**
   * Generate a 6-digit numeric OTP
   * @returns {string} 6-digit OTP
   */
  generateSixDigitOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * Clean up expired OTP records
   * This method should be called periodically (e.g., via cron job)
   * @returns {Promise<number>} Number of deleted records
   */
  async cleanupExpiredOTPs() {
    try {
      const result = await OTPVerification.cleanupExpired();
      
      // Log cleanup activity
      await AuditLog.logAction({
        action: 'otp_cleanup',
        metadata: {
          deletedCount: result.deletedCount,
          cleanupTime: new Date().toISOString()
        }
      });

      return result.deletedCount;
    } catch (error) {
      await AuditLog.logAction({
        action: 'otp_cleanup',
        metadata: {
          error: error.message,
          cleanupTime: new Date().toISOString()
        }
      });
      throw error;
    }
  }

  /**
   * Get OTP statistics for monitoring
   * @param {number} hours - Number of hours to look back (default: 24)
   * @returns {Promise<Object>} OTP statistics
   */
  async getOTPStatistics(hours = 24) {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    const [totalGenerated, totalVerified, totalExpired] = await Promise.all([
      OTPVerification.countDocuments({ createdAt: { $gte: since } }),
      OTPVerification.countDocuments({ 
        createdAt: { $gte: since },
        used: true 
      }),
      OTPVerification.countDocuments({ 
        createdAt: { $gte: since },
        used: false,
        expiresAt: { $lt: new Date() }
      })
    ]);

    return {
      timeWindow: `${hours} hours`,
      totalGenerated,
      totalVerified,
      totalExpired,
      verificationRate: totalGenerated > 0 ? (totalVerified / totalGenerated * 100).toFixed(2) + '%' : '0%'
    };
  }

  /**
   * Check if user has any valid OTPs of a specific type
   * @param {string} userId - User ID
   * @param {string} type - OTP type
   * @returns {Promise<boolean>} True if user has valid OTPs
   */
  async hasValidOTP(userId, type) {
    const validOTP = await OTPVerification.findOne({
      userId,
      type,
      used: false,
      expiresAt: { $gt: new Date() }
    });

    return !!validOTP;
  }
}

module.exports = OTPService;