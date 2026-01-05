const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // Some actions might not have a user (e.g., failed login attempts)
  },
  action: {
    type: String,
    required: [true, 'Action is required'],
    enum: {
      values: [
        'user_signup',
        'user_signup_failed',
        'user_login_success',
        'user_login_failed',
        'user_logout',
        'otp_requested',
        'otp_request_failed',
        'otp_verified',
        'otp_failed',
        'password_reset_requested',
        'password_reset_request_failed',
        'password_reset_completed',
        'password_reset_failed',
        'password_changed',
        'password_change_failed',
        'account_blocked',
        'account_unblocked',
        'rate_limit_exceeded',
        'request_initiated',
        'api_access',
        'api_access_failed',
        'security_event_detected',
        'cors_violation',
        'slow_request',
        'otp_cleanup'
      ],
      message: 'Invalid action type'
    }
  },
  ipAddress: {
    type: String,
    required: false,
    validate: {
      validator: function(ip) {
        if (!ip) return true;
        // Basic IPv4 and IPv6 validation (including IPv4-mapped IPv6)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        const ipv4MappedIpv6Regex = /^::ffff:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip) || ipv4MappedIpv6Regex.test(ip);
      },
      message: 'Invalid IP address format'
    }
  },
  userAgent: {
    type: String,
    required: false,
    maxlength: [500, 'User agent cannot exceed 500 characters']
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, {
  timestamps: { createdAt: true, updatedAt: false }
});

// Indexes for efficient querying
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ ipAddress: 1, createdAt: -1 });
auditLogSchema.index({ createdAt: -1 }); // For general time-based queries

// Static method to log an action
auditLogSchema.statics.logAction = function(actionData) {
  const {
    userId,
    action,
    ipAddress,
    userAgent,
    metadata = {}
  } = actionData;

  return this.create({
    userId,
    action,
    ipAddress,
    userAgent,
    metadata
  });
};

// Static method to get user activity
auditLogSchema.statics.getUserActivity = function(userId, limit = 50) {
  return this.find({ userId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .select('action ipAddress createdAt metadata');
};

// Static method to get failed login attempts
auditLogSchema.statics.getFailedLoginAttempts = function(ipAddress, timeWindow = 15 * 60 * 1000) {
  const since = new Date(Date.now() - timeWindow);
  return this.countDocuments({
    action: 'user_login_failed',
    ipAddress,
    createdAt: { $gte: since }
  });
};

// Static method to get security events
auditLogSchema.statics.getSecurityEvents = function(timeWindow = 24 * 60 * 60 * 1000) {
  const since = new Date(Date.now() - timeWindow);
  const securityActions = [
    'user_login_failed',
    'otp_failed',
    'rate_limit_exceeded',
    'account_blocked'
  ];
  
  return this.find({
    action: { $in: securityActions },
    createdAt: { $gte: since }
  }).sort({ createdAt: -1 });
};

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;