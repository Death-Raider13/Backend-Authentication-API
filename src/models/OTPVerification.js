const mongoose = require('mongoose');

const otpVerificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  otp: {
    type: String,
    required: [true, 'OTP is required'],
    validate: {
      validator: function(otp) {
        return /^\d{6}$/.test(otp);
      },
      message: 'OTP must be exactly 6 digits'
    }
  },
  type: {
    type: String,
    enum: {
      values: ['signup', 'login', 'reset'],
      message: 'OTP type must be signup, login, or reset'
    },
    required: [true, 'OTP type is required']
  },
  expiresAt: {
    type: Date,
    required: [true, 'Expiration time is required'],
    default: function() {
      // Default to 10 minutes from now
      return new Date(Date.now() + 10 * 60 * 1000);
    }
  },
  used: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: { createdAt: true, updatedAt: false }
});

// Compound index for efficient queries
otpVerificationSchema.index({ userId: 1, type: 1, used: 1 });
otpVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index for automatic cleanup

// Instance method to check if OTP is valid
otpVerificationSchema.methods.isValid = function() {
  return !this.used && this.expiresAt > new Date();
};

// Instance method to mark OTP as used
otpVerificationSchema.methods.markAsUsed = async function() {
  this.used = true;
  return this.save();
};

// Static method to find valid OTP
otpVerificationSchema.statics.findValidOTP = function(userId, otp, type) {
  return this.findOne({
    userId,
    otp,
    type,
    used: false,
    expiresAt: { $gt: new Date() }
  });
};

// Static method to cleanup expired OTPs
otpVerificationSchema.statics.cleanupExpired = function() {
  return this.deleteMany({
    expiresAt: { $lt: new Date() }
  });
};

// Static method to generate 6-digit OTP
otpVerificationSchema.statics.generateOTP = function() {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const OTPVerification = mongoose.model('OTPVerification', otpVerificationSchema);

module.exports = OTPVerification;