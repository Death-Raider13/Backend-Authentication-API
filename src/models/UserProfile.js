const mongoose = require('mongoose');

const userProfileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  displayName: {
    type: String,
    trim: true,
    maxlength: [100, 'Display name cannot exceed 100 characters']
  },
  avatarUrl: {
    type: String,
    trim: true,
    validate: {
      validator: function(url) {
        return !url || /^https?:\/\/.+\.(jpg|jpeg|png|gif|webp)$/i.test(url);
      },
      message: 'Avatar URL must be a valid image URL'
    }
  },
  preferences: {
    notifications: {
      type: Boolean,
      default: true
    },
    theme: {
      type: String,
      enum: {
        values: ['light', 'dark', 'auto'],
        message: 'Theme must be light, dark, or auto'
      },
      default: 'auto'
    },
    language: {
      type: String,
      enum: {
        values: ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko'],
        message: 'Language must be a supported language code'
      },
      default: 'en'
    }
  }
}, {
  timestamps: { createdAt: true, updatedAt: true }
});

// Index for userId for performance
userProfileSchema.index({ userId: 1 }, { unique: true });

// Populate user data when querying
userProfileSchema.methods.populateUser = function() {
  return this.populate('userId', 'email isVerified status lastLoginAt createdAt');
};

const UserProfile = mongoose.model('UserProfile', userProfileSchema);

module.exports = UserProfile;