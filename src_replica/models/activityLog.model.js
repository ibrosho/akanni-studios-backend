const mongoose = require('mongoose');

/**
 * @schema ActivityLogSchema
 * @description Stores records of security and profile activities performed by users.
 * Helps audit key changes such as logins, logouts, profile updates, and password changes.
 */
const activityLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    action: {
      type: String,
      required: true,
      enum: [
        'REGISTER_ATTEMPT',
        'EMAIL_VERIFIED',
        'LOGIN_LOCAL',
        'LOGIN_GOOGLE',
        'UPDATE_PROFILE',
        'CHANGE_PASSWORD',
        'PASSWORD_RESET_REQUEST',
        'PASSWORD_RESET_EXECUTE',
        'LOGOUT',
      ],
    },
    ipAddress: {
      type: String,
      default: 'unknown',
    },
    userAgent: {
      type: String,
      default: 'unknown',
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false }, // Only log the creation timestamp
  }
);

module.exports = mongoose.model('ActivityLog', activityLogSchema);
