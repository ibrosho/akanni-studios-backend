const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

/**
 * @schema UserSchema
 * @description Core user document for Akanni Studios.
 * Includes OTP verification, password reset token flows,
 * and extended profile fields (bio, profilePhoto).
 */
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false, // Never returned in queries by default
    },

    // ─── Extended Profile ──────────────────────────────────────────────────
    bio: {
      type: String,
      default: '',
      maxlength: [500, 'Bio cannot exceed 500 characters'],
      trim: true,
    },
    profilePhoto: {
      type: String,
      default: '',
    },

    // ─── Verification & Recovery ──────────────────────────────────────────
    isVerified: {
      type: Boolean,
      default: false,
    },
    otpCode: { type: String },
    otpExpires: { type: Date },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
  },
  {
    timestamps: true,
  }
);

/**
 * @hook pre('save')
 * @description Auto-hashes password whenever it is modified.
 * Uses bcrypt with a cost factor of 12 for production-grade security.
 */
userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
});

/**
 * @method matchPassword
 * @description Compares a plaintext candidate password to the stored hash.
 * @param {string} enteredPassword - Plaintext password from the request.
 * @returns {Promise<boolean>}
 */
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);