const express = require('express');
const router = express.Router();

const {
  getProfile,
  updateProfile,
  changePassword,
  getActivityLogs,
  logoutUser,
} = require('../controllers/user.controller');

const { protect } = require('../middleware/authmiddleware');
const { uploadProfilePhoto } = require('../config/multer.config');
const { validate, updateProfileSchema, changePasswordSchema } = require('../validator/uservalidator');

// ─────────────────────────────────────────────────────────────────────────────
// All routes in this file require a valid JWT (enforced by `protect` middleware)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @route   GET /api/user/profile
 * @desc    Retrieve the authenticated user's complete profile.
 * @access  Protected
 */
router.get('/profile', protect, getProfile);

/**
 * @route   PUT /api/user/profile
 * @desc    Update name, bio, and/or profile photo.
 *          Accepts multipart/form-data when uploading a photo.
 * @access  Protected
 */
router.put('/profile', protect, uploadProfilePhoto, validate(updateProfileSchema), updateProfile);

/**
 * @route   PUT /api/user/change-password
 * @desc    Change authenticated user's password. Invalidates current session.
 * @access  Protected
 */
router.put('/change-password', protect, validate(changePasswordSchema), changePassword);

/**
 * @route   GET /api/user/activity
 * @desc    Retrieve authenticated user's security action/audit logs.
 * @access  Protected
 */
router.get('/activity', protect, getActivityLogs);

/**
 * @route   POST /api/user/logout
 * @desc    Clear the auth cookie and terminate the session.
 * @access  Protected
 */
router.post('/logout', protect, logoutUser);

module.exports = router;
