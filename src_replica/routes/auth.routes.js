const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const {
  registerUser,
  loginUser,
  verifyOTP,
  forgotPassword,
  resetPassword,
} = require('../controllers/user.controller');

const {
  validate,
  registerSchema,
  loginSchema,
  verifyOtpSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} = require('../validator/uservalidator');

// ─────────────────────────────────────────────────────────────────────────────
// Rate Limiters
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @rateLimit authLimiter
 * @desc  Restricts sensitive auth endpoints to 10 requests per 15-minute window
 *        per IP. Defends against brute-force and credential-stuffing attacks.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,  // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP. Please try again after 15 minutes.',
  },
});

/**
 * @rateLimit forgotPasswordLimiter
 * @desc  Stricter limit on password recovery to prevent email spam abuse.
 *        5 requests per hour per IP.
 */
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many password reset requests. Please try again after 1 hour.',
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// Public Auth Routes
// ─────────────────────────────────────────────────────────────────────────────

// @route POST /api/auth/register
router.post('/register', authLimiter, validate(registerSchema), registerUser);

// @route POST /api/auth/verify-otp
router.post('/verify-otp', authLimiter, validate(verifyOtpSchema), verifyOTP);

// @route POST /api/auth/login
router.post('/login', authLimiter, validate(loginSchema), loginUser);


// @route POST /api/auth/forgot-password
router.post('/forgot-password', forgotPasswordLimiter, validate(forgotPasswordSchema), forgotPassword);

// @route POST /api/auth/reset-password/:token
router.post('/reset-password/:token', validate(resetPasswordSchema), resetPassword);

module.exports = router;