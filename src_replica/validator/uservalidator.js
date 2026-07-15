const { z } = require('zod');

// ─────────────────────────────────────────────────────────────────────────────
// Reusable field definitions


const emailField = z
  .string({ required_error: 'Email is required' })
  .email('Please provide a valid email address')
  .toLowerCase();

const passwordField = z
  .string({ required_error: 'Password is required' })
  .min(8, 'Password must be at least 8 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number');


/**
 * @schema registerSchema
 * Validates the registration payload.
 */
const registerSchema = z.object({
  name: z
    .string({ required_error: 'Name is required' })
    .min(2, 'Name must be at least 2 characters')
    .max(80, 'Name cannot exceed 80 characters')
    .trim(),
  email: emailField,
  password: passwordField,
});

/**
 * @schema loginSchema
 * Validates the login payload.
 */
const loginSchema = z.object({
  email: emailField,
  password: z.string({ required_error: 'Password is required' }).min(1, 'Password is required'),
});

/**
 * @schema verifyOtpSchema
 * Validates the OTP verification payload.
 */
const verifyOtpSchema = z.object({
  email: emailField,
  otp: z
    .string({ required_error: 'OTP code is required' })
    .length(6, 'OTP must be exactly 6 digits')
    .regex(/^\d+$/, 'OTP must contain digits only'),
});

/**
 * @schema updateProfileSchema
 * Validates profile update payload. All fields are optional.
 */
const updateProfileSchema = z.object({
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(80, 'Name cannot exceed 80 characters')
    .trim()
    .optional(),
  bio: z
    .string()
    .max(500, 'Bio cannot exceed 500 characters')
    .trim()
    .optional(),
});

/**
 * @schema changePasswordSchema
 * Validates the change-password payload.
 */
const changePasswordSchema = z.object({
  currentPassword: z
    .string({ required_error: 'Current password is required' })
    .min(1, 'Current password is required'),
  newPassword: passwordField,
});

/**
 * @schema forgotPasswordSchema
 * Validates the forgot-password payload.
 */
const forgotPasswordSchema = z.object({
  email: emailField,
});

/**
 * @schema resetPasswordSchema
 * Validates the reset-password payload.
 */
const resetPasswordSchema = z.object({
  password: passwordField,
});

/**
 * @schema googleLoginSchema
 * Validates Google OAuth sign-in payload.
 */
const googleLoginSchema = z.object({
  idToken: z
    .string({ required_error: 'Google ID Token is required' })
    .min(1, 'Google ID Token cannot be empty'),
});

// ─────────────────────────────────────────────────────────────────────────────
// Middleware Factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @middleware validate
 * @description Express middleware factory that validates `req.body` against a
 * given Zod schema. Returns a structured 400 response on validation failure,
 * replacing `req.body` with the parsed/coerced output on success.
 *
 * @param {z.ZodSchema} schema - The Zod schema to validate against.
 * @returns {Function} Express middleware function.
 */
const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);

  if (!result.success) {
    const errors = (result.error.errors || result.error.issues).map((e) => ({
      field: e.path.join('.'),
      message: e.message,
    }));

    return res.status(400).json({
      success: false,
      message: 'Validation failed. Please review the errors below.',
      errors,
    });
  }

  // Replace body with Zod-parsed output (type-safe & sanitized)
  req.body = result.data;
  next();
};

module.exports = {
  validate,
  registerSchema,
  loginSchema,
  verifyOtpSchema,
  updateProfileSchema,
  changePasswordSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  googleLoginSchema,
};
