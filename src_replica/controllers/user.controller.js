const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const User = require('../models/usermodels');
const ActivityLog = require('../models/activityLog.model');
const generateToken = require('../utils/generatetoken');
const sendEmail = require('../utils/sendemail');

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT LOG HELPER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @helper logActivity
 * @description Internal helper to record user security and profile events.
 * Captures request metadata (IP address and User-Agent header) for audit purposes.
 * Does not throw on failure; logs locally instead to keep main request threads alive.
 */
const logActivity = async (userId, action, req) => {
  try {
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    await ActivityLog.create({
      userId,
      action,
      ipAddress,
      userAgent,
    });
  } catch (error) {
    console.error(`[AUDIT LOG ERROR] Failed to write action ${action} for user ${userId}:`, error.message);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// AUTH CONTROLLERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @controller registerUser
 * @desc    Register a new user and dispatch a 6-digit OTP via email.
 *          If the user exists but is unverified, re-issues a fresh OTP.
 * @route   POST /api/auth/register
 * @access  Public
 */
const registerUser = async (req, res, next) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email }).select('+password');

    // Block re-registration of fully verified accounts
    if (existingUser && existingUser.isVerified) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.',
      });
    }

    // Generate a 6-digit numeric OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    let user;

    if (existingUser && !existingUser.isVerified) {
      // Refresh OTP for unverified accounts (supports resend flow)
      existingUser.otpCode = otp;
      existingUser.otpExpires = otpExpires;
      if (name) existingUser.name = name;
      if (password) existingUser.password = password;
      user = await existingUser.save();
    } else {
      // Create a fresh unverified record
      user = await User.create({
        name,
        email,
        password,
        otpCode: otp,
        otpExpires,
        isVerified: false,
      });
    }

    // Dispatch OTP email — fallback to Sandbox Console Mode on failure
    try {
      await sendEmail({
        to: user.email,
        subject: 'Akanni Studios — Email Verification Code',
        text: `Hello ${user.name},\n\nYour account verification requires email validation.\n\nVerification Code: ${otp}\n\nThis code expires in 10 minutes. Do not share it with anyone.\n\n— Akanni Studios`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
            <h2 style="color: #1a1a2e;">Akanni Studios</h2>
            <p>Hello <strong>${user.name}</strong>,</p>
            <p>Use the code below to verify your email address:</p>
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 20px; background: #f4f4f4; text-align: center; border-radius: 8px;">
              ${otp}
            </div>
            <p style="color: #888; font-size: 12px; margin-top: 16px;">This code expires in 10 minutes. Do not share it.</p>
          </div>
        `,
      });

      // Audit register attempt
      await logActivity(user._id, 'REGISTER_ATTEMPT', req);

      return res.status(201).json({
        success: true,
        message: 'Verification code dispatched to your email inbox.',
      });
    } catch (emailError) {
      console.error('[MAIL SYSTEM FAILURE] Falling back to Sandbox Mode:', emailError.message);
      
      console.log(`
      ┌────────────────────────────────────────────────────────┐
      │  Akanni Studios - Sandbox OTP Dispatch                  │
      ├────────────────────────────────────────────────────────┤
      │  Recipient: ${user.email}                              │
      │  Verification Code: ${otp}                            │
      │  Expiry: 10 minutes                                    │
      └────────────────────────────────────────────────────────┘
      `);

      await logActivity(user._id, 'REGISTER_ATTEMPT', req);

      return res.status(201).json({
        success: true,
        message: 'Account created. [Sandbox Mode] Verification code generated (printed to backend console).',
        sandbox: true,
        otp: otp // Pass OTP directly to frontend to allow instant bypass during local testing
      });
    }
  } catch (error) {
    next(error);
  }
};

/**
 * @controller verifyOTP
 * @desc    Validate a 6-digit OTP and mark the user account as verified.
 * @route   POST /api/auth/verify-otp
 * @access  Public
 */
const verifyOTP = async (req, res, next) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'No registration record found for this email address.',
      });
    }

    const isExpired = Date.now() > new Date(user.otpExpires).getTime();
    const isInvalid = user.otpCode !== otp.trim();

    if (isInvalid || isExpired) {
      return res.status(400).json({
        success: false,
        message: isExpired
          ? 'Verification code has expired. Please request a new one.'
          : 'Invalid verification code. Please check and try again.',
      });
    }

    // Activate the account and clear OTP fields
    user.isVerified = true;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Audit verified status
    await logActivity(user._id, 'EMAIL_VERIFIED', req);

    return res.status(200).json({
      success: true,
      message: 'Email verified successfully. You may now log in.',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @controller loginUser
 * @desc    Authenticate user credentials and issue a JWT via httpOnly cookie.
 * @route   POST /api/auth/login
 * @access  Public
 */
const loginUser = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    // Explicitly select password since it's excluded by default
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.',
      });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: 'Account not verified. Please check your email for the OTP code.',
      });
    }

    // Issue JWT and set httpOnly cookie
    const token = generateToken(user._id, res);

    // Audit local login success
    await logActivity(user._id, 'LOGIN_LOCAL', req);

    return res.status(200).json({
      success: true,
      message: 'Credentials verified successfully.',
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        bio: user.bio,
        profilePhoto: user.profilePhoto,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    next(error);
  }
};



/**
 * @controller logoutUser
 * @desc    Invalidate the session by clearing the auth cookie.
 * @route   POST /api/user/logout
 * @access  Protected
 */
const logoutUser = async (req, res, next) => {
  try {
    const userId = req.user._id;

    const isProd = process.env.NODE_ENV === 'production';

    res.cookie('token', '', {
      httpOnly: true,
      expires: new Date(0), // Immediately expired
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
    });

    // Audit logout action
    await logActivity(userId, 'LOGOUT', req);

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully.',
    });
  } catch (error) {
    next(error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// PROFILE CONTROLLERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @controller getProfile
 * @desc    Retrieve the authenticated user's profile.
 * @route   GET /api/user/profile
 * @access  Protected
 */
const getProfile = async (req, res, next) => {
  try {
    // req.user is already attached by the protect middleware
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User profile not found.',
      });
    }

    return res.status(200).json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        bio: user.bio,
        profilePhoto: user.profilePhoto,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @controller updateProfile
 * @desc    Update the authenticated user's name, bio, and/or profile photo.
 *          Accepts multipart/form-data when a file is included.
 * @route   PUT /api/user/profile
 * @access  Protected
 */
const updateProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User profile not found.',
      });
    }

    // Apply text field updates
    if (req.body.name !== undefined) user.name = req.body.name;
    if (req.body.bio !== undefined) user.bio = req.body.bio;

    // Handle profile photo upload (via Multer)
    if (req.file) {
      // Clean up local temp file if created
      const filePath = req.file.path;
      if (filePath && fs.existsSync(filePath)) {
        const fileBuffer = fs.readFileSync(filePath);
        const mimeType = req.file.mimetype || 'image/jpeg';
        // Store as Base64 Data URI in MongoDB for 100% cloud persistence across Render server restarts
        user.profilePhoto = `data:${mimeType};base64,${fileBuffer.toString('base64')}`;
        try {
          fs.unlinkSync(filePath); // Clean up temp disk file
        } catch (_err) {}
      }
    } else if (req.body.deletePhoto === 'true') {
      user.profilePhoto = '';
    }

    const updatedUser = await user.save();

    // Audit profile update
    await logActivity(user._id, 'UPDATE_PROFILE', req);

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully.',
      user: {
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        bio: updatedUser.bio,
        profilePhoto: updatedUser.profilePhoto,
      },
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @controller changePassword
 * @desc    Change the authenticated user's password after verifying the current one.
 * @route   PUT /api/user/change-password
 * @access  Protected
 */
const changePassword = async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  try {
    // Explicitly select password for comparison
    const user = await User.findById(req.user._id).select('+password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.',
      });
    }

    // Verify the current password before allowing the change
    const isMatch = await user.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect.',
      });
    }

    // Guard against reusing the same password
    const isSamePassword = await user.matchPassword(newPassword);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: 'New password must be different from your current password.',
      });
    }

    user.password = newPassword;
    await user.save();

    // Audit change password
    await logActivity(user._id, 'CHANGE_PASSWORD', req);

    // Invalidate the existing session — force re-login with new credentials
    res.cookie('token', '', {
      httpOnly: true,
      expires: new Date(0),
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully. Please log in with your new password.',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @controller getActivityLogs
 * @desc    Retrieve the authenticated user's audit trail logs (e.g. logins, changes).
 * @route   GET /api/user/activity
 * @access  Protected
 */
const getActivityLogs = async (req, res, next) => {
  try {
    const logs = await ActivityLog.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50); // Limit to top 50 recent records

    return res.status(200).json({
      success: true,
      logs,
    });
  } catch (error) {
    next(error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// PASSWORD RECOVERY CONTROLLERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @controller forgotPassword
 * @desc    Generate a secure password reset token and dispatch a recovery email.
 * @route   POST /api/auth/forgot-password
 * @access  Public
 */
const forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    // Return a generic 200 even if the user is not found (anti-enumeration)
    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If an account with that email exists, a reset link has been sent.',
      });
    }

    const rawResetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = crypto
      .createHash('sha256')
      .update(rawResetToken)
      .digest('hex');
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await user.save();

    const frontendBase = (req.headers.origin && !req.headers.origin.includes('localhost')) 
      ? req.headers.origin 
      : (process.env.FRONTEND_URL || 'https://akanni-studio.vercel.app');
    const resetUrl = `${frontendBase}/reset-password/${rawResetToken}`;

    try {
      await sendEmail({
        to: user.email,
        subject: 'Akanni Studios — Password Reset Request',
        text: `You requested a password reset.\n\nClick the link below to reset your password (expires in 15 minutes):\n\n${resetUrl}\n\nIf you did not request this, please ignore this email.`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
            <h2 style="color: #1a1a2e;">Akanni Studios</h2>
            <p>Hello <strong>${user.name}</strong>,</p>
            <p>You requested a password reset. Click the button below:</p>
            <a href="${resetUrl}" style="display:inline-block; padding: 12px 24px; background: #1a1a2e; color: white; text-decoration: none; border-radius: 6px; margin: 16px 0;">Reset Password</a>
            <p style="color: #888; font-size: 12px;">This link expires in 15 minutes. If you did not request this, ignore this email.</p>
          </div>
        `,
      });

      // Audit password reset request
      await logActivity(user._id, 'PASSWORD_RESET_REQUEST', req);

    } catch (emailError) {
      console.error('[MAIL SYSTEM FAILURE] Falling back to Sandbox Mode:', emailError.message);
      
      console.log(`
      ┌────────────────────────────────────────────────────────┐
      │  Akanni Studios - Sandbox Password Reset Link          │
      ├────────────────────────────────────────────────────────┤
      │  Recipient: ${user.email}                              │
      │  Reset Link: ${resetUrl}                               │
      │  Expiry: 15 minutes                                    │
      └────────────────────────────────────────────────────────┘
      `);

      await logActivity(user._id, 'PASSWORD_RESET_REQUEST', req);

      return res.status(200).json({
        success: true,
        message: 'If an account with that email exists, a reset link has been generated (printed to backend console).',
        sandbox: true,
        resetUrl: resetUrl // Pass resetUrl directly to frontend for easy local testing
      });
    }

    return res.status(200).json({
      success: true,
      message: 'If an account with that email exists, a reset link has been sent.',
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @controller resetPassword
 * @desc    Validate a reset token and apply the new password.
 * @route   POST /api/auth/reset-password/:token
 * @access  Public
 */
const resetPassword = async (req, res, next) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Password reset token is invalid or has expired.',
      });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // Audit password reset execution
    await logActivity(user._id, 'PASSWORD_RESET_EXECUTE', req);

    return res.status(200).json({
      success: true,
      message: 'Password reset successful. You may now log in.',
    });
  } catch (error) {
    next(error);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  registerUser,
  verifyOTP,
  loginUser,
  logoutUser,
  getProfile,
  updateProfile,
  changePassword,
  getActivityLogs,
  forgotPassword,
  resetPassword,
};