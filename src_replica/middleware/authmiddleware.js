const jwt = require('jsonwebtoken');
const User = require('../models/usermodels');

/**
 * @middleware protect
 * @description JWT authentication guard. Extracts and verifies a JWT from
 * either the signed httpOnly cookie (`token`) or the Authorization header
 * (`Bearer <token>`). Attaches the authenticated user object to `req.user`.
 *
 * @throws {401} If no token is present or the token is invalid/expired.
 */
const protect = async (req, res, next) => {
  let token;

  // ── 1. Prefer httpOnly cookie (primary auth mechanism) ──────────────────
  if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }
  // ── 2. Fallback: Authorization header for API clients / mobile ──────────
  else if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer ')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. No authentication token provided.',
    });
  }

  try {
    // Verify signature and decode payload
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Fetch the user — exclude password from projection
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Token principal no longer exists. Please log in again.',
      });
    }

    // Attach principal to request context
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token.',
    });
  }
};

module.exports = { protect };
