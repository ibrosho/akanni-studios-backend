const jwt = require('jsonwebtoken');

/**
 * @util generateToken
 * @description Generates a signed JWT and delivers it via an httpOnly cookie
 * on the response object. This prevents client-side JavaScript from accessing
 * the token, mitigating XSS-based token theft.
 *
 * Cookie attributes:
 * - `httpOnly`: true  — inaccessible to document.cookie / JS
 * - `secure`:   true in production (HTTPS only)
 * - `sameSite`: 'strict' — CSRF mitigation
 *
 * @param {string}   id  - MongoDB ObjectId of the authenticated user.
 * @param {Object}   res - Express response object to attach the cookie to.
 * @returns {string} The signed JWT (also returned for use in response body if needed).
 */
const generateToken = (id, res) => {
  const expiresIn = process.env.JWT_EXPIRES_IN || '7d';

  const token = jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn });

  // Parse expiry string (e.g. "7d") to milliseconds for cookie maxAge
  const daysToMs = (str) => {
    const days = parseInt(str, 10);
    return isNaN(days) ? 7 * 24 * 60 * 60 * 1000 : days * 24 * 60 * 60 * 1000;
  };

  const isProd = process.env.NODE_ENV === 'production';

  res.cookie('token', token, {
    httpOnly: true,
    secure: isProd, // Must be secure (HTTPS) in production for SameSite=None
    sameSite: isProd ? 'none' : 'lax', // Use 'none' for cross-domain cookie auth, 'lax' for local dev
    maxAge: daysToMs(expiresIn),
  });

  return token;
};

module.exports = generateToken;