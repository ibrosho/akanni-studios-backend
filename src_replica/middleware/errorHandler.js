/**
 * @middleware errorHandler
 * @description Centralized error-handling middleware for Akanni Studios API.
 * Must be mounted LAST in the Express middleware chain.
 *
 * Handles the following error classes:
 * - Mongoose CastError        → 404 (invalid ObjectId)
 * - Mongoose ValidationError  → 400 (schema constraint violations)
 * - MongoDB Duplicate Key     → 409 (unique index conflict)
 * - JWT JsonWebTokenError     → 401 (malformed token)
 * - JWT TokenExpiredError     → 401 (expired token)
 * - All others                → 500 (internal server error)
 */
const errorHandler = (err, req, res, next) => {
  // Log the full error stack in non-production environments
  if (process.env.NODE_ENV !== 'production') {
    console.error(`[ERROR] ${err.name}: ${err.message}`);
  }

  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';

  // ── Mongoose: Invalid ObjectId ───────────────────────────────────────────
  if (err.name === 'CastError') {
    statusCode = 404;
    message = `Resource not found. Invalid identifier: ${err.value}`;
  }

  // ── Mongoose: Schema Validation Failures ─────────────────────────────────
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = Object.values(err.errors)
      .map((e) => e.message)
      .join(', ');
  }

  // ── MongoDB: Duplicate Key (e.g. unique email) ───────────────────────────
  if (err.code === 11000) {
    statusCode = 409;
    const field = Object.keys(err.keyValue)[0];
    message = `An account with that ${field} already exists.`;
  }

  // ── JWT: Malformed Token ─────────────────────────────────────────────────
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid authentication token. Please log in again.';
  }

  // ── JWT: Expired Token ───────────────────────────────────────────────────
  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Authentication token has expired. Please log in again.';
  }

  return res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
};

module.exports = errorHandler;
