const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const helmet = require('helmet');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const path = require('path');

const connectDB = require('./src_replica/db/mongodb');
const authRoutes = require('./src_replica/routes/auth.routes');
const userRoutes = require('./src_replica/routes/user.routes');
const errorHandler = require('./src_replica/middleware/errorHandler');

// ─────────────────────────────────────────────────────────────────────────────
// Environment & Database
// ─────────────────────────────────────────────────────────────────────────────
dotenv.config();
connectDB();

const app = express();

// ─────────────────────────────────────────────────────────────────────────────
// Security Headers — Helmet sets 14 HTTP response headers by default
// (e.g. X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security)
// ─────────────────────────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ─────────────────────────────────────────────────────────────────────────────
// CORS — Restrict to configured frontend origin with credential support
// Required for httpOnly cookie auth to work cross-origin
// ─────────────────────────────────────────────────────────────────────────────

// CORS — Restrict to configured frontend origin with credential support
// Required for httpOnly cookie auth to work cross-origin

const allowedOrigins = [
  'https://akanni-studio.vercel.app', // Your live Vercel frontend
  'http://localhost:5173',             // Your local development frontend
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like Postman or mobile apps)
      if (!origin) return callback(null, true);
      
      const isAllowed = allowedOrigins.includes(origin) || 
                        origin.endsWith('.vercel.app') ||
                        /^https?:\/\/localhost(:\d+)?$/.test(origin);

      if (isAllowed) {
        callback(null, true);
      } else {
        console.warn(`Blocked by CORS: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true, // Allow cookies to be sent/received
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// Request Logging — Dev: colorized, Production: combined Apache format
// ────────────────────────────────────────────────────────────────────────────
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// ─────────────────────────────────────────────────────────────────────────────
// Body & Cookie Parsers
// ─────────────────────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));       // Limit JSON payload size
app.use(express.urlencoded({ extended: false })); // Parse form-encoded bodies
app.use(cookieParser());                          // Parse httpOnly cookies

// ─────────────────────────────────────────────────────────────────────────────
// Static File Serving — Profile photo uploads accessible at /uploads/*
// ─────────────────────────────────────────────────────────────────────────────
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ─────────────────────────────────────────────────────────────────────────────
// API Route Mounting
// ─────────────────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);   // Public auth routes (register, login, etc.)
app.use('/api/user', userRoutes);   // Protected user routes (profile, password, etc.)

// ─────────────────────────────────────────────────────────────────────────────
// Health Check
// ─────────────────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.json({
    success: true,
    service: 'Akanni Studios API',
    version: '2.0.0',
    status: 'operational',
    timestamp: new Date().toISOString(),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 404 Handler — Catch-all for unmatched routes
// ─────────────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({
    success: false,
    message: 'The requested endpoint does not exist on this server.',
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Centralized Error Handler — Must be registered LAST
// ─────────────────────────────────────────────────────────────────────────────
app.use(errorHandler);

// ─────────────────────────────────────────────────────────────────────────────
// Server Bootstrap
// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(
    `\n🚀 Akanni Studios API [${process.env.NODE_ENV || 'development'}] → http://localhost:${PORT}\n`
  );
});