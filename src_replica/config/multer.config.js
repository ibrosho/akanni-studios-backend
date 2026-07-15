const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ─────────────────────────────────────────────────────────────────────────────
// Ensure upload directory exists at startup
// ─────────────────────────────────────────────────────────────────────────────
const UPLOAD_DIR = path.join(__dirname, '../../uploads/profiles');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ─────────────────────────────────────────────────────────────────────────────
// Disk Storage Strategy
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @config diskStorage
 * @description Stores uploaded files to disk in `uploads/profiles/`.
 * Filename pattern: `<userId>-<timestamp>.<ext>` — guarantees uniqueness
 * and allows per-user cleanup when profile photos are updated.
 */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const userId = req.user ? req.user._id.toString() : 'unknown';
    const ext = path.extname(file.originalname).toLowerCase();
    const filename = `${userId}-${Date.now()}${ext}`;
    cb(null, filename);
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// File Type Guard
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @config fileFilter
 * @description Whitelists JPEG, PNG, and WebP MIME types.
 * Rejects all other file types with a descriptive error message.
 */
const fileFilter = (_req, file, cb) => {
  const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

  if (ALLOWED_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error('Invalid file type. Only JPEG, PNG, and WebP images are accepted.'),
      false
    );
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Multer Instance — Profile Photo Upload
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @middleware uploadProfilePhoto
 * @description Multer single-file upload handler for the `profilePhoto` field.
 * Enforces a 2MB file size limit.
 *
 * Usage in router: `router.put('/profile', protect, uploadProfilePhoto, updateProfile)`
 */
const uploadProfilePhoto = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2 MB
  },
}).single('profilePhoto');

module.exports = { uploadProfilePhoto };
