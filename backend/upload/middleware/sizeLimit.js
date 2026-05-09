const multer = require('multer');
const { AppError } = require('../../shared/errors');

const MAX_MB = 5;
const MAX_BYTES = MAX_MB * 1024 * 1024;

const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  // We can do MIME type filtering here, but since Member C has specific allowed extensions,
  // we'll be slightly permissive and let magicByte/sanitize services do further validation if needed.
  // For basic security, reject executables.
  if (file.mimetype === 'application/x-msdownload' || file.mimetype === 'application/x-dosexec') {
    return cb(new AppError('Executable files are not allowed', 'INVALID_FILE_TYPE', 400), false);
  }
  cb(null, true);
};

const uploadMiddleware = multer({
  storage,
  limits: {
    fileSize: MAX_BYTES, // Enforce 5MB limit on the backend
  },
  fileFilter,
});

module.exports = { uploadMiddleware };
