const express = require('express');
const router = express.Router();

const { authenticate } = require('../../auth/middleware/authenticate');
const { uploadMiddleware } = require('../middleware/sizeLimit');
const { uploadFile, getStatus, getFiles } = require('../controllers/upload.controller');

// Require authentication for all file endpoints
router.use(authenticate);

// List files for the logged in user
router.get('/', getFiles);

// Upload a new file
router.post('/upload', uploadMiddleware.single('file'), uploadFile);

// Poll file scan status
router.get('/:id/status', getStatus);

module.exports = router;
