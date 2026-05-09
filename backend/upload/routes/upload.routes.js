const express = require('express');
const router = express.Router();

// Placeholder for future file upload endpoints
// Frontend expects these at /api/files/...

router.all('*', (req, res) => {
  res.status(501).json({ message: 'File upload endpoints are not implemented yet.' });
});

module.exports = router;
