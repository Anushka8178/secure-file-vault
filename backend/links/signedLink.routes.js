const express = require('express');
const router = express.Router();
const { generateSignedLink, verifySignedLink } = require('./signedLink.service');
const { authenticate } = require('../auth/middleware/authenticate');
const { success } = require('../shared/response');
const { AppError } = require('../shared/errors');

/**
 * POST /links/generate — create a signed download link
 */
router.post('/generate', authenticate, (req, res) => {
  const { fileId, ttl, bindIp } = req.body;
  if (!fileId) throw new AppError('fileId is required', 400);

  const ipBinding = bindIp ? req.ip : null;
  const link = generateSignedLink(fileId, { ttl, ipBinding });
  return success(res, { link });
});

/**
 * GET /links/verify — verify a signed link (used internally)
 */
router.get('/verify', (req, res) => {
  const { fileId, expires, sig, ip } = req.query;
  const result = verifySignedLink(fileId, { expires, sig, ip }, req.ip);
  if (!result.valid) throw new AppError(`Invalid link: ${result.reason}`, 403, 'LINK_INVALID');
  return success(res, { valid: true });
});

module.exports = router;
