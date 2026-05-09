const express = require('express');
const router = express.Router();
const { generateSignedLink, verifySignedLink } = require('./signedLink.service');
const { authenticate } = require('../auth/middleware/authenticate');
const { success } = require('../shared/response');
const { AppError } = require('../shared/errors');

const File = require('../upload/models/file.model');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const env = require('../config/env');

/**
 * POST /links — create a signed download link
 */
router.post('/', authenticate, async (req, res) => {
  const { fileId, ttl, bindIp } = req.body;
  if (!fileId) throw new AppError('fileId is required', 400);

  const file = await File.findById(fileId);
  if (!file) throw new AppError('File not found', 404);

  const ipBinding = bindIp ? req.ip : null;
  const relativeLink = generateSignedLink(fileId, { ttl, ipBinding });
  
  // Construct full URL (since the frontend uses an Nginx proxy, the download route will be at FRONTEND_URL/api/...)
  const fullUrl = `${env.FRONTEND_URL}/api${relativeLink}`;
  
  // Generate QR code
  const qrDataURL = await QRCode.toDataURL(fullUrl);
  
  const expiresAt = new Date(Date.now() + (ttl * 1000)).toISOString();
  
  const linkObj = {
    id: uuidv4(),
    url: fullUrl,
    qrDataURL,
    expiresAt,
    label: file.originalName
  };

  return success(res, linkObj);
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

/**
 * DELETE /links/:id — Revoke a signed link
 * (For now, since links are stateless HMACs, we just return success to remove it from the UI.
 * A production system would add the ID to a Redis blacklist).
 */
router.delete('/:id', authenticate, (req, res) => {
  return success(res, { revoked: true });
});

module.exports = router;
