const crypto = require('crypto');
const env = require('../config/env');

/**
 * Generate an HMAC-signed download link with TTL and optional IP binding
 * @param {string} fileId - the file resource ID
 * @param {object} options - { ttl (seconds), ipBinding }
 */
const generateSignedLink = (fileId, { ttl = env.SIGNED_LINK_DEFAULT_TTL, ipBinding = null } = {}) => {
  const expires = Math.floor(Date.now() / 1000) + ttl;
  const payload = ipBinding
    ? `${fileId}:${expires}:${ipBinding}`
    : `${fileId}:${expires}`;

  const sig = crypto
    .createHmac('sha256', env.SIGNED_LINK_SECRET)
    .update(payload)
    .digest('hex');

  const params = new URLSearchParams({ expires: expires.toString(), sig });
  if (ipBinding) params.set('ip', ipBinding);

  return `/files/${fileId}/download?${params.toString()}`;
};

/**
 * Verify a signed link
 * @param {string} fileId
 * @param {object} query - { expires, sig, ip? }
 * @param {string} requestIp - the requester's IP
 */
const verifySignedLink = (fileId, { expires, sig, ip }, requestIp) => {
  if (!expires || !sig) return { valid: false, reason: 'missing_params' };

  const expiresNum = parseInt(expires, 10);
  if (isNaN(expiresNum) || Math.floor(Date.now() / 1000) > expiresNum) {
    return { valid: false, reason: 'expired' };
  }

  // IP binding check
  if (ip && ip !== requestIp) {
    return { valid: false, reason: 'ip_mismatch' };
  }

  const payload = ip
    ? `${fileId}:${expires}:${ip}`
    : `${fileId}:${expires}`;

  const expected = crypto
    .createHmac('sha256', env.SIGNED_LINK_SECRET)
    .update(payload)
    .digest('hex');

  const valid = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  return { valid, reason: valid ? null : 'invalid_signature' };
};

module.exports = { generateSignedLink, verifySignedLink };
