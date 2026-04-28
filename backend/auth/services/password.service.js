const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const crypto = require('crypto');
const env = require('../../config/env');

/**
 * Hash a password using bcrypt (cost>=12) or argon2id
 */
const hashPassword = async (password, algo = env.PASSWORD_ALGO) => {
  if (algo === 'argon2id') {
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,   // 64 MB
      timeCost: 3,
      parallelism: 4,
    });
    return { hash, algo: 'argon2id' };
  }
  // Default: bcrypt with cost >= 12
  const rounds = Math.max(env.BCRYPT_ROUNDS, 12);
  const hash = await bcrypt.hash(password, rounds);
  return { hash, algo: 'bcrypt' };
};

/**
 * Verify password against stored hash (supports both algorithms)
 */
const verifyPassword = async (password, storedHash, algo = 'bcrypt') => {
  if (algo === 'argon2id') {
    return argon2.verify(storedHash, password);
  }
  return bcrypt.compare(password, storedHash);
};

/**
 * Generate a secure HMAC-SHA256 password reset token (TTL 15 min)
 */
const generateResetToken = () => {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + env.RESET_TOKEN_TTL_MINUTES * 60 * 1000);
  const hmac = crypto
    .createHmac('sha256', env.RESET_TOKEN_SECRET)
    .update(rawToken)
    .digest('hex');
  return { rawToken, hmacToken: hmac, expires };
};

/**
 * Verify a reset token HMAC
 */
const verifyResetToken = (rawToken, storedHmac) => {
  const expected = crypto
    .createHmac('sha256', env.RESET_TOKEN_SECRET)
    .update(rawToken)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(storedHmac));
};

module.exports = { hashPassword, verifyPassword, generateResetToken, verifyResetToken };
