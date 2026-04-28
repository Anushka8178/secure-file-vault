const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const RefreshToken = require('../models/refreshToken.model');
const redis = require('../../config/redis');
const env = require('../../config/env');

/**
 * Create a new refresh token with a new family (first login)
 */
const createRefreshToken = async (userId, meta = {}) => {
  const token = crypto.randomBytes(64).toString('hex');
  const family = uuidv4();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  await RefreshToken.create({
    userId,
    token,
    family,
    expiresAt,
    userAgent: meta.userAgent,
    ipAddress: meta.ipAddress,
  });

  return { token, family };
};

/**
 * Rotate refresh token (RTR pattern):
 * - Marks old token as used
 * - If already used → family compromise → invalidate entire family
 */
const rotateRefreshToken = async (oldToken, meta = {}) => {
  const existing = await RefreshToken.findOne({ token: oldToken }).lean();

  if (!existing) throw new Error('INVALID_REFRESH_TOKEN');
  if (existing.invalidated) throw new Error('FAMILY_COMPROMISED');
  if (existing.expiresAt < new Date()) throw new Error('REFRESH_TOKEN_EXPIRED');

  // Reuse detected → invalidate whole family
  if (existing.used) {
    await RefreshToken.updateMany(
      { family: existing.family },
      { $set: { invalidated: true } }
    );
    throw new Error('REFRESH_TOKEN_REUSE_DETECTED');
  }

  // Mark old token as used
  await RefreshToken.findByIdAndUpdate(existing._id, { used: true });

  // Issue new token in same family
  const newToken = crypto.randomBytes(64).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await RefreshToken.create({
    userId: existing.userId,
    token: newToken,
    family: existing.family,
    expiresAt,
    userAgent: meta.userAgent,
    ipAddress: meta.ipAddress,
  });

  return { token: newToken, userId: existing.userId };
};

/**
 * Revoke all refresh tokens for a user (logout everywhere)
 */
const revokeAllUserTokens = async (userId) => {
  await RefreshToken.updateMany(
    { userId, used: false, invalidated: false },
    { $set: { invalidated: true } }
  );
};

/**
 * Blacklist an access token in Redis (for logout before expiry)
 */
const blacklistAccessToken = async (jti, ttlSeconds) => {
  await redis.setex(`blacklist:${jti}`, ttlSeconds, '1');
};

const isAccessTokenBlacklisted = async (jti) => {
  const val = await redis.get(`blacklist:${jti}`);
  return val === '1';
};

module.exports = {
  createRefreshToken,
  rotateRefreshToken,
  revokeAllUserTokens,
  blacklistAccessToken,
  isAccessTokenBlacklisted,
};
