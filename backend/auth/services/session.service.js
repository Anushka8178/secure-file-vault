const redis = require('../../config/redis');

const SESSION_PREFIX = 'session:';
const SESSION_TTL = 7 * 24 * 60 * 60; // 7 days in seconds

/**
 * Store session metadata in Redis
 */
const createSession = async (userId, sessionId, meta = {}) => {
  const key = `${SESSION_PREFIX}${userId}:${sessionId}`;
  await redis.setex(key, SESSION_TTL, JSON.stringify({
    userId: userId.toString(),
    sessionId,
    createdAt: new Date().toISOString(),
    ...meta,
  }));
};

/**
 * Get all sessions for a user
 */
const getUserSessions = async (userId) => {
  const keys = await redis.keys(`${SESSION_PREFIX}${userId}:*`);
  if (!keys.length) return [];
  const values = await redis.mget(...keys);
  return values
    .filter(Boolean)
    .map((v) => JSON.parse(v));
};

/**
 * Revoke a specific session
 */
const revokeSession = async (userId, sessionId) => {
  await redis.del(`${SESSION_PREFIX}${userId}:${sessionId}`);
};

/**
 * Revoke all sessions for a user
 */
const revokeAllSessions = async (userId) => {
  const keys = await redis.keys(`${SESSION_PREFIX}${userId}:*`);
  if (keys.length) await redis.del(...keys);
};

module.exports = { createSession, getUserSessions, revokeSession, revokeAllSessions };
