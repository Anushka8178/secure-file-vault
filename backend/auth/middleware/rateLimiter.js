const redis = require('../../config/redis');
const { AppError } = require('../../shared/errors');
const env = require('../../config/env');

/**
 * Redis sliding-window rate limiter
 * @param {number} maxRequests - max requests per window
 * @param {number} windowMs - window size in milliseconds
 * @param {Function} keyFn - function(req) => string key
 */
const createRateLimiter = (maxRequests, windowMs, keyFn) => async (req, res, next) => {
  const key = `rl:${keyFn(req)}`;
  const now = Date.now();
  const windowStart = now - windowMs;

  const pipeline = redis.pipeline();
  pipeline.zremrangebyscore(key, '-inf', windowStart);         // remove old entries
  pipeline.zadd(key, now, `${now}-${Math.random()}`);          // add current request
  pipeline.zcard(key);                                          // count in window
  pipeline.pexpire(key, windowMs);                              // reset TTL

  const results = await pipeline.exec();
  const count = results[2][1];

  res.setHeader('X-RateLimit-Limit', maxRequests);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - count));
  res.setHeader('X-RateLimit-Reset', Math.ceil((now + windowMs) / 1000));

  if (count > maxRequests) {
    return next(new AppError('Too many requests', 429, 'RATE_LIMITED'));
  }
  next();
};

// Per-IP limiter
const ipLimiter = createRateLimiter(
  env.RATE_LIMIT_MAX,
  env.RATE_LIMIT_WINDOW_MS,
  (req) => `ip:${req.ip}`
);

// Per-user limiter (use after authenticate)
const userLimiter = createRateLimiter(
  200,
  60_000,
  (req) => `user:${req.user?.id || req.ip}`
);

// Strict auth limiter (login/register endpoints)
const authLimiter = createRateLimiter(
  10,
  60_000,
  (req) => `auth:${req.ip}`
);

module.exports = { createRateLimiter, ipLimiter, userLimiter, authLimiter };
