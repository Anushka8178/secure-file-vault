const crypto = require('crypto');
const { AppError } = require('../../shared/errors');
const env = require('../../config/env');

const CSRF_HEADER = 'x-csrf-token';
const CSRF_COOKIE = 'csrf_token';

/**
 * Generate a CSRF token and set it as a cookie
 * Double-submit cookie pattern: cookie value must match header value
 */
const generateCsrfToken = (req, res, next) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false,  // Must be readable by JS to put in header
    sameSite: 'Strict',
    secure: env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });
  res.locals.csrfToken = token;
  next();
};

/**
 * Validate CSRF token on state-changing requests
 * Skips GET, HEAD, OPTIONS
 */
const validateCsrf = (req, res, next) => {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) return next();

  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const headerToken = req.headers[CSRF_HEADER];

  if (!cookieToken || !headerToken) {
    return next(new AppError('CSRF token missing', 403, 'CSRF_MISSING'));
  }

  if (!crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
    return next(new AppError('CSRF token mismatch', 403, 'CSRF_INVALID'));
  }

  next();
};

module.exports = { generateCsrfToken, validateCsrf };
