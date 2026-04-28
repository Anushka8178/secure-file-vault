const { verifyAccessToken } = require('../services/jwt.service');
const { isAccessTokenBlacklisted } = require('../services/token.service');
const { AuthError } = require('../../shared/errors');

/**
 * JWT authentication middleware
 * Verifies JWT, checks blacklist, attaches user to req
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthError('No token provided', 'NO_TOKEN');
    }

    const token = authHeader.slice(7);
    const payload = verifyAccessToken(token);

    // Check if token is blacklisted (logged out)
    if (payload.jti) {
      const blacklisted = await isAccessTokenBlacklisted(payload.jti);
      if (blacklisted) throw new AuthError('Token has been revoked', 'TOKEN_REVOKED');
    }

    req.user = {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      jti: payload.jti,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return next(new AuthError('Token expired', 'TOKEN_EXPIRED'));
    }
    if (err.name === 'JsonWebTokenError') {
      return next(new AuthError('Invalid token', 'INVALID_TOKEN'));
    }
    next(err);
  }
};

module.exports = { authenticate };
