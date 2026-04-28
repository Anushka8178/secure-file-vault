const { body } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/user.model');
const { hashPassword, verifyPassword } = require('../services/password.service');
const { signAccessToken } = require('../services/jwt.service');
const { createRefreshToken, rotateRefreshToken, revokeAllUserTokens, blacklistAccessToken } = require('../services/token.service');
const { createSession, revokeAllSessions } = require('../services/session.service');
const { recordFailedAttempt, resetFailedAttempts } = require('../middleware/lockout');
const { verifyTotp, consumeBackupCode } = require('../services/mfa.service');
const { auditLog } = require('../../audit/audit.service');
const { success, created, error } = require('../../shared/response');
const { AuthError, ConflictError } = require('../../shared/errors');
const { validate } = require('../../shared/validate');
const env = require('../../config/env');

// Validation rules
const registerValidation = [
  body('email').isEmail().normalizeEmail(),
  body('username').isLength({ min: 3, max: 30 }).trim(),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must have uppercase, lowercase, number, and special char'),
  validate,
];

const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  validate,
];

/**
 * POST /auth/register
 */
const register = async (req, res) => {
  const { email, username, password } = req.body;

  const exists = await User.findOne({ $or: [{ email }, { username }] });
  if (exists) throw new ConflictError('Email or username already taken');

  const { hash, algo } = await hashPassword(password);

  const user = await User.create({
    email,
    username,
    passwordHash: hash,
    passwordAlgo: algo,
  });

  await auditLog({ event: 'USER_REGISTERED', userId: user._id, ip: req.ip });

  return created(res, {
    user: { id: user._id, email: user.email, username: user.username, role: user.role },
  }, 'Registration successful');
};

/**
 * POST /auth/login
 */
const login = async (req, res) => {
  const { email, password, totpCode, backupCode } = req.body;

  const user = await User.findOne({ email }).select('+passwordHash +passwordAlgo +mfaSecret +failedLoginAttempts +lockoutUntil');
  if (!user) throw new AuthError('Invalid credentials');

  const valid = await verifyPassword(password, user.passwordHash, user.passwordAlgo || 'bcrypt');
  if (!valid) {
    await recordFailedAttempt(user._id);
    await auditLog({ event: 'LOGIN_FAILED', userId: user._id, ip: req.ip, meta: { reason: 'bad_password' } });
    throw new AuthError('Invalid credentials');
  }

  // MFA check
  if (user.mfaEnabled) {
    if (totpCode) {
      const mfaValid = verifyTotp(totpCode, user.mfaSecret);
      if (!mfaValid) throw new AuthError('Invalid MFA code', 'MFA_INVALID');
    } else if (backupCode) {
      const used = await consumeBackupCode(user._id, backupCode);
      if (!used) throw new AuthError('Invalid backup code', 'BACKUP_CODE_INVALID');
    } else {
      return res.status(200).json({ ok: true, mfaRequired: true, message: 'MFA code required' });
    }
  }

  await resetFailedAttempts(user._id);
  user.lastLoginAt = new Date();
  await user.save();

  // Issue tokens
  const sessionId = uuidv4();
  const accessToken = signAccessToken({
    sub: user._id.toString(),
    email: user.email,
    role: user.role,
    jti: uuidv4(),
  });

  const { token: refreshToken } = await createRefreshToken(user._id, {
    userAgent: req.headers['user-agent'],
    ipAddress: req.ip,
  });

  await createSession(user._id, sessionId, {
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });

  // Set refresh token as HttpOnly cookie
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/auth/refresh',
  });

  await auditLog({ event: 'LOGIN_SUCCESS', userId: user._id, ip: req.ip });

  return success(res, {
    accessToken,
    user: { id: user._id, email: user.email, username: user.username, role: user.role },
  });
};

/**
 * POST /auth/refresh
 */
const refresh = async (req, res) => {
  const oldToken = req.cookies?.refresh_token || req.body?.refreshToken;
  if (!oldToken) throw new AuthError('No refresh token', 'NO_REFRESH_TOKEN');

  const { token: newRefreshToken, userId } = await rotateRefreshToken(oldToken, {
    userAgent: req.headers['user-agent'],
    ipAddress: req.ip,
  });

  const user = await User.findById(userId);
  if (!user || !user.isActive) throw new AuthError('User not found or inactive');

  const accessToken = signAccessToken({
    sub: user._id.toString(),
    email: user.email,
    role: user.role,
    jti: uuidv4(),
  });

  res.cookie('refresh_token', newRefreshToken, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/auth/refresh',
  });

  return success(res, { accessToken });
};

/**
 * POST /auth/logout
 */
const logout = async (req, res) => {
  const { jti } = req.user;

  // Blacklist current access token
  if (jti) await blacklistAccessToken(jti, 900); // 15 min TTL matches JWT_ACCESS_TTL

  // Invalidate refresh token cookie
  const refreshToken = req.cookies?.refresh_token;
  if (refreshToken) {
    res.clearCookie('refresh_token', { path: '/auth/refresh' });
  }

  await auditLog({ event: 'LOGOUT', userId: req.user.id, ip: req.ip });

  return success(res, null, 'Logged out');
};

/**
 * POST /auth/logout-all  — revoke all sessions
 */
const logoutAll = async (req, res) => {
  await revokeAllUserTokens(req.user.id);
  await revokeAllSessions(req.user.id);
  await auditLog({ event: 'LOGOUT_ALL', userId: req.user.id, ip: req.ip });
  return success(res, null, 'All sessions revoked');
};

/**
 * GET /auth/me
 */
const me = async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) throw new AuthError('User not found');
  return success(res, { user });
};

module.exports = {
  register,
  login,
  refresh,
  logout,
  logoutAll,
  me,
  registerValidation,
  loginValidation,
};
