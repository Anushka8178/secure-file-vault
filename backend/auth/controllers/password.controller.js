const crypto = require('crypto');
const User = require('../models/user.model');
const { hashPassword, verifyPassword, generateResetToken, verifyResetToken } = require('../services/password.service');
const { revokeAllUserTokens } = require('../services/token.service');
const { auditLog } = require('../../audit/audit.service');
const { success } = require('../../shared/response');
const { AuthError, NotFoundError } = require('../../shared/errors');

/**
 * POST /auth/password/forgot
 */
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email: email?.toLowerCase() });
  // Always return 200 to prevent email enumeration
  if (!user) return success(res, null, 'If that email exists, a reset link was sent');

  const { rawToken, hmacToken, expires } = generateResetToken();

  user.passwordResetToken = hmacToken;
  user.passwordResetExpires = expires;
  await user.save();

  // In production: send email with rawToken
  // For dev: return token directly
  const payload = process.env.NODE_ENV !== 'production' ? { devToken: rawToken } : {};

  await auditLog({ event: 'PASSWORD_RESET_REQUESTED', userId: user._id, ip: req.ip });

  return success(res, payload, 'If that email exists, a reset link was sent');
};

/**
 * POST /auth/password/reset
 */
const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  // Find users with non-expired reset tokens
  const users = await User.find({
    passwordResetExpires: { $gt: new Date() },
  }).select('+passwordResetToken +passwordResetExpires');

  let targetUser = null;
  for (const user of users) {
    if (user.passwordResetToken && verifyResetToken(token, user.passwordResetToken)) {
      targetUser = user;
      break;
    }
  }

  if (!targetUser) throw new AuthError('Invalid or expired reset token', 'RESET_TOKEN_INVALID');

  const { hash, algo } = await hashPassword(newPassword);
  targetUser.passwordHash = hash;
  targetUser.passwordAlgo = algo;
  targetUser.passwordResetToken = undefined;
  targetUser.passwordResetExpires = undefined;
  targetUser.failedLoginAttempts = 0;
  targetUser.lockoutUntil = null;
  await targetUser.save();

  // Revoke all active sessions
  await revokeAllUserTokens(targetUser._id);

  await auditLog({ event: 'PASSWORD_RESET_SUCCESS', userId: targetUser._id, ip: req.ip });

  return success(res, null, 'Password reset successfully. Please log in again.');
};

/**
 * PUT /auth/password/change  (authenticated)
 */
const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id).select('+passwordHash +passwordAlgo');

  const valid = await verifyPassword(currentPassword, user.passwordHash, user.passwordAlgo);
  if (!valid) throw new AuthError('Current password is incorrect');

  const { hash, algo } = await hashPassword(newPassword);
  user.passwordHash = hash;
  user.passwordAlgo = algo;
  await user.save();

  await revokeAllUserTokens(user._id);
  await auditLog({ event: 'PASSWORD_CHANGED', userId: user._id, ip: req.ip });

  return success(res, null, 'Password changed. Please log in again.');
};

module.exports = { forgotPassword, resetPassword, changePassword };
