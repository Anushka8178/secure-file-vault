const User = require('../models/user.model');
const { generateMfaSecret, verifyTotp, generateBackupCodes } = require('../services/mfa.service');
const { auditLog } = require('../../audit/audit.service');
const { success } = require('../../shared/response');
const { AuthError } = require('../../shared/errors');

/**
 * POST /auth/mfa/setup  — generate TOTP secret + QR code
 */
const setupMfa = async (req, res) => {
  const user = await User.findById(req.user.id);
  const { secret, qrDataUrl, otpAuthUrl } = await generateMfaSecret(user.email);

  // Store secret temporarily (not yet enabled — must verify first)
  user.mfaSecret = secret;
  await user.save();

  return success(res, { qrDataUrl, otpAuthUrl, secret });
};

/**
 * POST /auth/mfa/verify  — confirm TOTP code and activate MFA
 */
const verifyMfa = async (req, res) => {
  const { totpCode } = req.body;
  const user = await User.findById(req.user.id).select('+mfaSecret');

  if (!user.mfaSecret) throw new AuthError('MFA setup not initiated');

  const valid = verifyTotp(totpCode, user.mfaSecret);
  if (!valid) throw new AuthError('Invalid TOTP code', 'MFA_INVALID');

  user.mfaEnabled = true;
  await user.save();

  const backupCodes = await generateBackupCodes(user._id);
  await auditLog({ event: 'MFA_ENABLED', userId: user._id, ip: req.ip });

  return success(res, {
    message: 'MFA enabled. Save your backup codes — they will not be shown again.',
    backupCodes,
  });
};

/**
 * DELETE /auth/mfa  — disable MFA (requires TOTP confirmation)
 */
const disableMfa = async (req, res) => {
  const { totpCode } = req.body;
  const user = await User.findById(req.user.id).select('+mfaSecret');

  if (!user.mfaEnabled) throw new AuthError('MFA not enabled');
  const valid = verifyTotp(totpCode, user.mfaSecret);
  if (!valid) throw new AuthError('Invalid TOTP code to disable MFA');

  user.mfaEnabled = false;
  user.mfaSecret = undefined;
  await user.save();

  await auditLog({ event: 'MFA_DISABLED', userId: user._id, ip: req.ip });
  return success(res, null, 'MFA disabled');
};

/**
 * POST /auth/mfa/backup-codes/regenerate
 */
const regenerateBackupCodes = async (req, res) => {
  const { totpCode } = req.body;
  const user = await User.findById(req.user.id).select('+mfaSecret');

  if (!user.mfaEnabled) throw new AuthError('MFA not enabled');
  const valid = verifyTotp(totpCode, user.mfaSecret);
  if (!valid) throw new AuthError('Invalid TOTP code');

  const backupCodes = await generateBackupCodes(user._id);
  await auditLog({ event: 'MFA_BACKUP_REGENERATED', userId: user._id, ip: req.ip });

  return success(res, { backupCodes });
};

module.exports = { setupMfa, verifyMfa, disableMfa, regenerateBackupCodes };
