const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const MfaBackupCode = require('../models/mfaBackupCode.model');
const env = require('../../config/env');

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(env.MFA_BACKUP_ENCRYPTION_KEY.padEnd(32, '0').slice(0, 32));

/**
 * Encrypt a backup code with AES-256-GCM
 */
const encryptCode = (plaintext) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
};

/**
 * Decrypt a backup code
 */
const decryptCode = (ciphertext) => {
  const [ivHex, tagHex, dataHex] = ciphertext.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const data = Buffer.from(dataHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
};

/**
 * Generate a TOTP secret + QR code for enrollment
 */
const generateMfaSecret = async (email) => {
  authenticator.options = { digits: 6, period: 30, algorithm: 'sha1' };
  const secret = authenticator.generateSecret(32);
  const otpAuthUrl = authenticator.keyuri(email, env.MFA_ISSUER, secret);
  const qrDataUrl = await qrcode.toDataURL(otpAuthUrl);
  return { secret, otpAuthUrl, qrDataUrl };
};

/**
 * Verify a TOTP code
 */
const verifyTotp = (token, secret) => {
  authenticator.options = { window: 1 }; // ±1 period tolerance
  return authenticator.verify({ token, secret });
};

/**
 * Generate 10 AES-encrypted backup codes for a user
 */
const generateBackupCodes = async (userId) => {
  // Delete existing backup codes
  await MfaBackupCode.deleteMany({ userId });

  const plainCodes = [];
  const docs = [];

  for (let i = 0; i < 10; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // e.g. "A1B2C3D4"
    plainCodes.push(code);
    docs.push({ userId, codeEncrypted: encryptCode(code) });
  }

  await MfaBackupCode.insertMany(docs);
  return plainCodes; // Return plain codes ONCE for user to save
};

/**
 * Validate and consume a backup code
 */
const consumeBackupCode = async (userId, inputCode) => {
  const codes = await MfaBackupCode.find({ userId, used: false });

  for (const codeDoc of codes) {
    try {
      const plain = decryptCode(codeDoc.codeEncrypted);
      if (plain === inputCode.toUpperCase()) {
        codeDoc.used = true;
        codeDoc.usedAt = new Date();
        await codeDoc.save();
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
};

module.exports = {
  generateMfaSecret,
  verifyTotp,
  generateBackupCodes,
  consumeBackupCode,
};
