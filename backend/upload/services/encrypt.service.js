const crypto = require('crypto');
const env = require('../../config/env');

const ALGORITHM = 'aes-256-gcm';
// key must be 32 bytes for aes-256-gcm. We will pad or slice the env variable.
const KEY = crypto.createHash('sha256').update(String(env.FILE_ENCRYPTION_KEY)).digest();

/**
 * Encrypt a buffer in memory
 * @param {Buffer} buffer - The plain text file buffer
 * @returns {Object} - { encryptedBuffer, iv } (iv is hex encoded)
 */
const encryptBuffer = (buffer) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // We prepend the 16-byte auth tag to the encrypted buffer so it's all one piece
  const finalBuffer = Buffer.concat([authTag, encrypted]);
  
  return {
    encryptedBuffer: finalBuffer,
    iv: iv.toString('hex')
  };
};

/**
 * Decrypt an encrypted buffer
 * @param {Buffer} encryptedBuffer - The buffer starting with authTag followed by ciphertext
 * @param {String} ivHex - The hex string of the IV
 * @returns {Buffer} - The decrypted plain text buffer
 */
const decryptBuffer = (encryptedBuffer, ivHex) => {
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = encryptedBuffer.subarray(0, 16);
  const ciphertext = encryptedBuffer.subarray(16);
  
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);
  
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted;
};

module.exports = { encryptBuffer, decryptBuffer };
