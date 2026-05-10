/**
 * Member C - Polyglot Detection
 * Scans the raw decrypted file buffer for embedded malicious scripts
 * often used in polyglot attacks (e.g. hiding PHP in a PNG file).
 */

const SUSPICIOUS_PATTERNS = [
  '<script',
  '<?php',
  'javascript:',
  'vbscript:',
  'onload=',
  'onerror=',
  'eval(',
  'base64_decode('
];

/**
 * Scan a buffer for polyglot patterns
 * @param {Buffer} buffer - The decrypted file buffer
 * @returns {Boolean} true if safe, false if malicious patterns detected
 */
const detectPolyglot = (buffer) => {
  // Convert buffer to string to perform pattern matching.
  // Note: For very large files, this should be done in chunks to save memory,
  // but since we have a 5MB limit, converting to string is acceptable.
  const content = buffer.toString('utf-8').toLowerCase();

  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (content.includes(pattern)) {
      console.warn(`Polyglot detection triggered! Found suspicious pattern: ${pattern}`);
      return false; // Malicious
    }
  }

  // Check for MZ header (Windows executable) in non-executable files
  // (Assuming we don't allow .exe uploads based on earlier requirements)
  const hexStart = buffer.toString('hex', 0, 2).toLowerCase();
  if (hexStart === '4d5a') { // MZ
    console.warn(`Polyglot detection triggered! Found MZ executable header in buffer.`);
    return false; // Malicious
  }

  return true; // Safe
};

module.exports = { detectPolyglot };
