/**
 * Member C - Magic Byte Validation
 * Verifies that the actual file binary signature matches its claimed mime type/extension.
 */

// Mapping of mimetypes to array of acceptable hex signatures
const MAGIC_BYTES = {
  'application/pdf': ['25504446'], // %PDF
  'image/png': ['89504e470d0a1a0a'],
  'image/jpeg': ['ffd8ffe0', 'ffd8ffe1', 'ffd8ffe2', 'ffd8ffe3', 'ffd8ffee', 'ffd8ffdb'],
  'image/gif': ['474946383761', '474946383961'], // GIF87a, GIF89a
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['504b0304', '504b0506', '504b0708'], // DOCX (ZIP)
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['504b0304', '504b0506', '504b0708'], // XLSX (ZIP)
};

// Types that don't have strict magic bytes
const SKIP_VALIDATION = [
  'text/plain',
  'text/csv'
];

/**
 * Validate a buffer against its expected mimeType
 * @param {Buffer} buffer - The decrypted file buffer
 * @param {String} mimeType - The mimeType from the upload
 * @returns {Boolean} true if valid or skipped, false if magic bytes don't match
 */
const validateMagicBytes = (buffer, mimeType) => {
  if (SKIP_VALIDATION.includes(mimeType)) {
    return true; // Skip strict binary validation for plain text files
  }

  const expectedSignatures = MAGIC_BYTES[mimeType];
  if (!expectedSignatures) {
    console.warn(`No magic byte signatures defined for mime type: ${mimeType}`);
    return false; // Unknown mime type, fail safe
  }

  // Get the first 8 bytes of the buffer as hex
  const bufferHex = buffer.toString('hex', 0, 8).toLowerCase();

  // Check if the buffer starts with any of the expected signatures
  for (const signature of expectedSignatures) {
    if (bufferHex.startsWith(signature.toLowerCase())) {
      return true;
    }
  }

  return false;
};

module.exports = { validateMagicBytes };
