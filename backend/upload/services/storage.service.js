const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const env = require('../../config/env');

/**
 * Ensure the upload directory exists
 */
const ensureUploadDir = async () => {
  try {
    await fs.access(env.UPLOAD_DIR);
  } catch {
    await fs.mkdir(env.UPLOAD_DIR, { recursive: true });
  }
};

/**
 * Save an encrypted buffer to disk
 * @param {Buffer} encryptedBuffer - The buffer to save
 * @returns {String} - The filename (relative path within UPLOAD_DIR)
 */
const saveFile = async (encryptedBuffer) => {
  await ensureUploadDir();
  const fileName = uuidv4(); // Store file with a random UUID name to prevent path traversal / guessing
  const filePath = path.join(env.UPLOAD_DIR, fileName);
  await fs.writeFile(filePath, encryptedBuffer);
  return fileName;
};

/**
 * Read a file from disk
 * @param {String} fileName - The filename within UPLOAD_DIR
 * @returns {Buffer}
 */
const readFile = async (fileName) => {
  const filePath = path.join(env.UPLOAD_DIR, fileName);
  return fs.readFile(filePath);
};

/**
 * Delete a file from disk
 * @param {String} fileName 
 */
const deleteFile = async (fileName) => {
  const filePath = path.join(env.UPLOAD_DIR, fileName);
  try {
    await fs.unlink(filePath);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err; // Ignore if file already deleted
  }
};

module.exports = { saveFile, readFile, deleteFile };
