const Queue = require('bull');
const { connect: connectDb } = require('../../config/db');
const env = require('../../config/env');
const logger = require('../../shared/logger');
const File = require('../models/file.model');

const { readFile, deleteFile } = require('../services/storage.service');
const { decryptBuffer } = require('../services/encrypt.service');
const { validateMagicBytes } = require('../services/magicByte.service');
const { detectPolyglot } = require('../services/polyglot.service');

const scanQueue = new Queue('scan-queue', env.REDIS_URL);

// Connect to MongoDB before starting to process
connectDb().then(() => {
  logger.info('Scan Worker connected to MongoDB');
  
  scanQueue.process(async (job) => {
    const { fileId } = job.data;
    logger.info(`Processing scan job for file: ${fileId}`);
    
    try {
      const file = await File.findById(fileId);
      if (!file) {
        logger.error(`File ${fileId} not found in DB`);
        return;
      }

      // Read encrypted file from disk
      const encryptedBuffer = await readFile(file.encryptedPath);
      
      // Decrypt file
      const decryptedBuffer = decryptBuffer(encryptedBuffer, file.iv);
      
      // Security Check 1: Magic Bytes
      const isMagicValid = validateMagicBytes(decryptedBuffer, file.mimeType);
      if (!isMagicValid) {
        logger.warn(`File ${fileId} failed magic byte validation`);
        await markQuarantine(file);
        return;
      }
      
      // Security Check 2: Polyglot / Malicious string patterns
      const isPolyglotSafe = detectPolyglot(decryptedBuffer);
      if (!isPolyglotSafe) {
        logger.warn(`File ${fileId} failed polyglot scan`);
        await markQuarantine(file);
        return;
      }
      
      // If all checks pass
      await File.findByIdAndUpdate(fileId, { status: 'approved' });
      logger.info(`File ${fileId} passed security scans and is approved.`);
      
    } catch (err) {
      logger.error(`Error processing scan for file ${fileId}`, { error: err.message });
      // On error, we could retry or just quarantine. Since it's a security scan, default to quarantine on failure.
      try {
        await File.findByIdAndUpdate(fileId, { status: 'quarantine' });
      } catch (dbErr) {
        logger.error(`Failed to quarantine file ${fileId} after error`, { error: dbErr.message });
      }
      throw err; // Let Bull know the job failed
    }
  });

  logger.info('Scan Worker listening for jobs...');
}).catch((err) => {
  logger.error('Failed to connect to MongoDB in worker', { error: err.message });
  process.exit(1);
});

// Helper to quarantine and cleanup
async function markQuarantine(file) {
  // Update status in DB
  await File.findByIdAndUpdate(file._id, { status: 'quarantine' });
  // Delete the malicious file from disk to save space and reduce risk
  await deleteFile(file.encryptedPath);
}
