const File = require('../models/file.model');
const Queue = require('bull');
const env = require('../../config/env');

const scanQueue = new Queue('scan-queue', env.REDIS_URL);

/**
 * Queue a file for malware scanning.
 * Pushes a job to a Redis queue to be processed by a background worker.
 * @param {String} fileId - The Mongoose ObjectId of the file
 */
const queueFileForScan = async (fileId) => {
  // Update status to scanning immediately
  await File.findByIdAndUpdate(fileId, { status: 'scanning' });

  // Add job to the Bull queue
  await scanQueue.add({ fileId: fileId.toString() });
};

module.exports = { queueFileForScan, scanQueue };
