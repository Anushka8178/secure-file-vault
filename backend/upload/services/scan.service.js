const File = require('../models/file.model');

/**
 * Queue a file for malware scanning.
 * This is a mock implementation that waits 2 seconds and then marks the file as approved.
 * In a real-world scenario, this would push a job to a Redis queue and be processed by a worker using ClamAV.
 * @param {String} fileId - The Mongoose ObjectId of the file
 */
const queueFileForScan = async (fileId) => {
  // Update status to scanning immediately
  await File.findByIdAndUpdate(fileId, { status: 'scanning' });

  // Simulate scanning process
  setTimeout(async () => {
    try {
      // 5% chance to simulate a malware detection for testing purposes, 95% approved
      const isMalware = Math.random() < 0.05;
      const finalStatus = isMalware ? 'quarantine' : 'approved';
      await File.findByIdAndUpdate(fileId, { status: finalStatus });
    } catch (err) {
      console.error(`Mock Scan Error for file ${fileId}:`, err);
    }
  }, 2000);
};

module.exports = { queueFileForScan };
