const AuditLog = require('./audit.model');
const { authenticate } = require('../auth/middleware/authenticate');
const { authorize } = require('../auth/middleware/authorize');

/**
 * SSE endpoint for real-time audit log streaming (Admin+)
 * GET /admin/audit/stream
 */
const auditStream = [
  authenticate,
  authorize('Admin'),
  async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    // Send last 20 events on connect
    const recent = await AuditLog.find().sort({ timestamp: -1 }).limit(20).lean();
    recent.reverse().forEach((log) => {
      res.write(`data: ${JSON.stringify(log)}\n\n`);
    });

    // Poll for new entries every 2 seconds
    let lastTimestamp = new Date();
    const interval = setInterval(async () => {
      try {
        const newLogs = await AuditLog.find({ timestamp: { $gt: lastTimestamp } })
          .sort({ timestamp: 1 })
          .lean();

        newLogs.forEach((log) => {
          res.write(`data: ${JSON.stringify(log)}\n\n`);
          lastTimestamp = log.timestamp;
        });
      } catch (err) {
        clearInterval(interval);
      }
    }, 2000);

    req.on('close', () => {
      clearInterval(interval);
      res.end();
    });
  },
];

module.exports = { auditStream };
