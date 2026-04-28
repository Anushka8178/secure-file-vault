const AuditLog = require('./audit.model');
const logger = require('../shared/logger');

/**
 * Append an immutable audit log entry
 * Also emits JSON log line for SIEM (ELK/Splunk)
 */
const auditLog = async ({ event, userId, ip, userAgent, meta = {} }) => {
  try {
    await AuditLog.create({ event, userId, ip, userAgent, meta });

    // SIEM-compatible JSON log (ELK/Splunk)
    logger.info('AUDIT', {
      audit: true,
      event,
      userId: userId?.toString(),
      ip,
      meta,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    // Never fail the main request due to audit failure
    logger.error('Audit log write failed', { error: err.message, event });
  }
};

/**
 * Query audit logs (admin only)
 */
const queryAuditLogs = async ({ userId, event, from, to, page = 1, limit = 50 }) => {
  const filter = {};
  if (userId) filter.userId = userId;
  if (event) filter.event = event;
  if (from || to) {
    filter.timestamp = {};
    if (from) filter.timestamp.$gte = new Date(from);
    if (to) filter.timestamp.$lte = new Date(to);
  }

  const [logs, total] = await Promise.all([
    AuditLog.find(filter)
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate('userId', 'email username'),
    AuditLog.countDocuments(filter),
  ]);

  return { logs, total, page, pages: Math.ceil(total / limit) };
};

module.exports = { auditLog, queryAuditLogs };
