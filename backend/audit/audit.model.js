const mongoose = require('mongoose');

const auditSchema = new mongoose.Schema({
  event: {
    type: String,
    required: true,
    index: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
  },
  ip: String,
  userAgent: String,
  meta: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true,
  },
}, {
  // Append-only: disable updates
  strict: true,
  versionKey: false,
});

// Prevent updates — immutable audit log
auditSchema.pre('save', function (next) {
  if (!this.isNew) return next(new Error('Audit logs are immutable'));
  next();
});

auditSchema.pre('findOneAndUpdate', function () {
  throw new Error('Audit logs are immutable');
});

auditSchema.pre('updateMany', function () {
  throw new Error('Audit logs are immutable');
});

module.exports = mongoose.model('AuditLog', auditSchema);
