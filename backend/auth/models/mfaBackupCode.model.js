const mongoose = require('mongoose');

const mfaBackupCodeSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  // AES-encrypted backup code
  codeEncrypted: {
    type: String,
    required: true,
  },
  used: {
    type: Boolean,
    default: false,
  },
  usedAt: {
    type: Date,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('MfaBackupCode', mfaBackupCodeSchema);
