const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  originalName: {
    type: String,
    required: true,
    trim: true,
  },
  encryptedPath: {
    type: String,
    required: true,
  },
  iv: {
    type: String,
    required: true,
  },
  mimeType: {
    type: String,
    required: true,
  },
  size: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    enum: ['pending', 'scanning', 'approved', 'quarantine'],
    default: 'pending',
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
}, {
  timestamps: true,
});

// Index for fetching user's files quickly
fileSchema.index({ uploadedBy: 1, createdAt: -1 });

module.exports = mongoose.model('File', fileSchema);
