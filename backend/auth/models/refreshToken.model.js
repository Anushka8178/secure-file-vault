const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  token: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  // Token family for RTR (Refresh Token Rotation)
  family: {
    type: String,
    required: true,
    index: true,
  },
  // If this token was used (reuse = family compromise)
  used: {
    type: Boolean,
    default: false,
  },
  // If this family was invalidated due to reuse detection
  invalidated: {
    type: Boolean,
    default: false,
  },
  userAgent: String,
  ipAddress: String,
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 },
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
